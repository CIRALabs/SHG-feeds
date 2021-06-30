#!/usr/bin/python3

"""
This application will connect to the MQTT server on
a local box, subscribe to interesting topics,
and then bundle / send that data to the SSHG backend
data collection server.
"""

import argparse
import sys
import time
import json
import socket
import os
import re
from threading import Lock, Timer, Thread
import subprocess
import paho.mqtt.client as mqtt
import requests
from socket import gethostname
from typing import Dict, List, Any

# Required constants
MQTT_TOPICS = ['SPIN/traffic']
MQTT_PORT = 1883
MQTT_HOST = '127.0.0.1'
CERT = '/etc/shg/certificates/jrc_prime256v1.crt'
KEY = '/etc/shg/certificates/jrc_prime256v1.key'
URL = 'https://api.securehomegateway.ca/data'
LOGREAD = '/sbin/logread'
TOP = '/usr/bin/top'
FREE = '/bin/free'
DF = '/bin/df'
PGREP = '/bin/pgrep'
PS = '/bin/ps'

IPTABLES_DEL_CMD = '/usr/sbin/iptables -D zone_wan_dest_REJECT -m limit --limit 1/sec -j LOG --log-prefix "SSHG-REJECT: " --log-level 6'
IPTABLES_ADD_CMD = '/usr/sbin/iptables -I zone_wan_dest_REJECT 1 -m limit --limit 1/sec -j LOG --log-prefix "SSHG-REJECT: " --log-level 6'
IPTABLES_SAVE_CMD = '/usr/sbin/iptables-save > /dev/null 2>&1'


class StatsCollectorThread(Thread):
    """
    Run system stats collection  evey so often and add those
    stats to the message queue...
    """

    def __init__(self, queue: List[Dict[str, Any]], debug: bool):
        Thread.__init__(self)

        self.queue = queue
        self.debug = debug
        self.log_type = 'SYSTEM-STATS'
        self.check_interval = 300

    def get_load_average(self) -> str:
        """
        Run a single iteration of the 'top' command and scrape
        the 1 minute load average from the output.
        """
        process = subprocess.run([TOP, '-bn1'], stdout=subprocess.PIPE)
        output = process.stdout.decode('utf-8')

        first_index = output.index('load average:')
        second_index = output.index(',', first_index)

        # Pull just the load from the data in output...
        load_average = output[first_index + 14: second_index]
        return load_average

    def get_free_memory(self) -> str:
        """
        Run the 'free' command and scrape the amount of free
        bytes.  Then convert that to megabytes and return that.

        """
        process = subprocess.run([FREE, '-h'], stdout=subprocess.PIPE)
        output = process.stdout.decode('utf-8')

        line2 = output.splitlines()[1]
        free = line2.split()[6]
        free = int(free) / 1000
        return f'{free}MB'

    def get_free_disk_space(self) -> str:
        """
        Run the 'df' command, scrape the amount of free space.
        """
        process = subprocess.run([DF, '-h'], stdout=subprocess.PIPE)
        output = process.stdout.decode('utf-8')

        line2 = output.splitlines()[1]
        available = line2.split()[3]
        return available

    def get_top_cpu_process(self) -> Dict[str, str]:
        """
        Run a single iteration of the top command sorted by CPU usage,
        scrape it for the command / percentage used.
        We need to supply the -w 500 so that the command will not be
        truncated.
        """
        process = subprocess.run([TOP, '-bn1', '-o', '%CPU', '-w', str(500)],
                                 stdout=subprocess.PIPE)
        output = process.stdout.decode('utf-8')

        line = output.splitlines()[8]
        parts = line.split(None, 10)
        percent_cpu = parts[6]
        command = parts[10]

        return {'percentage': f'{percent_cpu}%', 'command': command}

    def get_top_mem_process(self) -> Dict[str, str]:
        """
        Run a single iteration of the top command, sorted by memory usage.
        Scrape the process with the highest memory usage.
        """
        process = subprocess.run([TOP, '-bn1', '-o', '%MEM', '-w', str(500)],
                                 stdout=subprocess.PIPE)
        output = process.stdout.decode('utf-8')

        line = output.splitlines()[8]
        parts = line.split(None, 10)
        percent_mem = parts[7]
        command = parts[10]

        return {'percentage:': f'{percent_mem}%', 'command': command}

    def get_proc_stats(self, process_name: str) -> Dict[str, str]:
        """
        This method will get the %cpu and %memory usage for a given process,
        given by process_name (or substring of process_name)
        """
        process = subprocess.run([PGREP, '-f', process_name],
                                 stdout=subprocess.PIPE)
        output = process.stdout.decode('utf-8')

        process_id = output.strip()

        if self.debug:
            print(f'Process ID for {process_name} is {process_id}')

        # Now, use PS to get the stats for just that processId...
        process = subprocess.run(
            [PS, '-p', process_id, '-o', '%cpu,%mem'],
            stdout=subprocess.PIPE)
        output = process.stdout.decode('utf-8')

        line2 = output.splitlines()[1]
        percent_cpu, percent_mem = line2.split(None, 1)

        return {
            'percent_cpu': f'{percent_cpu}%',
            'percent_memory': f'{percent_mem}%'
        }

    def collect_system_stats(self) -> Dict[str, Any]:
        """
        Run a bunch of commands to collect system stats and throw them
        in a hash (for later jsonification).
        """

        stats = {
            'log_type': 'SYSTEM_STATS',
            'time': time.time(),
            'hostname': gethostname(),
            'load': self.get_load_average(),
            'free_mem': self.get_free_memory(),
            'free_disk': self.get_free_disk_space(),
            'top_cpu_process': self.get_top_cpu_process(),
            'top_mem_process': self.get_top_mem_process(),
            'device_manager_stats': self.get_proc_stats('shg-device-manager')
        }

        if self.debug:
            print(f'Collected Stats:\n{stats}')

        return stats

    def run(self) -> None:
        """
        This thread should run every 5 minutes or so, collect a number
        of different system stats, and then insert those into the message
        queue so that they are logged.
        """

        if self.debug:
            print("Starting the stats collection thread...")

        while True:
            if self.debug:
                print("Collecting system stats...")

            stats = self.collect_system_stats()
            self.queue.add(stats)

            time.sleep(self.check_interval)


class FirewallConfigThread(Thread):
    """
    This class will handle making sure that the firewall rule that we rely on
    being in place stays in placed (some UCI commands seem to blow it away).
    """

    def __init__(self, debug: bool):

        Thread.__init__(self)

        self.debug = debug
        self.check_interval = 300

    def run(self) -> None:

        if self.debug:
            print("Starting the FW config thread...")

        while True:
            if self.debug:
                print("Doing FW config...")

            os.system(IPTABLES_DEL_CMD)
            os.system(IPTABLES_ADD_CMD)
            os.system(IPTABLES_SAVE_CMD)

            time.sleep(self.check_interval)


class LogreadScraperThread(Thread):
    """
    This class will handle reading lines of logs from "logread -f"
    then adding those new lines to the message queue...
    """

    def __init__(self, queue: List[Dict[str, Any]], debug: bool):

        Thread.__init__(self)

        self.queue = queue
        self.debug = debug
        self.log_type = 'SSHG-REJECT'

        # This is the regex that is used to decode the line logged in syslog
        # by fw3 for rejected connections
        # NOTE: if this doesn't match what we see being logged, we won't
        # get anything...
        self.the_regex = re.compile(r"""

        ^
        (\w+\s+\d+)        # The date
        \s+
        (\d+:\d+:\d+)      # The time
        \s+
        ([na-f0-9]{7})     # The machine hostname
        \s+
        kernel:
        \s+
        .+?                # some number
        \s+
        SSHG-REJECT:
        \s+
        IN=([^\s]+)        # Input interface
        \s+
        OUT=([^\s]+)       # Output interface
        \s+
        MAC=([^\s]+)       # MAC address
        \s+
        SRC=([^\s]+)       # Source IP
        \s+
        DST=([^\s]+)       # Destination IP
        .+?
        \s+
        PROTO=([^\s]+)     # Protocol

        """, re.VERBOSE)

    def run(self) -> None:

        if self.debug:
            print("Starting the logread scraper thread...")

        # This code is going to monitoring the output from the
        # logread -f command, scan it for firewall rejects, and then
        # add those to the message queue.
        proc = subprocess.Popen([LOGREAD, '-f'], stdout=subprocess.PIPE)

        while True:
            line = proc.stdout.readline()

            if not line:
                continue

            # If the process ended...
            if proc.poll() is not None:
                print("Error: logread process exited...")
                break

            # Clean up the line and make sure it's something that
            # we're interested in...
            line = line.decode('utf-8')
            line = line.rstrip()

            # Next, pull all the interesting bits out of the log line...
            match = self.the_regex.search(line)

            if not match:
                continue

            date = match.group(1)
            the_time = match.group(2)
            hostname = match.group(3)
            in_int = match.group(4)
            out_int = match.group(5)
            mac = match.group(6)
            src_ip = match.group(7)
            dst_ip = match.group(8)

            # Make that into json...
            json_log = {'log_type': self.log_type, 'date': date,
                        'time': the_time, 'hostname': hostname,
                        'in_int': in_int, 'out_int': out_int, 'mac': mac,
                        'src_ip': src_ip, 'dst_ip': dst_ip}

            self.queue.add(json_log)


class MessageQueue:
    """
    This class handles everything having to do with the message queue, including
    checking to see if it's time to sent the data, as well the upload.
    """

    def __init__(self, debug):
        self.queue = []
        self.last_collection_time = time.time()
        self.max_bytes = 5_000
        self.check_interval = 60
        self.queue_lock = Lock()
        self.debug = debug

    def add(self, message: Dict[str, Any]) -> None:
        """
        This method will add a message to the message queue
        """
        if 'log_type' not in message:
            print("Error - log_type not defined for message - skipping")
            return

        if self.debug:
            log_type = message['log_type']
            print(f'Adding to queue: {log_type}')

        self.queue_lock.acquire(blocking=True)
        self.queue.append(message)
        self.queue_lock.release()

    def clear(self) -> None:
        """
        This method will clear the contents of the message queue
        """
        self.queue_lock.acquire(blocking=True)
        self.queue = []
        self.queue_lock.release()

    def get_messages(self) -> List[Dict[str, Any]]:
        """
        This method will return a copy of the list of messages in the queue
        """
        self.queue_lock.acquire(blocking=True)
        queue_copy = self.queue.copy()
        self.queue_lock.release()

        return queue_copy

    def set_last_collection_time(self, timestamp: float) -> None:
        """
        This method will set the last collection time, which is
        the time that we last checked to see if we needed to upload
        data
        """
        self.last_collection_time = timestamp

    def get_last_collection_time(self) -> float:
        """
        This method will return the last collection time for this queue.
        """
        return self.last_collection_time

    def queue_length(self) -> int:
        """
        This method will return the number of items in the current queue.
        """
        return len(self.queue)

    def queue_size(self) -> int:
        """
        This method returns the current queue size (in bytes)
        """
        return sys.getsizeof(self.queue)

    def start_timer(self) -> None:
        """
        Set a timer to re-run the process method in the future
        """
        Timer(self.check_interval, self.process).start()

    def process(self) -> None:
        """
        Check the queue to see if we should sent the messages we have...
        """

        if self.debug:
            print("Processing the queue...")

        # Reset the timer, so we try to send messages again later...
        self.start_timer()

        # Make sure we have items in the queue to send...
        if self.queue_length() == 0:
            return

        # If the size of the queue is less than the max
        # AND it hasn't been too long since the last collection time,
        # we don't need to send anything...
        if self.queue_size() < self.max_bytes \
                and self.last_collection_time + self.check_interval > \
                time.time():
            return

        # Update the last_collection timestamp so that we know when we
        # last checked the queue...
        self.last_collection_time = time.time()

        if self.debug:
            print(f"Sending {self.queue_length()} items")

        # Add the 'Data' wrapper to the list of queue items to
        # make the API happy...
        json_data = {'Data': self.get_messages()}

        # Empty the queue so it's ready for the next batch of items...
        self.queue.clear()

        # Do the upload of data to the back end server...
        if self.debug:
            print('Doing upload...')

        try:
            self.do_upload(json_data)

            if self.debug:
                print("Data uploaded!")

        except Exception as err:
            print(f'Upload Error: {err} ')

    def do_upload(self, json_data: Dict[str, Any]):
        """
         Do the log upload to the backend log collection server, and
         verify the result
        """

        # Figure the size of the upload so that we can make sure that the
        # server got all the bytes we tried to send.
        num_bytes = len(json.dumps(json_data))

        if self.debug:
            print(f'Number of bytes to send: {num_bytes}')

        # Finally, do the upload of the data...
        try:
            response = requests.post(URL, cert=(CERT, KEY), json=json_data)

        except socket.gaierror as err:
            raise Exception(f'Could not open connection to {MQTT_HOST}') \
                from err

        except requests.exceptions.ConnectionError as err:
            raise Exception('Could not create TLS connection') from err

        except Exception as err:
            # If we get an unexpected exception, log it and bail...
            print(f'Unknown exception: {err}')
            return

        if not response.ok:
            raise Exception(
                f'Could not upload data, got:\n{response.status_code}\n'
                f'{response.content}')

        # Verify that the upload was accepted and the number of bytes
        # received by the server matched what we wanted to send...
        try:
            json_response = response.json()
        except ValueError as err:
            raise Exception(f'Got invalid json response: {response.content}') \
                from err

        if self.debug:
            the_response = response.content.decode('utf-8').rstrip()
            print(f'Response: {the_response}')

        if 'accepted' not in json_response \
                or json_response['accepted'] != 'yes':
            raise Exception(f'Data not accepted by server: {response.content}')

        if 'fileLength' not in json_response:
            raise Exception("fileLength not in json response")

        if json_response['fileLength'] != num_bytes:
            file_length = json_response['fileLength']

            raise Exception(f'Number of uploaded bytes not as expected. '
                            f'Got {file_length}, expected {num_bytes}')


def on_connect(client: mqtt.Client, userdata: dict, _flags: dict,
               rc: int) -> None:
    """
     Callback handler for MQTT connect to server
    """

    the_queue = userdata['queue']
    debug = userdata['debug']

    if rc == 0:
        if debug:
            print(f'Connected to MQTT server on {MQTT_HOST}...')

        for this_topic in MQTT_TOPICS:
            client.subscribe(this_topic)

            if debug:
                print(f'Subscribed to {this_topic}')

        # Start the timer so we will check the message queue over and over...
        the_queue.start_timer()

    else:
        print(f'Error: Could not connect to {MQTT_HOST}: RC is {rc}')
        sys.exit(0)


def on_message(_client: mqtt.Client, userdata: dict,
               message: mqtt.MQTTMessage) -> None:
    """
    Callback handler for MQTT message received
    """

    the_queue = userdata['queue']
    debug = userdata['debug']

    payload = message.payload.decode('utf-8')
    json_payload = json.loads(payload)

    json_payload['log_type'] = f'{message.topic}'

    # Clean up the json, SPIN inserts some garbage values...
    if 'result' in json_payload:
        json_payload['result'].pop('total_size', None)
        json_payload['result'].pop('total_count', None)

        if 'flows' in json_payload['result']:
            for this_flow in json_payload['result']['flows']:
                this_flow.pop('size', None)
                this_flow.pop('count', None)

    the_queue.add(json_payload)


def run_main() -> None:
    """
    The main method, launches everything.
    """

    # Check for the -d debug mode flag...
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', dest='debug', action='store_true',
                        help='Run in debug mode')

    args = parser.parse_args()
    if args.debug:
        print("Starting shg-logger...")

    # Make sure the cert and key exist...
    if not os.path.exists(CERT):
        print(f'Error: Certificate file {CERT} does not exist.')
        sys.exit(1)

    if not os.path.exists(KEY):
        print(f'Error: Key file {KEY} does not exist.')
        sys.exit(1)

    if not os.path.exists(LOGREAD):
        print(f'Error: Key file {KEY} does not exist.')
        sys.exit(1)

    # Creat the message queue, and pass that queue into MQTT callbacks...
    the_queue = MessageQueue(args.debug)

    client_userdata = {'queue': the_queue, 'debug': args.debug}
    client = mqtt.Client(userdata=client_userdata)
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(MQTT_HOST, MQTT_PORT)

    # Start the "logread -f" scraper thread for the firewall rejects...
    scraper_thread = LogreadScraperThread(the_queue, args.debug)
    scraper_thread.start()

    # Start the fw configuration thread - gotta keep our
    # reject logging configuration active...
    fw_config_thread = FirewallConfigThread(args.debug)
    fw_config_thread.start()

    # Start the system stats collection thread...
    stats_collector_thread = StatsCollectorThread(the_queue, args.debug)
    stats_collector_thread.start()

    while True:
        try:
            client.loop_forever()
        except KeyboardInterrupt:
            client.disconnect()
            sys.exit(0)

        except:
            raise


if __name__ == "__main__":
    run_main()
