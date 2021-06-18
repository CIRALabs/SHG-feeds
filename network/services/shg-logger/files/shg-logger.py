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

# Required constants
MQTT_TOPICS = ['SPIN/traffic']
MQTT_PORT = 1883
MQTT_HOST = '127.0.0.1'
CERT = '/etc/shg/certificates/jrc_prime256v1.crt'
KEY = '/etc/shg/certificates/jrc_prime256v1.key'
URL = 'https://api.securehomegateway.ca/data'
LOGREAD = '/sbin/logread'


class LogreadScraperThread(Thread):
    """
    This class will handle reading lines of logs from "logread -f"
    then adding those new lines to the message queue...
    """

    def __init__(self, queue, debug):

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
        \[\d+\.\d+\]       # some number
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

    def run(self):

        if self.debug:
            print("Starting the logread scraper thread...")

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

            if self.debug:
                print(f'Got a {self.log_type} logread line...')

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

    def add(self, message):
        """
        This method will add a message to the message queue
        """
        if self.debug:
            print("Adding a message to the queue")
            print(message)

        self.queue_lock.acquire(blocking=True)
        self.queue.append(message)
        self.queue_lock.release()

    def clear(self):
        """
        This method will clear the contents of the message queue
        """
        self.queue_lock.acquire(blocking=True)
        self.queue = []
        self.queue_lock.release()

    def messages(self):
        """
        This method will return a copy of the list of messages in the queue
        """
        self.queue_lock.acquire(blocking=True)
        queue_copy = self.queue.copy()
        self.queue_lock.release()

        return queue_copy

    def set_last_collection_time(self, timestamp):
        """
        This method will set the last collection time, which is
        the time that we last checked to see if we needed to upload
        data
        """
        self.last_collection_time = timestamp

    def get_last_collection_time(self):
        """
        This method will return the last collection time for this queue.
        """
        return self.last_collection_time

    def queue_length(self):
        """
        This method will return the number of items in the current queue.
        """
        return len(self.queue)

    def queue_size(self):
        """
        This method returns the current queue size (in bytes)
        """
        return sys.getsizeof(self.queue)

    def start_timer(self):
        """
        Set a timer to re-run the process method in the future
        """
        Timer(self.check_interval, self.process).start()

    def process(self):
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
        json_data = {'Data': self.messages()}

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

    def do_upload(self, json_data):
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
            raise Exception(err)

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

        if 'accepted' not in json_response.keys() \
                or json_response['accepted'] != 'yes':
            raise Exception(f'Data not accepted by server: {response.content}')

        if 'fileLength' not in json_response.keys():
            raise Exception("fileLength not in json response")

        if json_response['fileLength'] != num_bytes:
            file_length = json_response['fileLength']

            raise Exception(f'Number of uploaded bytes not as expected. '
                            f'Got {file_length}, expected {num_bytes}')


def on_connect(client, userdata, _flags, rc):
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


def on_message(_client, userdata, message):
    """
    Callback handler for MQTT message received
    """

    the_queue = userdata['queue']
    debug = userdata['debug']

    if debug:
        print(f'MQTT Message received on {message.topic}...')

    payload = message.payload.decode('utf-8')
    json_payload = json.loads(payload)

    json_payload['log_type'] = f'{message.topic}'

    # Clean up the json, SPIN inserts some garbage values...
    if 'result' in json_payload.keys():
        json_payload['result'].pop('total_size', None)
        json_payload['result'].pop('total_count', None)

        if 'flows' in json_payload['result'].keys():
            for this_flow in json_payload['result']['flows']:
                this_flow.pop('size', None)
                this_flow.pop('count', None)

    the_queue.add(json_payload)


def run_main():
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
