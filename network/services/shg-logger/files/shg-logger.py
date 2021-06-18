#!/usr/bin/python3
import argparse
import sys
import time
import json
import paho.mqtt.client as mqtt
import requests
from threading import Lock, Timer
import socket
import os

"""
This application will connect to the MQTT server on 
a local box, subscribe to interesting topics,
and then bundle / send that data to the SSHG backend
data collection server.
"""

# Required constants
MQTT_TOPICS = ['SPIN/traffic']
MQTT_PORT = 1883
MQTT_HOST = '127.0.0.1'
CERT = '/etc/shg/certificates/jrc_prime256v1.crt'
KEY = '/etc/shg/certificates/jrc_prime256v1.key'
URL = 'https://api.securehomegateway.ca/data'


class MessageQueue:
    """
    This class handles everything having to do with the message queue, including
    checking to see if it's time to sent the data, as well as uploading the data.
    """

    def __init__(self, debug):
        self.queue = []
        self.last_collection_time = time.time()
        self.max_bytes = 5_000
        self.check_interval = 60
        self.queue_lock = Lock()
        self.debug = debug

    def add(self, message):
        self.queue_lock.acquire(blocking=True)
        self.queue.append(message)
        self.queue_lock.release()

    def clear(self):
        self.queue = []

    def messages(self):
        return self.queue.copy()

    def set_last_collection_time(self, timestamp):
        self.last_collection_time = timestamp

    def get_last_collection_time(self):
        return self.last_collection_time

    def queue_length(self):
        return len(self.queue)

    def queue_size(self):
        return sys.getsizeof(self.queue)

    def set_timer(self):
        Timer(self.check_interval, self.process).start()

    # Check the queue to see if we should sent the messages we have...
    def process(self):

        # Reset the timer, so we try to send messages again later...
        self.set_timer()

        # Only one thread at a time should be able to process the queue...
        self.queue_lock.acquire(blocking=True)

        # Make sure we have items in the queue to send...
        if self.queue_length() == 0:
            self.queue_lock.release()
            return

        # If the size of the queue is less than the max
        # AND it hasn't been too long since the last collection time,
        # we don't need to send anything...
        if self.queue_size() < self.max_bytes\
                and self.last_collection_time + self.check_interval >\
                time.time():

            self.queue_lock.release()
            return

        # Update the last_collection timestamp so that we know when we
        # last checked the queue...
        self.last_collection_time = time.time()

        if self.debug:
            print(f"Sending {len(self.queue)} items")

        # Add the 'Data' wrapper to the list of queue items to
        # make the API happy...
        json_data = {'Data': self.messages()}

        # Empty the queue so it's ready for the next batch of items...
        self.queue.clear()

        # And release the queue lock so that new messages aren't waiting
        # to be put inserted into the queue...
        self.queue_lock.release()

        # Do the upload of data to the back end server...
        try:
            self.do_upload(json_data)

            if self.debug:
                print("Data uploaded!")

        except Exception as err:
            print(f'Upload Error: {err} ')

    # Do the log upload to the backend log collection server, and
    # verify the result
    def do_upload(self, json_data):
        global URL, CERT, KEY

        # Figure the size of the upload so that we can make sure that the
        # server got all the bytes we tried to send.
        num_bytes = len(json.dumps(json_data))

        if self.debug:
            print(f'Number of bytes to send: {num_bytes}')

        # Finally, do the upload of the data...
        try:
            response = requests.post(URL, cert=(CERT, KEY), json=json_data)

        except socket.gaierror as err:
            raise Exception(f'Could not open connection to {MQTT_HOST}: {err}')

        except requests.exceptions.ConnectionError as err:
            raise Exception(f"Could not create TLS connection: {err}")

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
        except ValueError:
            raise Exception(f'Got invalid json in response: {response.content}')

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


# Callback handler for MQTT connect to server
def on_connect(client, userdata, _flags, rc):
    global MQTT_HOST, MQTT_TOPICS

    the_queue = userdata['queue']
    debug = userdata['debug']

    if rc == 0:
        if debug:
            print(f'Connected to {MQTT_HOST}...')

        for this_topic in MQTT_TOPICS:
            client.subscribe(this_topic)

            if debug:
                print(f'Subscribed to {this_topic}')

        # Start the timer so we will check the message queue over and over...
        the_queue.set_timer()

    else:
        print(f'Error: Could not connect to {MQTT_HOST}: RC is {rc}')
        exit(0)


# Callback handler for MQTT message received
def on_message(_client, userdata, message):
    the_queue = userdata['queue']
    debug = userdata['debug']

    if debug:
        print(f'MQTT Message received on {message.topic}...')

    payload = message.payload.decode('utf-8')
    json_payload = json.loads(payload)

    # Clean up the json, SPIN inserts some garbage values...
    if 'result' in json_payload.keys():
        # Add a note so that we can locate SPIN traffic later...
        json_payload['result']['mqtt_topic'] = message.topic

        json_payload['result'].pop('total_size', None)
        json_payload['result'].pop('total_count', None)

        if 'flows' in json_payload['result'].keys():
            for this_flow in json_payload['result']['flows']:
                this_flow.pop('size', None)
                this_flow.pop('count', None)

    if debug:
        print(json_payload)

    the_queue.add(json_payload)


def run_main():
    # Make sure that we reference our global constants
    global MQTT_HOST, MQTT_PORT, CERT, KEY

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
        exit(1)

    if not os.path.exists(KEY):
        print(f'Error: Key file {KEY} does not exist.')
        exit(1)

    # Creat the message queue, and pass that queue into MQTT callbacks...
    the_queue = MessageQueue(args.debug)

    client_userdata = {'queue': the_queue, 'debug': args.debug}
    client = mqtt.Client(userdata=client_userdata)
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(MQTT_HOST, MQTT_PORT)

    while True:
        try:
            client.loop_forever()

        except KeyboardInterrupt:
            client.disconnect()
            exit(0)

        except:
            raise


if __name__ == "__main__":
    run_main()
