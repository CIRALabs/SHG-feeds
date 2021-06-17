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
This application will connect to the SPIN MQTT traffic topic on 
a local box, and then bundle / send that data to the SSHG backend
data collection server.
"""

# Check for the -d debug mode flag...
parser = argparse.ArgumentParser()
parser.add_argument('-d', '--debug', dest='debug', action='store_true',
                    help='Run in debug mode')

ARGS = parser.parse_args()

# Configuration for where to collect MQTT messages from
MQTT_TOPIC = 'SPIN/traffic'
MQTT_PORT = 1883
MQTT_HOST = '127.0.0.1'

# Configuration for where to send the collected MQTT JSON-formatted messages to
CERT = '/etc/shg/certificates/jrc_prime256v1.crt'
KEY = '/etc/shg/certificates/jrc_prime256v1.key'
URL = 'https://api.securehomegateway.ca/data'

# We'll send the logs every 60 seconds or every 5000 bytes,
# whatever comes first...
MAX_BYTES = 5_000
CHECK_INTERVAL = 60
LAST_COLLECTION_TIME = time.time()

# The global QUEUE and the synchronization lock for the queue...
QUEUE = []
QUEUE_LOCK = Lock()


# Check the queue and if we should send logs, send them
def check_queue():
    global ARGS, QUEUE, QUEUE_LOCK, LAST_COLLECTION_TIME, CHECK_INTERVAL,\
        MAX_BYTES

    # Reset the timer, so we try to send messages again later...
    Timer(CHECK_INTERVAL, check_queue).start()

    # Only one thread at a time should be able to process the queue...
    QUEUE_LOCK.acquire(blocking=True)

    # Make sure we have items in the queue to send...
    if len(QUEUE) == 0:
        QUEUE_LOCK.release()
        return

    # If the size of the queue is less than the max AND it hasn't been too long
    # since the last collection time, we don't need to send anything...
    if sys.getsizeof(QUEUE) < MAX_BYTES \
            and LAST_COLLECTION_TIME + CHECK_INTERVAL > time.time():
        QUEUE_LOCK.release()
        return

    # Update the collection timestamp so that we know when we last checked for
    # logs.
    LAST_COLLECTION_TIME = time.time()

    if ARGS.debug: print(f"Sending {len(QUEUE)} items")

    # Add the 'Data' wrapper to the list of queue items to make the API happy...
    json_data = {'Data': QUEUE.copy()}

    # Empty the queue so it's ready for the next batch of items...
    QUEUE.clear()

    # And release the queue lock so that new messages aren't waiting
    # to be put inserted into the queue...
    QUEUE_LOCK.release()

    # Clean up the json, SPIN inserts some garbage values...
    remove_bogus_values(json_data)

    try:
        do_upload(json_data)
        if ARGS.debug: print("Data uploaded!")

    except Exception as err:
        print(f'Upload Error: {err} ')


# Do the log upload to the backend log collection server, and 
# verify the result.
def do_upload(json_data):
    global ARGS, URL, CERT, KEY

    # Figure the size of the upload so that we can make sure that the
    # server got all the bytes we tried to send.
    num_bytes = len(json.dumps(json_data))
    if ARGS.debug: print(f'Number of bytes to send: {num_bytes}')

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
        raise Exception(f'Could not upload data, got:\n{response.status_code}\n'
                        f'{response.content}')

    # Verify that the upload was accepted and the number of bytes
    # received by the server matched what we wanted to send...
    try:
        json_response = response.json()
    except ValueError:
        raise Exception(f'Got invalid json in response: {response.content}')

    if ARGS.debug:
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



# SPIN inserts huge, incorrect numbers for size, count, total_size and
# total count, so we need to remove those...
def remove_bogus_values(json_data):

    for this_item in json_data['Data']:

        if 'result' in this_item.keys():
            this_item['result'].pop('total_size', None)
            this_item['result'].pop('total_count', None)

            if 'flows' in this_item['result'].keys():
                for this_flow in this_item['result']['flows']:
                    this_flow.pop('size', None)
                    this_flow.pop('count', None)


# When we first connect to the MQTT server, this is the handler...
def on_connect(client, _user_data, _flags, rc):
    global ARGS, CHECK_INTERVAL, MQTT_HOST, MQTT_TOPIC

    if rc == 0:
        if ARGS.debug: print(f'Connected to {MQTT_HOST}...')

        client.subscribe(MQTT_TOPIC)
        if ARGS.debug: print(f'Subscribed to {MQTT_TOPIC}')

        # Start the timer so we will check the message queue over and over...
        Timer(CHECK_INTERVAL, check_queue).start()

    else:
        print(f'Error: Could not connect to {MQTT_HOST}: RC is {rc}')
        exit(0)


# When a MQTT message is received, this is the handler...
def on_message(_client, _user_data, message):
    global ARGS, QUEUE, QUEUE_LOCK

    if ARGS.debug: print(f'MQTT Message received on {message.topic}...')

    payload = message.payload.decode('utf-8')
    json_payload = json.loads(payload)

    QUEUE_LOCK.acquire(blocking=True)
    QUEUE.append(json_payload)
    QUEUE_LOCK.release()


def run_main():
    global ARGS, MQTT_HOST, MQTT_PORT, CERT, KEY
    if ARGS.debug: print("Starting spinForwarder...")

    # Make sure the cert and key exist...
    if not os.path.exists(CERT):
        print(f'Error: Certificate file {CERT} does not exist.')
        exit(1)

    if not os.path.exists(KEY):
        print(f'Error: Key file {KEY} does not exist.')
        exit(1)

    client = mqtt.Client()
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
