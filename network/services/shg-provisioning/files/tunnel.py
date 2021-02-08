#!/usr/bin/python
# tunnel.py
# version .1
# by jason.blakey@cira.ca
# 2021/02/01

# A utility to bring up (and keep up) a reverse ssh tunnel to a central location.
# Used for remote administration / troubleshooting.

import os
import subprocess
import time


############## CONFIGURATION ################

# Where to connect to and what key to use?
#remote = "sshtunnel@69.196.164.44"
remote = "sshtunnel@remote.securehomegateway.ca"
remote_port = "2222"
pem_file = "/etc/shg/tunnelkey.pem"
sleep_secs = 60


# Some paths to utilities that we need to run...
ssh = "/usr/bin/ssh"
pgrep = "/bin/pgrep"

############ END CONFIGURATION ##############


# This routine will pull the MAC address from the interface address
# file in /sys/class/net/<int>/address
def get_mac(interface='eth0'):

    address_file = '/sys/class/net/' + interface + '/address';

    fh = open(address_file, "r")
    mac = fh.read()
    fh.close()

    return mac


# This routine will convert a string MAC address to a usable remote SSH port
# by taking only the first 12 bits of the MAC and adding 16384 to that.
def convert_mac_to_port(mac):

    mac = mac.replace(':', '')
    mac_int = int(mac, 16)
    mac_int = mac_int & 0b111111111111
    port = mac_int + 16384

    return port


def main():

    # Pull the MAC address for this box's ETH0 and use that to figure 
    # a good port number to use on the remote server...
    mac = get_mac()
    port = convert_mac_to_port(mac)

    # Next, we check to see if the tunnel is already up and running...
    ssh_match_string = "ssh\s+.+" + pem_file + ".+" + str(port) + ".+" + remote

    while 1:

        print("CHECKING FOR TUNNEL")

        ssh_pid = subprocess.run([pgrep, "-f", ssh_match_string],
            capture_output=True, text=True).stdout

        # If we can't find the tunnel process, start it up...
        if not ssh_pid:
            print("TUNNEL IS NOT RUNNING - STARTING TUNNEL")
            print("REMOTE PORT ON REMOTE IS " + str(port))

            command_list = [ssh,
            "-o",
            "StrictHostKeyChecking=no",
            "-i", 
            pem_file,
            "-p",
            remote_port,
            "-N",
            "-R",
            str(port) + ":127.0.0.1:22",
            remote
            ]

            new_pid = os.fork()

            # If this is the new process, replace this process with the ssh tunnel...
            if new_pid == 0:
                os.execv(ssh, command_list)
            else:
                print("TUNNEL STARTED: PID IS " + str(new_pid))

        else:

            # Otherwise, tunnel is already running...
            print("EXISTING TUNNEL PID: " + ssh_pid.rstrip())

        print("SLEEPING " + str(sleep_secs) + " SECONDS")
        time.sleep(sleep_secs)

if __name__ == "__main__":
    main()

