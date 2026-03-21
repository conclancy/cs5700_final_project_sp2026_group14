import socket
import time
from SFTP_Client_obj import Client
from socket import *
import os
import sys
from multiprocessing import Process, Manager

HOST = '127.0.0.1'
PORT = 12345

def parse_kwargs_from_argv(argv):
    kwargs = {}
    for arg in argv:
        key, value = arg.split('=')
        kwargs[key] = value

    #TODO: Logic to validate kwargs

    return kwargs

def listener(global_buf):
    # Setup listener socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    client_socket.bind((HOST, PORT))
    while True:
        #TODO: May want to add logic with the address for security
        data, addr = client_socket.recvfrom(65535) #TODO: Review buffer size with testing

        # Pass message to global buffer
        global_buf.append(data)
        time.sleep(0.01)



def main(global_buf, **kwargs):

    if os.geteuid() != 0:
        print("This script must be run as root (raw sockets require admin privileges).")
        sys.exit(1)

    # Set up a client obj
    client = Client(kwargs, global_buf)

    # Start listener process
    listener_proc = Process(target=listener, args=(GLOBAL_MSG,))
    listener_proc.start()

    # Open and read file
    data = client.read_file()
    # Split into packets
    split_data = client.split_data(data, 65000) #TODO: Is this the appropriate packet size?

    # Make packets
    packets = client.make_datagrams(split_data)
    # Send packets (with considerations of rules to wait for ACK)
    for packet in packets:
        client.process_rcvd_msgs()
        client.check_for_ack()
        if len(client.sent_msgs) < 5: #TODO: Is 5 the ideal number?
            client.send_packet(packet)
            client.sent_msgs.append({"packet": packet, "timestamp": time.time(), "attempts": 1})

        else:
            while len(client.sent_msgs) >= 5:
                for msg in list(client.sent_msgs):
                    if msg["attempts"] < 5: #TODO: is 5 the ideal number?
                        if time.time() > msg["timestamp"] + 5: #TODO: Need to confirm output of time.time()
                            # Resend msg
                            client.send_packet(msg["packet"])
                            msg["attempts"] += 1
                            msg["timestamp"] = time.time()
                    else:
                        # Terminate program
                        print("Reached maximum number of attempts for a message. Exiting.")
                        exit(0)

    while len(client.sent_msgs) > 0:
        client.process_rcvd_msgs()
        client.check_for_ack()
        for msg in list(client.sent_msgs):
            if msg["attempts"] < 5:  # TODO: is 5 the ideal number?
                if time.time() > msg["timestamp"] + 5:  # TODO: Need to confirm output of time.time()
                    # Resend msg
                    client.send_packet(msg["packet"])
                    msg["attempts"] += 1
                    msg["timestamp"] = time.time()

            else:
                # Terminate program
                print("Reached maximum number of attempts for a message.\n"
                      "Exiting without completing file transfer.")
                exit(0)
        time.sleep(0.01)

    listener_proc.join()

if __name__ == '__main__':
    GLOBAL_MSG = Manager().list()
    # sys.argv[0] is the script name, so skip it
    raw_args = sys.argv[1:]

    # Parse into kwargs
    kwargs = parse_kwargs_from_argv(raw_args)

    # Call function with unpacked kwargs
    main(GLOBAL_MSG, **kwargs)