import socket

from SFTP_Client_obj import Client
from socket import *
import os
import pickle
import SRFT_Message
from multiprocessing import Process

GLOBAL_MSG = {"ACK":[]}
HOST = '127.0.0.1'
PORT = 12345

def listener():
    # Setup listener socket
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    clientSocket.bind((HOST, PORT))
    while True:
        # Listen for acknowledgement
        data, addr = udp_socket.recvfrom(buffer_size)

        # Process and pass acknowledgement to global storage
        msg = pickle.loads(data)
        GLOBAL_MSG["ACK"].append(msg)



def main(**kwargs):

    if os.geteuid() != 0:
        print("This script must be run as root (raw sockets require admin privileges).")
        sys.exit(1)

    # Set up a client obj
    client = Client(kwards, GLOBAL_MSG)

    # Start listener process
    listener = Process(target=listener, args=())

    # Open and read file
    data = client.read_file("test.txt")
    # Split into packets
    split_data = client.split_data(data, 12345) #TODO: num of packets or packet size?
    # Make packets
    packets = client.make_datagrams(split_data)
    # Send packets (with considerations of rules to wait for ACK)
    while True:
        client.checkForACK()
        if len(client.sent_msgs) < 5:
            client.sendPacket(packets)
        else:
            for msg in client.sent_msgs:
                if msg["attempts"] < 5:
                    if time.time() > msg["timestamp"] + 5: #TODO: Need to confirm output of time.time()
                        # Resend msg
                        client.sendPacket(msg["packet"])

                else:
                    # Terminate program
                    print("Reached maximum number of attempts for a message. Exiting.")
                    exit(0) #TODO: Need to consider any clear up that might be needed.


if __name__ == '__main__':
    # sys.argv[0] is the script name, so skip it
    raw_args = sys.argv[1:]

    # Parse into kwargs
    kwargs = parse_kwargs_from_argv(raw_args)

    # Call function with unpacked kwargs
    my_function(**kwargs)
    main()