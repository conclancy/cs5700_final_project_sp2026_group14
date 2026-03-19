from client import Client
from datagram import Datagram

# code just for testing if functions are working
client = Client()

# read from file (get data) -> split data into chunks -> create datagrams
data = client.read_file('sample.txt')
split_data = client.split_data(data, 10)
datagrams = client.make_datagrams(split_data)

for i in range(0, len(datagrams)):
    print(datagrams[i])
    print("------------------------------------------------")