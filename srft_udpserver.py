from server import Server

# ------ testing if server functions are working --------
server = Server()

datagrams = [(1, b"Thi"), (2, b"s is"), (3, b" a pay"), (4, b"load")]
server.sort_payload(datagrams)
msg = server.assemble_payload()
print(msg)

# generate output and write to a txt file
output = server.generate_output("sample.txt", "285")
server.write_file("output.txt", output)