# Connect to a socket / port
import socket
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((sys.argv[1], int(sys.argv[2])))

try:
    while True:
        data = s.recv(1024)
        if len(data) > 0:
            print("received " + data)
        else:
            break
finally:
    # Clean up the connection
    s.close()
