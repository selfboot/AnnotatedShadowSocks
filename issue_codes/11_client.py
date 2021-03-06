#! /usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import socket
import sys

messages = ['This is the message.',
            'It will be sent',
            'in parts']

server_address = ('localhost', 10000)

# Create a TCP/IP socket
socks = [socket.socket(socket.AF_INET, socket.SOCK_STREAM),
         socket.socket(socket.AF_INET, socket.SOCK_STREAM)]

# Connect the socket to the port where the server is listening
print('connecting to %s port %s' % server_address)
for s in socks:
    s.connect(server_address)

for message in messages:
    # Send message on both sockets
    for s in socks:
        print('%s: sending "%s"' % (s.getsockname(), message))
        s.send(message)

    # Read response on both sockets
    for s in socks:
        data = s.recv(1024)
        print('%s: received "%s"' % (s.getsockname(), data))
        if not data:
            print('closing socket', s.getsockname())
            s.close()
