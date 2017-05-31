#! /usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import select
import Queue
import sys

# Create a TCP/IP socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setblocking(0)

# Bind the socket to the port
server_address = ('localhost', 10000)
print >> sys.stderr, 'starting up on %s port %s' % server_address
server.bind(server_address)

# Listen for incoming connections
server.listen(5)

# Keep up with the queues of outgoing messages
message_queues = {}

# Do not block forever(milliseconds)
TIMEOUT = 1000

# Commonly used flag setes
READ_ONLY = select.EPOLLIN | select.EPOLLPRI | select.EPOLLHUP | select.EPOLLERR
READ_WRITE = READ_ONLY | select.EPOLLOUT

# Set up the epoller
epoller = select.epoll()
epoller.register(server, READ_ONLY | select.EPOLLET)

# Map file description to socket objects
fd_to_sockets = {server.fileno(): server}

while True:
    # Wait for at least one of the sockets to be ready for processing
    print >> sys.stderr, '\nWaiting for the next event'
    events = epoller.poll(TIMEOUT)

    for fd, flag in events:
        s = fd_to_sockets[fd]

        # Handle inputs
        if flag & (select.EPOLLIN | select.EPOLLPRI):
            # A readable server is ready to accept a connection
            if s is server:
                connection, client_address = s.accept()
                print >> sys.stderr, 'new connection from', client_address
                connection.setblocking(0)
                fd_to_sockets[connection.fileno()] = connection
                epoller.register(connection, READ_ONLY | select.EPOLLET)

                # Give the connection a queue for the data we want to send
                message_queues[connection] = Queue.Queue()
            else:
                data = s.recv(1024)
                # A readable client socket has data
                if data:
                    print >> sys.stderr, 'received "%s" from %s' % (data, s.getpeername())
                    # Add output channel for response
                    message_queues[s].put(data)
                    epoller.modify(s, READ_WRITE | select.EPOLLET)
                else:
                    # Interpret empty result as closed connection
                    print >> sys.stderr, 'closing ', client_address, 'after reading no data'
                    # Stop listening for input on the connection
                    epoller.unregister(s)
                    s.close()

                    # Remove the message queue
                    del message_queues[s]
        elif flag & select.EPOLLHUP:
            # Client hung up
            print >> sys.stderr, 'closing', client_address, ' after receiving HUP'
            # Stop listening for input on the connection
            epoller.unregister(s)
            s.close()
        elif flag & select.EPOLLOUT:
            # Socket is ready to send data, if there is any to send
            try:
                next_msg = message_queues[s].get_nowait()
            except Queue.Empty:
                # No message waiting so stop checking for writability
                print >> sys.stderr, 'output queue for', s.getpeername(), 'is empty'
                epoller.modify(s, READ_ONLY | select.EPOLLET)
            else:
                print >> sys.stderr, 'sending "%s" to "%s"' % (next_msg, s.getpeername())
                s.send(next_msg)

        elif flag & select.POLLERR:
            print >> sys.stderr, 'handling exceptional condition for', s.getpeername()
            epoller.unregister(s)
            s.close()

            # Remove message queue
            del message_queues[s]
