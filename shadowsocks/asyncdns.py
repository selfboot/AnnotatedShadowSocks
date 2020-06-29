#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function, \
    with_statement

import time
import os
import socket
import struct
import re
import logging

from shadowsocks import common, lru_cache, eventloop


CACHE_SWEEP_INTERVAL = 30

# Ref: https://github.com/xuelangZF/AnnotatedShadowSocks/issues/41
VALID_HOSTNAME = re.compile(br"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)

# Dynamically add the method inet_pton and inet_ntop to the socket.
common.patch_socket()

# rfc1035
# format
# +---------------------+
# |        Header       |
# +---------------------+
# |       Question      | the question for the name server
# +---------------------+
# |        Answer       | RRs answering the question
# +---------------------+
# |      Authority      | RRs pointing toward an authority
# +---------------------+
# |      Additional     | RRs holding additional information
# +---------------------+
#
# Header
#                                 1  1  1  1  1  1
#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      ID                       |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    QDCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ANCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    NSCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ARCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#
# Question
#                                     1  1  1  1  1  1
#      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                                               |
#    /                     QNAME                     /
#    /                                               /
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                     QTYPE                     |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                     QCLASS                    |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+


# TYPE, CLASS, QTYPE and QCLASS values can be found at #38
QTYPE_ANY = 255
QTYPE_A = 1
QTYPE_AAAA = 28
QTYPE_CNAME = 5
QTYPE_NS = 2
QCLASS_IN = 1


def build_address(address):
    """ Convert domain name to QNAME used in the DNS Question section.

    Return a sequence of labels, where each label consists of a
    length octet followed by that number of octets.
    The domain name terminates with the zero length octet
    for the null label of the root.

    Ref: RFC 1035 4.1.2. Question section format

    :param address: domain name
    """
    address = address.strip(b'.')
    labels = address.split(b'.')
    results = []
    # Labels must be 63 characters or less.  Ref: RFC 1035
    for label in labels:
        l = len(label)
        if l > 63:
            return None
        results.append(common.chr(l))
        results.append(label)
    results.append(b'\0')
    return b''.join(results)


def build_request(address, qtype, request_id):
    """ Build a DNS request packet with the specified parameter.

    Ref: https://github.com/xuelangZF/AnnotatedShadowSocks/issues/40
    """
    header = struct.pack('!HBBHHHH', request_id, 1, 0, 1, 0, 0, 0)
    addr = build_address(address)
    qtype_qclass = struct.pack('!HH', qtype, QCLASS_IN)
    return header + addr + qtype_qclass


def parse_ip(addrtype, data, length, offset):
    """ Get the RDATA field from the RR(Resource Record).

    RDATA is a variable length string of octets that describes the resource.
    More details can be found on RFC 1035 and Issue #38
    :param addrtype: TYPE of the resource record, can be A, AAAA, CNAME or NS.
    :param data: The whole DNS packet.  Note the UDP and IP header is not contained.
    :param length: The length of the RDATA field.
    :param offset: Where this field start.
    :return: The info RDATA field record.
    """
    if addrtype == QTYPE_A:
        return socket.inet_ntop(socket.AF_INET, data[offset:offset + length])
    elif addrtype == QTYPE_AAAA:
        return socket.inet_ntop(socket.AF_INET6, data[offset:offset + length])
    elif addrtype in [QTYPE_CNAME, QTYPE_NS]:
        return parse_name(data, offset)[1]
    else:
        return data[offset:offset + length]


def parse_name(data, offset):
    """ Get domain name from the response packet.

    The domain system utilizes a compression scheme to reduce the size of messages.
    Ref:
    https://github.com/xuelangZF/AnnotatedShadowSocks/issues/38
    https://github.com/xuelangZF/AnnotatedShadowSocks/issues/42

    :param data: The whole DNS packet.  Note the UDP and IP header is not contained.
    :param offset: Index specify where the hostname field start in DNS packet.
    :return: A tuple. Firstly is the length of the NAME section, secondly is the hostname.
    """
    p = offset
    labels = []
    l = common.ord(data[p])

    # A sequence of labels ending in a zero octet.
    while l > 0:
        # If NAME's first two bits are 11, then it's a pointer, we need to get the OFFSET.
        if (l & (128 + 64)) == (128 + 64):
            pointer = struct.unpack('!H', data[p:p + 2])[0]
            pointer &= 0x3FFF                   # Get the offset
            r = parse_name(data, pointer)
            labels.append(r[1])
            p += 2
            # Assert: pointer is always the domain name's end.
            return p - offset, b'.'.join(labels)
        # Each label consists of a length octet followed by that number of octets.
        else:
            labels.append(data[p + 1:p + 1 + l])
            p += 1 + l
        l = common.ord(data[p])
    return p - offset + 1, b'.'.join(labels)

# https://github.com/xuelangZF/AnnotatedShadowSocks/issues/38
#
# Resource record format
#                                    1  1  1  1  1  1
#      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                                               |
#    /                                               /
#    /                      NAME                     /
#    |                                               |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                      TYPE                     |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                     CLASS                     |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                      TTL                      |
#    |                                               |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                   RDLENGTH                    |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
#    /                     RDATA                     /
#    /                                               /
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+


def parse_record(data, offset, question=False):
    """ Parse either the question section or resource record.

    The answer, authority, and additional sections all share the same format:
    a variable number of resource records.
    Ref: https://github.com/xuelangZF/AnnotatedShadowSocks/issues/38

    :param data: The whole DNS packet content, which is consist of bytes.
    :param offset: Where this record start.
    :param question: Flag to specify whether this is a question record or answer record.
    :return: A tuple, firstly is the record's length, secondly is the concrete information.
    """

    nlen, name = parse_name(data, offset)
    # Parse the answer, authority, and additional sections.  Ref: issue #38
    if not question:
        record_type, record_class, record_ttl, record_rdlength = struct.unpack(
            '!HHiH', data[offset + nlen:offset + nlen + 10]
        )
        ip = parse_ip(record_type, data, record_rdlength, offset + nlen + 10)
        return nlen + 10 + record_rdlength, \
            (name, ip, record_type, record_class, record_ttl)
    # Parse the entries in question section.
    else:
        record_type, record_class = struct.unpack(
            '!HH', data[offset + nlen:offset + nlen + 4]
        )
        return nlen + 4, (name, None, record_type, record_class, None, None)


def parse_header(data):
    """ Get the header info from the original data.

    Ref: https://github.com/xuelangZF/AnnotatedShadowSocks/issues/38
    """
    if len(data) >= 12:
        header = struct.unpack('!HBBHHHH', data[:12])
        res_id = header[0]
        res_qr = header[1] & 128
        res_tc = header[1] & 2
        res_ra = header[2] & 128
        res_rcode = header[2] & 15
        res_qdcount = header[3]
        res_ancount = header[4]
        res_nscount = header[5]
        res_arcount = header[6]
        return (res_id, res_qr, res_tc, res_ra, res_rcode, res_qdcount,
                res_ancount, res_nscount, res_arcount)
    return None


def parse_response(data):
    """ Parse the DNS packet and save the useful info into the DNSResponse class.

    :param data: The whole DNS packet content, which is consist of bytes.
    :return: Return a DNSResponse object if response is valid, else return None.
    """
    try:
        # DNS packet's header is larger than 12 octets.
        if len(data) >= 12:
            header = parse_header(data)
            if not header:
                return None
            res_id, res_qr, res_tc, res_ra, res_rcode, res_qdcount, \
                res_ancount, res_nscount, res_arcount = header

            qds = []
            ans = []
            offset = 12                 # Skip the header(12 octets).

            # Parse all entries in question, answer, authority and additional records sections.
            for i in range(0, res_qdcount):
                l, r = parse_record(data, offset, True)
                offset += l
                if r:
                    qds.append(r)
            for i in range(0, res_ancount):
                l, r = parse_record(data, offset)
                offset += l
                if r:
                    ans.append(r)
            for i in range(0, res_nscount):
                l, r = parse_record(data, offset)
                offset += l
            for i in range(0, res_arcount):
                l, r = parse_record(data, offset)
                offset += l
            response = DNSResponse()
            if qds:
                response.hostname = qds[0][0]
            for an in qds:
                response.questions.append((an[1], an[2], an[3]))
            for an in ans:
                response.answers.append((an[1], an[2], an[3]))
            return response
    except Exception as e:
        import traceback
        traceback.print_exc()
        logging.error(e)
        return None


def is_ip(address):
    """ Return IP family if address is a valid IP Address, else return False.

    :param address: family-specific string format of IP address.
    """
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            if type(address) != str:
                address = address.decode('utf8')
            socket.inet_pton(family, address)
            return family
        except (TypeError, ValueError, OSError, IOError):
            pass
    return False


def is_valid_hostname(hostname):
    """ Return True is hostname is valid, otherwise return False.

    Hostname is composed of series of labels concatenated with dots,
    And there are some fundamentals should observe.  Details can be found:
    https://github.com/xuelangZF/AnnotatedShadowSocks/issues/41

    :param hostname: The type of hostname must be bytes.
    """
    if len(hostname) > 255:
        return False
    if hostname[-1] == b'.':
        hostname = hostname[:-1]
    return all(VALID_HOSTNAME.match(x) for x in hostname.split(b'.'))


class DNSResponse(object):
    """ Simple class to record the major response info.
    """
    def __init__(self):
        self.hostname = None
        self.questions = []  # each: (addr, type, class)
        self.answers = []    # each: (addr, type, class)

    def __str__(self):
        return '%s: %s' % (self.hostname, str(self.answers))


STATUS_IPV4 = 0
STATUS_IPV6 = 1


class DNSResolver(object):

    def __init__(self):
        """
        _loop: event loop object bind to.
        _request_id: DNS request id used to map the request and response.
        _hosts: dns records parsed from hosts file once initialized.
        _hostname_status:
        _hostname_to_cb: Mapping domain names to callback functions
        _cb_to_hostname: Mapping callback functions to domain names, conversely
        _cache: DNS record cache dict, such as {"localhost": "127.0.0.1"}
        _last_time:
        _sock:
        _servers: DNS server address parsed from /etc/resolv.conf or default value if it's empty
        _parse_resolv:
        _parse_hosts:
        """
        self._loop = None
        self._request_id = 1
        self._hosts = {}
        self._hostname_status = {}
        self._hostname_to_cb = {}
        self._cb_to_hostname = {}
        self._cache = lru_cache.LRUCache(timeout=300)
        self._last_time = time.time()
        self._sock = None
        self._servers = None
        self._parse_resolv()
        self._parse_hosts()
        # TODO monitor hosts change and reload hosts
        # TODO parse /etc/gai.conf and follow its rules

    def _parse_resolv(self):
        """ Load the DNS server address from /etc/resolv.conf to the _servers list.

        If resolv.conf has no DNS server specified, just us Google's server
        Ref: https://github.com/xuelangZF/AnnotatedShadowSocks/issues/35
        """
        self._servers = []
        try:
            with open('/etc/resolv.conf', 'rb') as f:
                content = f.readlines()
                for line in content:
                    line = line.strip()
                    if line:
                        if line.startswith(b'nameserver'):
                            parts = line.split()
                            if len(parts) >= 2:
                                server = parts[1]
                                if is_ip(server) == socket.AF_INET:
                                    if type(server) != str:
                                        server = server.decode('utf8')
                                    self._servers.append(server)
        except IOError:
            pass
        if not self._servers:
            self._servers = ['8.8.4.4', '8.8.8.8']

    def _parse_hosts(self):
        """ Load default ip and domain mappings from the hosts file to the _hosts dict.

        Ref: https://github.com/xuelangZF/AnnotatedShadowSocks/issues/35
        """
        etc_path = '/etc/hosts'
        if 'WINDIR' in os.environ:
            etc_path = os.environ['WINDIR'] + '/system32/drivers/etc/hosts'
        try:
            with open(etc_path, 'rb') as f:
                for line in f.readlines():
                    line = line.strip()
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        if is_ip(ip):
                            for i in range(1, len(parts)):
                                hostname = parts[i]
                                if hostname:
                                    self._hosts[hostname] = ip
        except IOError:
            self._hosts['localhost'] = '127.0.0.1'

    def add_to_loop(self, loop, ref=False):
        """ Bind the resolver to specified EventLoop and add UDP socket to the loop.
        """
        if self._loop:
            raise Exception('already add to loop')
        self._loop = loop
        # TODO when dns server is IPv6
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                   socket.SOL_UDP)
        self._sock.setblocking(False)
        loop.add(self._sock, eventloop.POLL_IN)
        loop.add_handler(self.handle_events, ref=ref)

    def _call_callback(self, hostname, ip, error=None):
        callbacks = self._hostname_to_cb.get(hostname, [])
        for callback in callbacks:
            if callback in self._cb_to_hostname:
                del self._cb_to_hostname[callback]
            if ip or error:
                callback((hostname, ip), error)
            else:
                callback((hostname, None),
                         Exception('unknown hostname %s' % hostname))
        if hostname in self._hostname_to_cb:
            del self._hostname_to_cb[hostname]
        if hostname in self._hostname_status:
            del self._hostname_status[hostname]

    def _handle_data(self, data):
        response = parse_response(data)
        if response and response.hostname:
            hostname = response.hostname
            ip = None
            for answer in response.answers:
                if answer[1] in (QTYPE_A, QTYPE_AAAA) and \
                        answer[2] == QCLASS_IN:
                    ip = answer[0]
                    break
            if not ip and self._hostname_status.get(hostname, STATUS_IPV6) \
                    == STATUS_IPV4:
                self._hostname_status[hostname] = STATUS_IPV6
                self._send_req(hostname, QTYPE_AAAA)
            else:
                if ip:
                    self._cache[hostname] = ip
                    self._call_callback(hostname, ip)
                elif self._hostname_status.get(hostname, None) == STATUS_IPV6:
                    for question in response.questions:
                        if question[1] == QTYPE_AAAA:
                            self._call_callback(hostname, None)
                            break

    def handle_events(self, events):
        for sock, fd, event in events:
            if sock != self._sock:
                continue
            if event & eventloop.POLL_ERR:
                logging.error('dns socket err')
                self._loop.remove(self._sock)
                self._sock.close()
                # TODO when dns server is IPv6
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                           socket.SOL_UDP)
                self._sock.setblocking(False)
                self._loop.add(self._sock, eventloop.POLL_IN)
            else:
                data, addr = sock.recvfrom(1024)
                if addr[0] not in self._servers:
                    logging.warn('received a packet other than our dns')
                    break
                self._handle_data(data)
            break
        now = time.time()
        if now - self._last_time > CACHE_SWEEP_INTERVAL:
            self._cache.sweep()
            self._last_time = now

    def remove_callback(self, callback):
        hostname = self._cb_to_hostname.get(callback)
        if hostname:
            del self._cb_to_hostname[callback]
            arr = self._hostname_to_cb.get(hostname, None)
            if arr:
                arr.remove(callback)
                if not arr:
                    del self._hostname_to_cb[hostname]
                    if hostname in self._hostname_status:
                        del self._hostname_status[hostname]

    def _send_req(self, hostname, qtype):
        """ Send DNS request to all DNS servers.
        """
        self._request_id += 1
        if self._request_id > 32768:
            self._request_id = 1
        req = build_request(hostname, qtype, self._request_id)
        for server in self._servers:
            logging.debug('resolving %s with type %d using server %s',
                          hostname, qtype, server)
            self._sock.sendto(req, (server, 53))

    def resolve(self, hostname, callback):
        if type(hostname) != bytes:
            hostname = hostname.encode('utf8')
        if not hostname:
            callback(None, Exception('empty hostname'))
        elif is_ip(hostname):
            callback((hostname, hostname), None)
        elif hostname in self._hosts:
            logging.debug('hit hosts: %s', hostname)
            ip = self._hosts[hostname]
            callback((hostname, ip), None)
        elif hostname in self._cache:
            logging.debug('hit cache: %s', hostname)
            ip = self._cache[hostname]
            callback((hostname, ip), None)
        else:
            if not is_valid_hostname(hostname):
                callback(None, Exception('invalid hostname: %s' % hostname))
                return
            arr = self._hostname_to_cb.get(hostname, None)
            if not arr:
                self._hostname_status[hostname] = STATUS_IPV4
                self._send_req(hostname, QTYPE_A)
                self._hostname_to_cb[hostname] = [callback]
                self._cb_to_hostname[callback] = hostname
            else:
                arr.append(callback)
                # TODO send again only if waited too long
                self._send_req(hostname, QTYPE_A)

    def close(self):
        if self._sock:
            self._sock.close()
            self._sock = None


def test():
    dns_resolver = DNSResolver()
    loop = eventloop.EventLoop()
    dns_resolver.add_to_loop(loop, ref=True)

    global counter
    counter = 0

    def make_callback():
        global counter

        def callback(result, error):
            global counter
            # TODO: what can we assert?
            print(result, error)
            counter += 1
            if counter == 9:
                loop.remove_handler(dns_resolver.handle_events)
                dns_resolver.close()
        a_callback = callback
        return a_callback

    assert(make_callback() != make_callback())

    dns_resolver.resolve(b'google.com', make_callback())
    dns_resolver.resolve('google.com', make_callback())
    dns_resolver.resolve('example.com', make_callback())
    dns_resolver.resolve('ipv6.google.com', make_callback())
    dns_resolver.resolve('www.facebook.com', make_callback())
    dns_resolver.resolve('ns2.google.com', make_callback())
    dns_resolver.resolve('invalid.@!#$%^&$@.hostname', make_callback())
    dns_resolver.resolve('toooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'long.hostname', make_callback())
    dns_resolver.resolve('toooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'long.hostname', make_callback())

    loop.run()


if __name__ == '__main__':
    test()
