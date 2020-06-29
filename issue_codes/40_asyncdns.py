#! /usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function, \
    with_statement
from shadowsocks import asyncdns
import binascii
import struct

address_set = set([b"google.com", b"example.com", "ns2.google.com", "invalid.@!#$%^&$@.hostname"])
hostname_set = set([b"-google.com", b"1example.com", "2.google.com", "invalid.@!#$%^&$@.hostname-"])

# Ref https://github.com/xuelangZF/AnnotatedShadowSocks/issues/39
# DNS response of google.com
dns_response_demo = u"911881800001" \
                    "00010000000006676f6f676c6503636f" \
                    "6d0000010001c00c000100010000012b" \
                    "0004acd91b8e"

# Convert hex string to bytes
# Ref: https://stackoverflow.com/questions/443967/how-to-create-python-bytes-object-from-long-hex-string
data = bytearray.fromhex(dns_response_demo)


def uc_build_address(addresses):
    """ Get a readable format of QNAME.
    """
    for address in addresses:
        print(address, end="==>")
        address = asyncdns.build_address(address)
        print(address)
        cur_label_len_index = 0
        while cur_label_len_index < len(address):
            cur_label_len = ord(address[cur_label_len_index])
            print(cur_label_len, end='')
            print(address[cur_label_len_index + 1: cur_label_len_index + cur_label_len + 1], end='')
            cur_label_len_index += cur_label_len + 1
        print()


def uc_is_valid_hostname(hostnames):
    for hostname in hostnames:
        print(hostname, asyncdns.is_valid_hostname(hostname))


def uc_parse_hostname(d, offset):
    print(":".join("{:02x}".format(ord(c)) for c in d))
    print(len(d))
    print("{:02x}".format(ord(d[offset])))

    print(asyncdns.parse_name(data, offset))


def uc_parse_record(d):
    print(asyncdns.parse_response(d))


if __name__ == "__main__":
    # uc_build_address(address_set)
    # uc_is_valid_hostname(hostname_set)
    # uc_parse_hostname(data, 28)
    # uc_parse_record(data)

    dns_request = asyncdns.build_request("google.com", 1, 0x9118)
    print(type(dns_request))
    print(dns_request)
    print(binascii.hexlify(dns_request))

    qtype_qclass = struct.pack('!HH', 1, 1)
    print(binascii.hexlify(qtype_qclass))
