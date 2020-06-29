from __future__ import print_function
import socket
import sys
import os

sys.path.append(os.path.abspath(os.path.join('..')))
from shadowsocks.common import inet_ntop
from shadowsocks.common import inet_pton


def test_inet_ntop():
    print(inet_ntop(socket.AF_INET6, b"\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78"))
    print(inet_ntop(socket.AF_INET, b"\xc0\xa8\x01\x01"))       # 192.168.1.1
    print(inet_ntop(socket.AF_INET, b"\xff\xff\xff\xff"))       # 255.255.255.255
    print(inet_ntop(socket.AF_INET, b"\x00\x00\x00\x00"))       # 0.0.0.0


def test_inet_pton():
    print(hex_2_bin(inet_pton(socket.AF_INET, '192.168.1.1')))
    print(hex_2_bin(inet_pton(socket.AF_INET, "255.255.255.255")))
    print(hex_2_bin(inet_pton(socket.AF_INET, "0.0.0.0")))
    print(hex_2_bin(inet_pton(socket.AF_INET6, '1234:5678:1234:5678:1234:5678:1234:5678')))


def hex_2_bin(binary_str):
    # Refer: https://stackoverflow.com/questions/11676864/how-can-i-format-an-integer-to-a-two-digit-hex
    # print(map(hex, map(ord, binary_str)))
    # print(map("{:02x}".format, map(ord, binary_str)))
    return "".join(map("{:02x}".format, map(ord, binary_str)))


if __name__ == '__main__':
    test_inet_ntop()
    print("--" * 10)
    test_inet_pton()
