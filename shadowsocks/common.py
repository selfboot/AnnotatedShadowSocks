#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function, \
    with_statement

import socket
import struct
import logging


def compat_ord(s):
    """ Return an integer representing the Unicode code point of the character

    Ref: https://github.com/xuelangZF/AnnotatedShadowSocks/issues/5
    """
    if type(s) == int:
        return s
    return _ord(s)


def compat_chr(d):
    """ Return a string or bytes of one character whose ASCII code is the integer i.

    The argument d must be in the range [0..255], inclusive
    Python 2.7+ returns a string abd Python 3.3+ returns bytes.
    Ref: https://github.com/xuelangZF/AnnotatedShadowSocks/issues/6
    """
    if bytes == str:
        return _chr(d)
    return bytes([d])


_ord = ord
_chr = chr
ord = compat_ord
chr = compat_chr


def to_bytes(s):
    """ Convert string s into bytes sequence.

    To python3.3+, encode str type to bytes type.
    Ref: https://github.com/xuelangZF/AnnotatedShadowSocks/issues/6
    """
    if bytes != str:
        if type(s) == str:
            return s.encode('utf-8')
    return s


def to_str(s):
    """ Convert bytes s into str type.

    To python3.3+, decode bytes type to str type.
    Ref: https://github.com/xuelangZF/AnnotatedShadowSocks/issues/6
    """
    if bytes != str:
        if type(s) == bytes:
            return s.decode('utf-8')
    return s


def inet_ntop(family, ipstr):
    """ Convert a packed IP address to its standard, family-specific string representation.

    :param family: Supported values for address_family are currently AF_INET and AF_INET6.
    :param ipstr:  A 32-bit packed IPv4 address (a string four characters in length) or 128-bit ipv6.
            such as 'abcd' or 'abcdefghabcdefgh'.
    :return: A byte sequence, which is standard string representation for address.
            (for example, b'7.10.0.5' or '5aef:2b::8')

    Usage:
        >>> from shadowsocks.common import inet_pton, inet_ntop
        >>> import socket
        >>> inet_ntop(socket.AF_INET, 'abcd')
        '97.98.99.100'
        >>> inet_ntop(socket.AF_INET6, 'abcdefghijklmnop')
        '6162:6364:6566:6768:696A:6B6C:6D6E:6F70'

    Ref: https://github.com/xuelangZF/AnnotatedShadowSocks/issues/9
    """

    if family == socket.AF_INET:
        return to_bytes(socket.inet_ntoa(ipstr))
    elif family == socket.AF_INET6:
        import re
        v6addr = ':'.join(('%02X%02X' % (ord(i), ord(j))).lstrip('0')
                          for i, j in zip(ipstr[::2], ipstr[1::2]))
        v6addr = re.sub('::+', '::', v6addr, count=1)
        return to_bytes(v6addr)


def inet_pton(family, addr):
    """ Convert an IP address from its family-specific string format to a packed, binary format.

    Reverse process of inet_ntop.


    :param family: Supported values for address_family are currently AF_INET and AF_INET6.
    :param addr: A standard, family-specific string representation of IP, such as '7.10.0.5' or '5aef:2b::8'.
    :return: A 32-bit packed IPv4 address (a string four characters in length) or 128-bit ipv6.

    # TODO
    """
    addr = to_str(addr)
    if family == socket.AF_INET:
        return socket.inet_aton(addr)
    elif family == socket.AF_INET6:
        if '.' in addr:  # a v4 addr
            v4addr = addr[addr.rindex(':') + 1:]
            v4addr = socket.inet_aton(v4addr)
            v4addr = map(lambda x: ('%02X' % ord(x)), v4addr)
            v4addr.insert(2, ':')
            newaddr = addr[:addr.rindex(':') + 1] + ''.join(v4addr)
            return inet_pton(family, newaddr)
        dbyts = [0] * 8  # 8 groups
        grps = addr.split(':')
        for i, v in enumerate(grps):
            if v:
                dbyts[i] = int(v, 16)
            else:
                for j, w in enumerate(grps[::-1]):
                    if w:
                        dbyts[7 - j] = int(w, 16)
                    else:
                        break
                break
        return b''.join((chr(i // 256) + chr(i % 256)) for i in dbyts)
    else:
        raise RuntimeError("What family?")


def patch_socket():
    """ Bind inet_ntop and inet_pton function to socket module.

    socket.inet_pton and socket.inet_ntop are available only on most Unix platforms.
    Here we use custom function if there are no inet_pton or inet_ntop defined.

    Ref: https://docs.python.org/2/library/socket.html#socket.inet_pton
    """
    if not hasattr(socket, 'inet_pton'):
        socket.inet_pton = inet_pton

    if not hasattr(socket, 'inet_ntop'):
        socket.inet_ntop = inet_ntop


patch_socket()


ADDRTYPE_IPV4 = 1
ADDRTYPE_IPV6 = 4
ADDRTYPE_HOST = 3


def pack_addr(address):
    address_str = to_str(address)
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            r = socket.inet_pton(family, address_str)
            if family == socket.AF_INET6:
                return b'\x04' + r
            else:
                return b'\x01' + r
        except (TypeError, ValueError, OSError, IOError):
            pass
    if len(address) > 255:
        address = address[:255]  # TODO
    return b'\x03' + chr(len(address)) + address


def parse_header(data):
    addrtype = ord(data[0])
    dest_addr = None
    dest_port = None
    header_length = 0
    if addrtype == ADDRTYPE_IPV4:
        if len(data) >= 7:
            dest_addr = socket.inet_ntoa(data[1:5])
            dest_port = struct.unpack('>H', data[5:7])[0]
            header_length = 7
        else:
            logging.warn('header is too short')
    elif addrtype == ADDRTYPE_HOST:
        if len(data) > 2:
            addrlen = ord(data[1])
            if len(data) >= 2 + addrlen:
                dest_addr = data[2:2 + addrlen]
                dest_port = struct.unpack('>H', data[2 + addrlen:4 +
                                          addrlen])[0]
                header_length = 4 + addrlen
            else:
                logging.warn('header is too short')
        else:
            logging.warn('header is too short')
    elif addrtype == ADDRTYPE_IPV6:
        if len(data) >= 19:
            dest_addr = socket.inet_ntop(socket.AF_INET6, data[1:17])
            dest_port = struct.unpack('>H', data[17:19])[0]
            header_length = 19
        else:
            logging.warn('header is too short')
    else:
        logging.warn('unsupported addrtype %d, maybe wrong password' %
                     addrtype)
    if dest_addr is None:
        return None

    return addrtype, to_bytes(dest_addr), dest_port, header_length


def test_inet_conv():
    ipv4 = b'8.8.4.4'
    b = inet_pton(socket.AF_INET, ipv4)
    assert inet_ntop(socket.AF_INET, b) == ipv4
    ipv6 = b'2404:6800:4005:805::1011'
    b = inet_pton(socket.AF_INET6, ipv6)
    assert inet_ntop(socket.AF_INET6, b) == ipv6


def test_parse_header():
    assert parse_header(b'\x03\x0ewww.google.com\x00\x50') == \
        (3, b'www.google.com', 80, 18)
    assert parse_header(b'\x01\x08\x08\x08\x08\x00\x35') == \
        (1, b'8.8.8.8', 53, 7)
    assert parse_header((b'\x04$\x04h\x00@\x05\x08\x05\x00\x00\x00\x00\x00'
                         b'\x00\x10\x11\x00\x50')) == \
        (4, b'2404:6800:4005:805::1011', 80, 19)


def test_pack_header():
    assert pack_addr(b'8.8.8.8') == b'\x01\x08\x08\x08\x08'
    assert pack_addr(b'2404:6800:4005:805::1011') == \
        b'\x04$\x04h\x00@\x05\x08\x05\x00\x00\x00\x00\x00\x00\x10\x11'
    assert pack_addr(b'www.google.com') == b'\x03\x0ewww.google.com'


if __name__ == '__main__':
    test_inet_conv()
    test_parse_header()
    test_pack_header()
