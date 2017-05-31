#!/usr/bin/python
# -*- coding: utf-8 -*-

# from ssloop
# https://github.com/clowwindy/ssloop

from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import socket
import select
import errno
import logging
from collections import defaultdict


__all__ = ['EventLoop', 'POLL_NULL', 'POLL_IN', 'POLL_OUT', 'POLL_ERR',
           'POLL_HUP', 'POLL_NVAL', 'EVENT_NAMES']

POLL_NULL = 0x00
POLL_IN = 0x01
POLL_OUT = 0x04
POLL_ERR = 0x08
POLL_HUP = 0x10
POLL_NVAL = 0x20


EVENT_NAMES = {
    POLL_NULL: 'POLL_NULL',
    POLL_IN: 'POLL_IN',
    POLL_OUT: 'POLL_OUT',
    POLL_ERR: 'POLL_ERR',
    POLL_HUP: 'POLL_HUP',
    POLL_NVAL: 'POLL_NVAL',
}


class EpollLoop(object):
    """ Encapsulate the epoll implementation in Linux, provide the consistent methods used in EventLoop.

    Details about select.epoll is available:
    https://github.com/xuelangZF/AnnotatedShadowSocks/issues/16
    """
    def __init__(self):
        self._epoll = select.epoll()

    def poll(self, timeout):
        return self._epoll.poll(timeout)

    def add_fd(self, fd, mode):
        self._epoll.register(fd, mode)

    def remove_fd(self, fd):
        self._epoll.unregister(fd)

    def modify_fd(self, fd, mode):
        self._epoll.modify(fd, mode)


class KqueueLoop(object):
    """ Encapsulate the kqueue implementation in BSD, provide the consistent methods used in EventLoop.

    Details about select.kqueue is available:
    https://github.com/xuelangZF/AnnotatedShadowSocks/issues/21
    """

    MAX_EVENTS = 1024

    def __init__(self):
        self._kqueue = select.kqueue()
        self._fds = {}

    def _control(self, fd, mode, flags):
        events = []
        if mode & POLL_IN:
            events.append(select.kevent(fd, select.KQ_FILTER_READ, flags))
        if mode & POLL_OUT:
            events.append(select.kevent(fd, select.KQ_FILTER_WRITE, flags))
        for e in events:
            self._kqueue.control([e], 0)

    def poll(self, timeout):
        if timeout < 0:
            timeout = None  # kqueue behaviour
        events = self._kqueue.control(None, KqueueLoop.MAX_EVENTS, timeout)
        results = defaultdict(lambda: POLL_NULL)
        for e in events:
            fd = e.ident
            if e.filter == select.KQ_FILTER_READ:
                results[fd] |= POLL_IN
            elif e.filter == select.KQ_FILTER_WRITE:
                results[fd] |= POLL_OUT
        return results.items()

    def add_fd(self, fd, mode):
        self._fds[fd] = mode
        self._control(fd, mode, select.KQ_EV_ADD)

    def remove_fd(self, fd):
        self._control(fd, self._fds[fd], select.KQ_EV_DELETE)
        del self._fds[fd]

    def modify_fd(self, fd, mode):
        self.remove_fd(fd)
        self.add_fd(fd, mode)


class SelectLoop(object):
    """ Encapsulate the select implementation for generality, provide the consistent methods used in EventLoop.

    Details about select.select is available:
    https://github.com/xuelangZF/AnnotatedShadowSocks/issues/11
    """
    def __init__(self):
        self._r_list = set()
        self._w_list = set()
        self._x_list = set()

    def poll(self, timeout):
        r, w, x = select.select(self._r_list, self._w_list, self._x_list,
                                timeout)
        # Details about defaultdict is available here:
        # https://github.com/xuelangZF/AnnotatedShadowSocks/issues/19
        results = defaultdict(lambda: POLL_NULL)
        for p in [(r, POLL_IN), (w, POLL_OUT), (x, POLL_ERR)]:
            for fd in p[0]:
                results[fd] |= p[1]
        return results.items()

    def add_fd(self, fd, mode):
        if mode & POLL_IN:
            self._r_list.add(fd)
        if mode & POLL_OUT:
            self._w_list.add(fd)
        if mode & POLL_ERR:
            self._x_list.add(fd)

    def remove_fd(self, fd):
        if fd in self._r_list:
            self._r_list.remove(fd)
        if fd in self._w_list:
            self._w_list.remove(fd)
        if fd in self._x_list:
            self._x_list.remove(fd)

    def modify_fd(self, fd, mode):
        self.remove_fd(fd)
        self.add_fd(fd, mode)


class EventLoop(object):
    """ EventLoop is used to serve the concurrent thousands of network connections.

    It encapsulates the underlying implementation of I/O interface on different platform
    and provides more readable and convenient functions to be used in shadowsocks.
    More details is available here:
    https://github.com/xuelangZF/AnnotatedShadowSocks/issues/20
    """

    def __init__(self):
        """ Select I/O model depend on platform and do initial operator.

        self._impl: point to the select model we use.
        self._fd_to_f: save the mapping relation between file descriptor and socket.
        self._handlers: save the
        self._ref_handlers:
        self._handlers_to_remove:
        """
        self._iterating = False
        if hasattr(select, 'epoll'):
            self._impl = EpollLoop()
            model = 'epoll'
        elif hasattr(select, 'kqueue'):
            self._impl = KqueueLoop()
            model = 'kqueue'
        elif hasattr(select, 'select'):
            self._impl = SelectLoop()
            model = 'select'
        else:
            raise Exception('can not find any available functions in select '
                            'package')
        self._fd_to_f = {}
        self._handlers = []
        self._ref_handlers = []
        self._handlers_to_remove = []
        logging.debug('using event model: %s', model)

    def poll(self, timeout=None):
        """ Polls the set of registered file descriptors, and returns a list containing (socket, fd, event)
        3-tuples for the descriptors that have events or errors to report.
        """
        events = self._impl.poll(timeout)
        return [(self._fd_to_f[fd], fd, event) for fd, event in events]

    def add(self, f, mode):
        """ Register a file descriptor with the specified mode in polling object.

        Record the file descriptor and socket relation at the same time.
        """
        fd = f.fileno()
        self._fd_to_f[fd] = f
        self._impl.add_fd(fd, mode)

    def remove(self, f):
        """ Remove a file descriptor being tracked by the polling object.

        Def the file descriptor and socket at the same time.
        """
        fd = f.fileno()
        del self._fd_to_f[fd]
        self._impl.remove_fd(fd)

    def modify(self, f, mode):
        # Modifies an already registered fd.
        fd = f.fileno()
        self._impl.modify_fd(fd, mode)

    def add_handler(self, handler, ref=True):
        self._handlers.append(handler)
        if ref:
            # when all ref handlers are removed, loop stops
            self._ref_handlers.append(handler)

    def remove_handler(self, handler):
        if handler in self._ref_handlers:
            self._ref_handlers.remove(handler)
        if self._iterating:
            self._handlers_to_remove.append(handler)
        else:
            self._handlers.remove(handler)

    def run(self):
        events = []
        while self._ref_handlers:
            try:
                events = self.poll(1)
            except (OSError, IOError) as e:
                if errno_from_exception(e) in (errno.EPIPE, errno.EINTR):
                    # EPIPE: Happens when the client closes the connection
                    # EINTR: Happens when received a signal handles them as soon as possible
                    logging.debug('poll:%s', e)
                else:
                    logging.error('poll:%s', e)
                    import traceback
                    traceback.print_exc()
                    continue
            self._iterating = True
            for handler in self._handlers:
                # TODO when there are a lot of handlers
                try:
                    handler(events)
                except (OSError, IOError) as e:
                    logging.error(e)
                    import traceback
                    traceback.print_exc()
            for handler in self._handlers_to_remove:
                self._handlers.remove(handler)
                self._handlers_to_remove = []
            self._iterating = False


# from tornado
def errno_from_exception(e):
    """Extract the errno from an Exception object.

    There are cases that the errno attribute was not set so we pull
    the errno out of the args but if someone instatiates an Exception
    without any args you will get a tuple error. So this function
    abstracts all that behavior to give you a safe way to get the
    errno.
    """

    if hasattr(e, 'errno'):
        return e.errno
    elif e.args:
        return e.args[0]
    else:
        return None


# from tornado
def get_sock_error(sock):
    error_number = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
    return socket.error(error_number, os.strerror(error_number))
