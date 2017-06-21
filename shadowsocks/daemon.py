#!/usr/bin/python
# -*- coding: utf-8 -*-


from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import sys
import logging
import signal
import time
from shadowsocks import common


def daemon_exec(config):
    # Do different operation according to the related daemon config.
    if 'daemon' in config:
        # os.name(ref: https://github.com/xuelangZF/AnnotatedShadowSocks/issues/23)
        if os.name != 'posix':
            raise Exception('daemon mode is only supported in unix')
        command = config['daemon']
        if not command:
            command = 'start'
        pid_file = config['pid-file']
        log_file = config['log-file']
        command = common.to_str(command)
        pid_file = common.to_str(pid_file)
        log_file = common.to_str(log_file)
        if command == 'start':
            daemon_start(pid_file, log_file)
        elif command == 'stop':
            daemon_stop(pid_file)
            # always exit after daemon_stop
            sys.exit(0)
        elif command == 'restart':
            daemon_stop(pid_file)
            daemon_start(pid_file, log_file)
        else:
            raise Exception('unsupported daemon command %s' % command)


def write_pid_file(pid_file, pid):
    """ Use the pid file to govern that the daemon is only running one instance.

    Open the pid file and set the close-on-exec flag firstly.
    Then try to acquire the exclusive lock of the pid file:
        If success, return 0 to start the daemon process.
        else, there already is a daemon process running, return -1.
    """
    import fcntl
    import stat

    # https://github.com/xuelangZF/AnnotatedShadowSocks/issues/23
    try:
        fd = os.open(pid_file, os.O_RDWR | os.O_CREAT,
                     stat.S_IRUSR | stat.S_IWUSR)
    except OSError as e:
        logging.error(e)
        return -1

    # https://github.com/xuelangZF/AnnotatedShadowSocks/issues/25
    flags = fcntl.fcntl(fd, fcntl.F_GETFD)
    assert flags != -1
    flags |= fcntl.FD_CLOEXEC
    r = fcntl.fcntl(fd, fcntl.F_SETFD, flags)
    assert r != -1

    # https://github.com/xuelangZF/AnnotatedShadowSocks/issues/26
    try:
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, 0, 0, os.SEEK_SET)
    except IOError:
        r = os.read(fd, 32)
        if r:
            logging.error('already started at pid %s' % common.to_str(r))
        else:
            logging.error('already started')
        os.close(fd)
        return -1
    os.ftruncate(fd, 0)
    os.write(fd, common.to_bytes(str(pid)))
    return 0


def freopen(f, mode, stream):
    """ Redirect predefined streams like stdin, stdout and stderr to specific files.

    Just like freopen function implemented in c++ <stdio.h>
    Ref: http://www.cplusplus.com/reference/cstdio/freopen/
    """
    oldf = open(f, mode)
    oldfd = oldf.fileno()
    newfd = stream.fileno()
    os.close(newfd)             # Not needed actually, dup2 will close newfd if it's open.
    os.dup2(oldfd, newfd)


def daemon_start(pid_file, log_file):
    """ Fork the current process and make the child to be a single-instance daemon.

    Ref: https://github.com/xuelangZF/AnnotatedShadowSocks/issues/27
    :param pid_file: used to make sure there is only one daemon process.
    :param log_file: used to save the log info.
    """
    pid = os.fork()
    assert pid != -1

    def handle_exit(signum, _):
        if signum == signal.SIGTERM:
            sys.exit(0)
        sys.exit(1)

    # Parent waits for child and exit.
    if pid > 0:
        # https://github.com/xuelangZF/AnnotatedShadowSocks/issues/28
        signal.signal(signal.SIGINT, handle_exit)
        signal.signal(signal.SIGTERM, handle_exit)
        time.sleep(5)
        sys.exit(0)

    ppid = os.getppid()
    pid = os.getpid()
    # There is already a daemon process running.
    if write_pid_file(pid_file, pid) != 0:
        os.kill(ppid, signal.SIGINT)
        sys.exit(1)

    print('started')
    # Child send signal to its parent to exit.
    os.kill(ppid, signal.SIGTERM)

    sys.stdin.close()
    try:
        freopen(log_file, 'a', sys.stdout)
        freopen(log_file, 'a', sys.stderr)
    except IOError as e:
        logging.error(e)
        os.kill(ppid, signal.SIGINT)
        sys.exit(1)


def daemon_stop(pid_file):
    """ Kill the daemon process if it's running.

    After calling kill to stop the process,
    wait at most 10 seconds and check if the process is stopped finally.
    :param pid_file: The file from which we can get the process id.
    """
    import errno
    try:
        with open(pid_file) as f:
            buf = f.read()
            pid = common.to_str(buf)
            if not buf:
                logging.error('not running')
    except IOError as e:
        logging.error(e)

        # No such pid_file, which means the daemon is not running.
        if e.errno == errno.ENOENT:
            logging.error('not running')
            return
        sys.exit(1)
    pid = int(pid)
    if pid > 0:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError as e:
            # No process with pid is running now, so just return 0.
            if e.errno == errno.ESRCH:
                logging.error('not running')
                return
            logging.error(e)
            sys.exit(1)
    else:
        logging.error('pid is not positive: %d', pid)

    # Sleep for maximum 10s to wait for the process stopped.
    for i in range(0, 200):
        try:
            # Check whether the process with pid is running or not.
            # Ref: https://github.com/xuelangZF/AnnotatedShadowSocks/issues/30
            os.kill(pid, 0)
        except OSError as e:
            if e.errno == errno.ESRCH:
                break
        time.sleep(0.05)

    # Ref: https://github.com/xuelangZF/AnnotatedShadowSocks/issues/29
    else:
        logging.error('timed out when stopping pid %d', pid)
        sys.exit(1)
    print('stopped')
    os.unlink(pid_file)
