#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import print_function
import json

json_content = u"""
{
    "server":"45.76.222.198",
    "server_port":8888,
    "local_address": "127.0.0.1",
    "local_port":1080,
    "password":"self boot",
    "timeout":300,
    "method":"aes-256-cfb",
    "comments": ["中文内容", 1, 2]
}
"""


def _decode_list(data):
    rv = []
    for item in data:
        if hasattr(item, 'encode'):
            item = item.encode('utf-8')
        elif isinstance(item, list):
            item = _decode_list(item)
        elif isinstance(item, dict):
            item = _decode_dict(item)
        rv.append(item)
    return rv


def _decode_dict(data):
    rv = {}
    for key, value in data.items():
        if hasattr(value, 'encode'):
            value = value.encode('utf-8')
        elif isinstance(value, list):
            value = _decode_list(value)
        elif isinstance(value, dict):
            value = _decode_dict(value)
        rv[key] = value
    return rv


if __name__ == "__main__":
    # Without object_hook
    config = json.loads(json_content)
    print(config)

    # With object_hook
    config_2 = json.loads(json_content, object_hook=_decode_dict)
    print(config_2)

    # json content is str before load.
    config_3 = json.loads(json_content.encode("utf-8"))
    print(config_3)
