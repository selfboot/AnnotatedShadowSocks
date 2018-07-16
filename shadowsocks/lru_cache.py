#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function, \
    with_statement

import collections
import logging
import time


# this LRUCache is optimized for concurrency, not QPS
# n: concurrency, keys stored in the cache
# m: visits not timed out, proportional to QPS * timeout
# get & set is O(1), not O(n). thus we can support very large n
# TODO: if timeout or QPS is too large, then this cache is not very efficient,
#       as sweep() causes long pause


class LRUCache(collections.MutableMapping):
    """ Cache 类，使用最近最少使用替换策略管理cache

    该类用法类似于dict，可以保存一系列 key-value，每次读或者写 key 的值，都会更新该 key 的操作时间
    对于 timeout 时间内，没有进行任何操作的key-value，将其从 key-value 键值对中删除.

    collections.MutableMapping 是可变 mappings 的抽象基类。(ABCs for mutable mappings)
    提供了以下抽象方法: __getitem__, __setitem__, __delitem__, __iter__, __len__
    继承了 collections.Mapping 的所有方法, 此外还有 pop, popitem, clear, update, and setdefault 方法
    文档: https://docs.python.org/2/library/collections.html#collections-abstract-base-classes

    注意这个类不是线程安全的!  如果多个线程使用一个全局LRUCache变量，可能会出现意外情况.
    """

    def __init__(self, timeout=60, close_callback=None, *args, **kwargs):
        """ 实例对象的初始化，设置缓存失效时间，回调函数，以及键值的初始化操作.

        注意，初始化时，前两个参数会被识别为 named arguments: timeout 和 close_callback
        更多关于 *args 和 **kwargs 的说明，可以参考:
        http://stackoverflow.com/questions/3394835/args-and-kwargs

        :param timeout: cache 有效的时间
        :param close_callback: cache失效时，执行的回调函数
        :param args: 可以是一个 mapping 对象，或者一个iterable对象，其中每项有两个对象
        :param kwargs: 关键字参数，可以用来进行初始化操作
        """
        self.timeout = timeout
        self.close_callback = close_callback

        # 存储 cache 中的 key-value 键值对
        self._store = {}

        self._time_to_keys = collections.defaultdict(list)
        """ 保存某一时间 t 访问的 keys.

        collections.defaultdict([default_factory[, ...]] 返回一个类似dictionary的对象.
        其中keys的值, 自行确定赋值.  但是values的类型, 是function_factory的类实例, 而且具有默认值.
        比如default(int)则创建一个类似dictionary对象, 里面任何的values都是int的实例,
        而且就算是一个不存在的key, d[key] 也有一个默认值,这个默认值是int()的默认值0.

        Doc： https://docs.python.org/2/library/collections.html#defaultdict-objects

        >>> import collections
        >>> store = collections.defaultdict(int)
        >>> store[2]
        0
        >>> store = collections.defaultdict(list)
        >>> store[1]
        []
        """

        # 保存 key 最后一次访问的时间
        self._keys_to_last_time = {}

        self._last_visits = collections.deque()
        """ 保存最近访问 cache 的时间.

        collections.deque 返回一个双端队列（类似 list），可以 O(1) 的时间复杂度在首尾添加、删除元素。
        主要提供了 append, appendleft, pop, popleft, extend, extendleft 等方法。

        >>> import collections
        >>> dq = collections.deque()
        >>> dq.append(2)
        >>> dq.append(3)
        >>> dq
        deque([2, 3])
        >>> dq.appendleft(1)
        >>> dq
        deque([1, 2, 3])
        >>> dq.pop()
        3
        >>> dq.popleft()
        1
        >>> dq
        deque([2])
        """

        self.update(dict(*args, **kwargs))
        """ 用 args 和 kwargs 来初始化cache中的 key-value 对

        dict 类的使用方法： https://docs.python.org/2/library/stdtypes.html#mapping-types-dict .

        >>> a = dict(one=1, two=2, three=3)
        >>> b = {'one': 1, 'two': 2, 'three': 3}
        >>> c = dict(zip(['one', 'two', 'three'], [1, 2, 3]))
        >>> d = dict([('two', 2), ('one', 1), ('three', 3)])
        >>> e = dict({'three': 3, 'one': 1, 'two': 2})
        >>> a == b == c == d == e
        True
        """

    def __getitem__(self, key):
        """ 从 cache 中获取 key 对应的值, 时间复杂度为 O(1)

        读取 cache 同时进行以下操作:
            1. 更新 key 最后一次访问的时间 t;
            2. 更新时间点 t 访问的 key 的记录;
            3. 更新保存最近一次访问 cache 时间的队列;
        """
        t = time.time()
        self._keys_to_last_time[key] = t
        self._time_to_keys[t].append(key)
        self._last_visits.append(t)
        return self._store[key]

    def __setitem__(self, key, value):
        """ 将 (key, value) 键值对写入到 cache 中, 时间复杂度为 O(1)

        写入 cache 同时进行以下操作:
            1. 更新 key 最后一次访问的时间 t;
            2. 更新时间点 t 访问的 key 的记录;
            3. 更新保存最近一次访问 cache 时间的队列;
        """
        t = time.time()
        self._keys_to_last_time[key] = t
        self._store[key] = value
        self._time_to_keys[t].append(key)
        self._last_visits.append(t)

    def __delitem__(self, key):
        """ 从 cache 中删除 key 记录, 时间复杂度为 O(1)

        在 _store 中删除 key, 同时删除字典中 key的最后一次访问时间记录。
        """
        del self._store[key]
        del self._keys_to_last_time[key]

    def __iter__(self):
        """ 返回一个迭代器对象, 里面是 cache 保存的内容 """
        return iter(self._store)

    def __len__(self):
        """返回 cache 的长度"""
        return len(self._store)

    def sweep(self):
        """ 清除缓存中过期的 key-value 对

        如果某个 key 在 timeout 时间内没有任何操作（读或者写），那么从 _store 中删除该键值对.
        """
        now = time.time()
        c = 0
        while len(self._last_visits) > 0:
            least = self._last_visits[0]
            if now - least <= self.timeout:
                break

            # 只有 key 确实在 _store 且 timeout 时间没有被访问才能先执行 callback， 然后销毁
            if self.close_callback is not None:
                for key in self._time_to_keys[least]:
                    if key in self._store:
                        if now - self._keys_to_last_time[key] > self.timeout:
                            value = self._store[key]
                            self.close_callback(value)

            for key in self._time_to_keys[least]:
                # 如果 least 时间时进行了n次操作，那么 _last_visits 队列中也会连续保存n次 least
                # 因此，这里在内层循环中每次都要执行 popleft 操作
                self._last_visits.popleft()
                if key in self._store:
                    if now - self._keys_to_last_time[key] > self.timeout:
                        del self._store[key]
                        del self._keys_to_last_time[key]
                        c += 1
            del self._time_to_keys[least]
        if c:
            logging.debug('%d keys swept' % c)


def demo_close_callback(value):
    print("The value %s is sweeped: " % str(value))


def test_close_callback():
    # 测试 close_callback 的使用
    c = LRUCache(timeout=0.3, close_callback=demo_close_callback)
    c['a'] = 1
    c['b'] = "strTest"
    time.sleep(0.5)
    c.sweep()


def test_private_data():
    # 查看LRUCache中保存各种信息的数据
    c = LRUCache(timeout=0.3)
    c['a'] = 12
    c['b'] = 4
    time.sleep(0.5)
    print(c['b'])     # 读取 b 中保存的数据

    print(c._store, c._last_visits, c._time_to_keys, c._keys_to_last_time)
    c.sweep()
    print(c._store, c._last_visits, c._time_to_keys, c._keys_to_last_time)


def test_init_args():
    # 创建 Cache 时可以指定键值对来进行初始化

    # 错误的用法, 初始化字典被识别为 timeout
    c = LRUCache({'three': 3, 'two': 2})
    print("_store:", c._store)

    # 正确的用法, 用 (iterable, **kwargs) 来初始化 cache 中的内容
    c = LRUCache(30, demo_close_callback, [('two', 2), ('one', 1)], three=3, strs="strTest")
    print("_store:", c._store)
    print (c['three'])


def test():
    c = LRUCache(timeout=0.3)

    c['a'] = 1
    assert c['a'] == 1

    time.sleep(0.5)
    c.sweep()
    assert 'a' not in c

    c['a'] = 2
    c['b'] = 3
    time.sleep(0.2)
    c.sweep()
    assert c['a'] == 2
    assert c['b'] == 3

    time.sleep(0.2)
    c.sweep()
    c['b']
    time.sleep(0.2)
    c.sweep()
    assert 'a' not in c
    assert c['b'] == 3

    time.sleep(0.5)
    c.sweep()
    assert 'a' not in c
    assert 'b' not in c

if __name__ == '__main__':
    test()

    print ('#'*10)
    test_close_callback()

    print ('#'*10)
    test_private_data()

    print ('#'*10)
    test_init_args()
