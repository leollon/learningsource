# -*- coding: utf-8 -*-
"""
    werkzeug.datastructures
    ~~~~~~~~~~~~~~~~~~~~~~~

    这个模块提供带有不可变接口的混入和接口。

    :copyright: 2007 Pallets
    :license: BSD-3-Clause
"""
import codecs
import mimetypes
import re
from copy import deepcopy
from itertools import repeat

from ._compat import BytesIO
from ._compat import collections_abc
from ._compat import integer_types
from ._compat import iteritems
from ._compat import iterkeys
from ._compat import iterlists
from ._compat import itervalues
from ._compat import make_literal_wrapper
from ._compat import PY2
from ._compat import string_types
from ._compat import text_type
from ._compat import to_native
from ._internal import _missing
from .filesystem import get_filesystem_encoding

_locale_delim_re = re.compile(r"[_-]")


def is_immutable(self):
    raise TypeError("%r objects are immutable" % self.__class__.__name__)


def iter_multi_items(mapping):
    """迭代映射的项来生成键和对应的值，而不落下任何来自更复杂结构的项。
    """
    if isinstance(mapping, MultiDict):
        # MultiDict([('a', 'b'), ('a', 'c'), ('a', 'd'), ('h', 'i')])
        for item in iteritems(mapping, multi=True):
            yield item
    elif isinstance(mapping, dict):
        for key, value in iteritems(mapping):
            if isinstance(value, (tuple, list)):
                # {'a': 'b', 'c': 'd', 'h': [1, 2, 3]}
                for value in value:
                    yield key, value
            else:
                # {'a': 'b', 'c': 'd', 'h': 'i'}
                yield key, value
    else:
        # [1, 2, 3, 4]
        # 'adbc'
        # {1, 3, 4}
        for item in mapping:
            yield item


def native_itermethods(names):
    if not PY2:
        return lambda x: x  # 匿名函数

    def setviewmethod(cls, name):
        viewmethod_name = "view%s" % name
        repr_name = "view_%s" % name

        def viewmethod(self, *a, **kw):
            return ViewItems(self, name, repr_name, *a, **kw)

        viewmethod.__name__ = viewmethod_name
        viewmethod.__doc__ = "`%s()` object providing a view on %s" % (
            viewmethod_name,
            name,
        )
        setattr(cls, viewmethod_name, viewmethod)  # 描述器

    def setitermethod(cls, name):
        itermethod = getattr(cls, name)
        setattr(cls, "iter%s" % name, itermethod)

        def listmethod(self, *a, **kw):
            return list(itermethod(self, *a, **kw))

        listmethod.__name__ = name
        listmethod.__doc__ = "Like :py:meth:`iter%s`, but returns a list." % name
        setattr(cls, name, listmethod)  # 描述器

    def wrap(cls):
        for name in names:
            setitermethod(cls, name)
            setviewmethod(cls, name)
        return cls

    return wrap


class ImmutableListMixin(object):
    """使一个:class:`list`成为不可变。

    .. versionadded:: 0.5

    :private:
    """

    _hash_cache = None

    def __hash__(self):
        # 列表可哈希
        if self._hash_cache is not None:
            return self._hash_cache
        rv = self._hash_cache = hash(tuple(self))
        return rv

    def __reduce_ex__(self, protocol):
        return type(self), (list(self),)

    def __delitem__(self, key):
        # 不可删除一个键，抛出类型错误异常
        is_immutable(self)

    def __iadd__(self, other):
        # += 运算符
        # 不可删除一个键，抛出类型错误异常
        is_immutable(self)

    # *= 运算符
    __imul__ = __iadd__

    def __setitem__(self, key, value):
        # d[key] = value
        is_immutable(self)

    def append(self, item):
        # obj.append(item)
        is_immutable(self)

    # 像这样子的调用：obj.remove(ele) => obj.append(ele)
    remove = append

    def extend(self, iterable):
        # 像这样子的调用：obj.extend(iteratable)
        is_immutable(self)

    def insert(self, pos, value):
        # 像这样子的调用：obj.insert(pos, value)
        is_immutable(self)

    def pop(self, index=-1):
        # 像这样子的调用：obj.pop(index)
        is_immutable(self)

    def reverse(self):
        # 像这样子的调用：obj.reverse()
        is_immutable(self)

    def sort(self, cmp=None, key=None, reverse=None):
        # 像这样子的调用：obj.sort(function_returns_boolean, None, None)
        is_immutable(self)


class ImmutableList(ImmutableListMixin, list):
    """一个不可变的 :class:`list`.

    .. versionadded:: 0.5

    :private:
    """

    def __repr__(self):
        return "%s(%s)" % (self.__class__.__name__, list.__repr__(self))


class ImmutableDictMixin(object):
    """使一个 :class:`dict` 不可变。

    .. versionadded:: 0.5

    :private:
    """

    _hash_cache = None

    @classmethod
    def fromkeys(cls, keys, value=None):
        instance = super(cls, cls).__new__(cls)
        instance.__init__(zip(keys, repeat(value)))
        return instance

    def __reduce_ex__(self, protocol):
        return type(self), (dict(self),)

    def _iter_hashitems(self):
        return iteritems(self)

    def __hash__(self):
        # 可哈希
        if self._hash_cache is not None:
            return self._hash_cache
        rv = self._hash_cache = hash(frozenset(self._iter_hashitems()))
        return rv

    def setdefault(self, key, default=None):
        # 像这样子的调用：obj.setdefault(key, Noe)
        is_immutable(self)

    def update(self, *args, **kwargs):
        # 像这样子的调用：obj.update(1, 3, 4, b=4, c=6)
        is_immutable(self)

    def pop(self, key, default=None):
        # 像这样子的调用：obj.pop(key, None)
        is_immutable(self)

    def popitem(self):
        # 像这样子的调用：obj.popitem()
        is_immutable(self)

    def __setitem__(self, key, value):
        # 像这样子的调用：obj[key] = value
        is_immutable(self)

    def __delitem__(self, key):
        # 像这样子的调用：del obj[key]
        is_immutable(self)

    def clear(self):
        # 像这样子的调用：obj.clear()
        is_immutable(self)


class ImmutableMultiDictMixin(ImmutableDictMixin):
    """使一个 :class:`MultiDict` 不可变。

    .. versionadded:: 0.5

    :private:
    """

    def __reduce_ex__(self, protocol):
        # method of builtins.func instance helper for pickle
        return type(self), (list(iteritems(self, multi=True)),)

    def _iter_hashitems(self):
        return iteritems(self, multi=True)

    def add(self, key, value):
        # obj.add(key, value)
        is_immutable(self)

    def popitemlist(self):
        is_immutable(self)

    def poplist(self, key):
        is_immutable(self)

    def setlist(self, key, new_list):
        # obj.setlist(key, new_list)
        is_immutable(self)

    def setlistdefault(self, key, default_list=None):
        # obj.setlistdefault(key, [])
        is_immutable(self)


class UpdateDictMixin(object):
    """调用`self.on_update`来修改字典。

    .. versionadded:: 0.5

    :private:
    """

    on_update = None

    def calls_update(name):  # noqa: B902
        def oncall(self, *args, **kw):
            rv = getattr(super(UpdateDictMixin, self), name)(*args, **kw)
            if self.on_update is not None:
                self.on_update(self)
            return rv

        oncall.__name__ = name  # 更改函数名字
        return oncall

    def setdefault(self, key, default=None):
        # obj.setdefault(key, default_value)
        modified = key not in self
        rv = super(UpdateDictMixin, self).setdefault(key, default)
        if modified and self.on_update is not None:
            # 允许修改并且对象的on_update属性不为None时，更新字典对象
            self.on_update(self)
        return rv

    def pop(self, key, default=_missing):
        # obj.pop(key, None)
        modified = key in self
        if default is _missing:
            rv = super(UpdateDictMixin, self).pop(key)
        else:
            rv = super(UpdateDictMixin, self).pop(key, default)
        if modified and self.on_update is not None:
            self.on_update(self)
        return rv

    __setitem__ = calls_update("__setitem__")
    __delitem__ = calls_update("__delitem__")
    clear = calls_update("clear")
    popitem = calls_update("popitem")
    update = calls_update("update")
    del calls_update


class TypeConversionDict(dict):
    """想普通字典一样工作，但是:meth:`get`方法能够执行类型转换。
    :class:`MultiDict` 和 :class:`CombinedMultiDict`是这个类
    的子类并且提供同样的特性。

    .. versionadded:: 0.5
    """

    def get(self, key, default=None, type=None):
        """如果请求的数据不存在，返回默认值。如果提同`type`并且是可调用的，应该转换并返回这个值，
        或者如果不可能进行转换， 则引起:exc:`ValueError`异常。在这种情况下，这个函数返回默认值
        就好象这个值没有被找到一样：

        >>> d = TypeConversionDict(foo='42', bar='blub')
        >>> d.get('foo', type=int)
        42
        >>> d.get('bar', -1, type=int)  # 键值对存在，但是值不能转换成`int`，因此返回-1
        -1

        :param key: 被查找的key。
        :param default: 如果key不能够被找到，返回的默认值。如果没有进一步的指定，则返回`None`。
        :param type: 一个可用于转换在:class:`MultiDict`中的值的可调用对象。假如调用可调用
                     对象进行转换过程中引起:exc:`ValueError`异常，则返回默认值。
        """
        try:
            rv = self[key]
        except KeyError:
            return default
        if type is not None:
            try:
                rv = type(rv)
            except ValueError:
                rv = default
        return rv


class ImmutableTypeConversionDict(ImmutableDictMixin, TypeConversionDict):
    """像:class:`TypeConversionDict`一样工作，但是不支持修改操作。

    .. versionadded:: 0.5
    """

    def copy(self):
        """返回这个对象的浅拷贝可变拷贝。注意标准库中的:func:`copy`函数对于这个类来说是一个空操作。
        这个类像任何其他python的不可变类型一样（例如： :class:`tuple`）。
        """
        return TypeConversionDict(self)

    def __copy__(self):
        return self


class ViewItems(object):
    def __init__(self, multi_dict, method, repr_name, *a, **kw):
        self.__multi_dict = multi_dict
        self.__method = method
        self.__repr_name = repr_name
        self.__a = a
        self.__kw = kw

    def __get_items(self):
        return getattr(self.__multi_dict, self.__method)(*self.__a, **self.__kw)

    def __repr__(self):
        return "%s(%r)" % (self.__repr_name, list(self.__get_items()))

    def __iter__(self):
        return iter(self.__get_items())


@native_itermethods(["keys", "values", "items", "lists", "listvalues"])  # 设置这类的方法
class MultiDict(TypeConversionDict):
    """:class:`MultiDict`是一个自定义用来处理一个键对应多个值的字典子类，
    举个例子，这个类在包装器中的解析函数中被使用到。因为一些HTML表单元素会给同一个键传递多个值。
    A :class:`MultiDict` is a dictionary subclass customized to deal with
    multiple values for the same key which is for example used by the parsing
    functions in the wrappers.  This is necessary because some HTML form
    elements pass multiple values for the same key.

    :class:`MultiDict`实现了所有的标准字典的方法。本质上，使用列表保存了一个键对应的所有值，但是
    这个标准字典访问方法会只返回一个键的第一个值。如果也想访问其他值，得使用下方描述的`list`方法。

    基本使用:

    >>> d = MultiDict([('a', 'b'), ('a', 'c')])
    >>> d
    MultiDict([('a', 'b'), ('a', 'c')])
    >>> d['a']
    'b'
    >>> d.getlist('a')
    ['b', 'c']
    >>> 'a' in d
    True

    表现的就像一个普通的字典，因此所有的字典函数之返回第一个值，当一个键对应的对个指被找到的时候。
    
    从 Werkzeug 0.3 往前，由这个类引发的`KerError`异常也是:exc:`~exceptions.BadRequest` Http 异常的子类，
    并且如果在HTTP异常的所有捕获中被捕获到，将会渲染一个``400 BAD REQUEST`` 的页面。

    一个 :class:`MultiDict`能够通过包含元组``(key, value)``，字典，一个:class:`MultiDict` 或
    来自 Werkzeug 0.2 之前的一些关键字参数的一个可迭代对象来构造。

    :param mapping: :class:`MultiDict`的初始值。要么是一个普通的字典，一个包含
                    ``(key,value)``元组的可迭代对象或者`None`。
    """

    def __init__(self, mapping=None):
        if isinstance(mapping, MultiDict):
            dict.__init__(self, ((k, l[:]) for k, l in iterlists(mapping)))
        elif isinstance(mapping, dict):
            tmp = {}
            for key, value in iteritems(mapping):
                if isinstance(value, (tuple, list)):
                    if len(value) == 0:
                        continue
                    value = list(value)
                else:
                    value = [value]
                tmp[key] = value
            dict.__init__(self, tmp)
        else:
            tmp = {}
            for key, value in mapping or ():
                tmp.setdefault(key, []).append(value)
            dict.__init__(self, tmp)

    def __getstate__(self):
        return dict(self.lists())

    def __setstate__(self, value):
        dict.clear(self)
        dict.update(self, value)

    def __getitem__(self, key):
        """返回这个键的第一个数据值;如果这个键没有被找到，则引发KeyError异常。

        :param key: 被查询的键。
        :raise KeyError: 如果键不存在。
        """

        if key in self:
            lst = dict.__getitem__(self, key)
            if len(lst) > 0:
                return lst[0]
        raise exceptions.BadRequestKeyError(key)

    def __setitem__(self, key, value):
        """像 :meth:`add` 一样，但是首先移除一个存在的键。

        :param key: 键值对中的的键。
        :param value: 设置键对应的值。
        """
        dict.__setitem__(self, key, [value])

    def add(self, key, value):
        """给这个键添加新的值。

        .. versionadded:: 0.6

        :param key: 键值对中的键。
        :param value: 添加的值。
        """
        dict.setdefault(self, key, []).append(value)

    def getlist(self, key, type=None):
        """返回一个键所有项的列表。如果那个键不在`MultiDict`中，返回的的值将会是空的列表。
        就像`get` `getlist` 接受一个`type` 参数。所有的项都将使用定义在那里的可调用对象
        进行转换。

        :param key: 被查询的键。
        :param type: 用来转换在:class:`MultiDict`中的值的可调用对象。
                     如果这个可调用对象引发异常，这个值将会被从列表中移除。
        :return: 包含键的所有值的一个 :class:`list`。
        """
        try:
            rv = dict.__getitem__(self, key)
        except KeyError:
            return []
        if type is None:
            return list(rv)
        result = []
        for item in rv:
            try:
                result.append(type(item))
            except ValueError:
                pass
        return result

    def setlist(self, key, new_list):
        """移除一个键对应的旧值并添加新的值。注意往列表传递的值在被插入到字典中之前将会是浅拷贝。

        >>> d = MultiDict()
        >>> d.setlist('foo', ['1', '2'])
        >>> d['foo']
        '1'
        >>> d.getlist('foo')
        ['1', '2']

        :param key: 被设置值的键。
        :param new_list: 一个可以用来设置键的新值的可迭代对象。旧的值将首先被移除。
        """
        dict.__setitem__(self, key, list(new_list))

    def setdefault(self, key, default=None):
        """假如这个键在字典中，返回这个键的值，否则返回`default`并且这个这个键的值为`default`。

        :param key: 被查询的键。
        :param default: 如果这个键不存在字典中，返回的默认值。如果没有特别指定，那么返回`None`。
        """
        if key not in self:
            self[key] = default
        else:
            default = self[key]
        return default

    def setlistdefault(self, key, default_list=None):
        """像`default`一样，但是是设置多个值。返回的列表不是一份拷贝，而是内部实际上被使用的列表。
        意味着可以往列表中添加（append）新值来将新的值放入字典中：

        >>> d = MultiDict({"foo": 1})
        >>> d.setlistdefault("foo").extend([2, 3])
        >>> d.getlist("foo")
        [1, 2, 3]

        :param key: 要查询的键。
        :param default_list: 一个默认值的可迭代对象。是可拷贝的（万一是列表的情况）抑或是在返回之前可以转换成一个列表的对象。
        :return: 一个 :class:`list`
        """
        if key not in self:
            default_list = list(default_list or ())
            dict.__setitem__(self, key, default_list)
        else:
            default_list = dict.__getitem__(self, key)
        return default_list

    def items(self, multi=False):
        """返回一个``(key, value)``对的迭代器。

        :param multi: 如果设置为`True`，返回的迭代器会以对的形式包含每个键的每个值。
                      否则将只是包含每个键和每个键第一个值的对。
        """

        for key, values in iteritems(dict, self):
            if multi:
                for value in values:
                    yield key, value
            else:
                yield key, values[0]

    def lists(self):
        """返回一个``(key, values)``对的迭代器。迭代器里的值是关联这个键的所有值的列表。
        """

        for key, values in iteritems(dict, self):
            yield key, list(values)

    def keys(self):
        """返回一个迭代所有键的迭代器。"""
        return iterkeys(dict, self)

    __iter__ = keys

    def values(self):
        """返回迭代每个键的值列表中第一个值的迭代器。"""
        for values in itervalues(dict, self):
            yield values[0]

    def listvalues(self):
        """返回可以迭代所有关联一个键所有值的迭代器。压缩:meth:`keys`并且和调用:meth:`lists`是一样的：

        >>> d = MultiDict({"foo": [1, 2, 3]})
        >>> zip(d.keys(), d.listvalues()) == d.lists()
        True
        """

        return itervalues(dict, self)

    def copy(self):
        """返回这个对象的浅拷贝。"""
        return self.__class__(self)

    def deepcopy(self, memo=None):
        """返回这对象的深拷贝。"""
        return self.__class__(deepcopy(self.to_dict(flat=False), memo))

    def to_dict(self, flat=True):
        """返回`MultiDict`的内容作为普通的字典。如果`flat`为`True`，返回的字典将只有第一项存在，
        如果`flat`为`False`，所有的值放入到列表中被返回。

        :param flat: 如果设置为`False`，返回的字典将会含有所有值的列表在里面。
                     否则，将只包含有每个键的第一个值。
        :return: 一个:class:`dict`
        """
        if flat:
            return dict(iteritems(self))
        return dict(self.lists())

    def update(self, other_dict):
        """更新扩展而不是替换存在的键列表。:

        >>> a = MultiDict({'x': 1})
        >>> b = MultiDict({'x': 2, 'y': 3})
        >>> a.update(b)
        >>> a
        MultiDict([('y', 3), ('x', 1), ('x', 2)])

        如果值列表在``other_dict``中的一个键是空的，没有的新的值会被加入到字典中并且不会创建这个键：

        >>> x = {'empty_list': []}
        >>> y = MultiDict()
        >>> y.update(x)
        >>> y
        MultiDict([])
        """
        for key, value in iter_multi_items(other_dict):
            MultiDict.add(self, key, value)

    def pop(self, key, default=_missing):
        """弹出字典中一个列表中的第一项。之后这个键从字典中被移除，因此，额外的值都会被丢弃：

        >>> d = MultiDict({"foo": [1, 2, 3]})
        >>> d.pop("foo")
        1
        >>> "foo" in d
        False

        :param key: 要弹出的键。
        :param default: 如果提供返回值则返回这个值，假如这个键没在字典中。
        """
        try:
            lst = dict.pop(self, key)

            if len(lst) == 0:
                raise exceptions.BadRequestKeyError(key)

            return lst[0]
        except KeyError:
            if default is not _missing:
                return default
            raise exceptions.BadRequestKeyError(key)

    def popitem(self):
        """Pop an item from the dict."""
        try:
            item = dict.popitem(self)

            if len(item[1]) == 0:
                raise exceptions.BadRequestKeyError(item)

            return (item[0], item[1][0])
        except KeyError as e:
            raise exceptions.BadRequestKeyError(e.args[0])

    def poplist(self, key):
        """从字典中弹出键对应的列表。如果键不在字典中，返回一个空列表。

        .. versionchanged:: 0.5
           如果键不再存在，返回一个列表而不是引发错误异常。
        """
        return dict.pop(self, key, [])

    def popitemlist(self):
        """从字典中弹出一个``(key, list)``元组。"""
        try:
            return dict.popitem(self)
        except KeyError as e:
            raise exceptions.BadRequestKeyError(e.args[0])

    def __copy__(self):
        return self.copy()

    def __deepcopy__(self, memo):
        return self.deepcopy(memo=memo)

    def __repr__(self):
        return "%s(%r)" % (self.__class__.__name__, list(iteritems(self, multi=True)))


class _omd_bucket(object):
    """包装在:class:`OrderMultiDict`中的值。使得多个不同的键可能保持顺序。需要大量的额外内存
    并且严重地减缓访问速度，但是却可能使得能够以O(1)来访问元素并且以O(n)来迭代这些元素。

    这是一个双向链表的数据结构
    """

    __slots__ = ("prev", "key", "value", "next")

    def __init__(self, omd, key, value):
        self.prev = omd._last_bucket
        self.key = key
        self.value = value
        self.next = None

        if omd._first_bucket is None:
            # 空的顺序字典
            omd._first_bucket = self
        if omd._last_bucket is not None:
            # 空的顺序字典
            omd._last_bucket.next = self
        omd._last_bucket = self

    def unlink(self, omd):
        # 断开链表中结点之间的连接
        if self.prev:
            # 将当前节点的前续结点的后续结点的地址指向当前结点的后续结点
            self.prev.next = self.next
        if self.next:
            # 将当前节点的后续结点的前续结点的地址指向当前结点的前续结点
            self.next.prev = self.prev
        if omd._first_bucket is self:
            # 首结点是当前结点，并且只有一个结点了
            omd._first_bucket = self.next  # None
        if omd._last_bucket is self:
            # 尾结点是当前结点，并且只有一个结点了
            omd._last_bucket = self.prev  # None


@native_itermethods(["keys", "values", "items", "lists", "listvalues"])
class OrderedMultiDict(MultiDict):
    """像普通的:class:`MultiDict`一的功能，但是保持字段顺序。为了转换有序的
    multi dict 为一个一个列表，可以使用:meth:`items`方法并且给这个方法传递``multi=True``。

    通常来说，:class:`OrderMultiDict`比起:class:`MultiDict`要慢一个数量级。

    .. admonition:: note

        由于Python中的限制，不能通过使用``dict(multidict)``来讲一个有序的字典转换成普通的字典。
        而是得使用:meth:`to_dict`方法，否则内部的桶对象会被公开出来。
    """

    def __init__(self, mapping=None):
        dict.__init__(self)
        self._first_bucket = self._last_bucket = None
        if mapping is not None:
            OrderedMultiDict.update(self, mapping)

    def __eq__(self, other):
        # 比较两个字典是否相等，dict1 == dict2
        if not isinstance(other, MultiDict):
            # other 不是 MultiDict 的实例。
            return NotImplemented
        if isinstance(other, OrderedMultiDict):
            # self 和 other 都是有序字典
            iter1 = iteritems(self, multi=True)
            iter2 = iteritems(other, multi=True)
            try:
                for k1, v1 in iter1:
                    k2, v2 = next(iter2)
                    if k1 != k2 or v1 != v2:
                        return False
            except StopIteration:
                # iter2率先迭代完
                return False
            try:
                # iter1率先迭代完，检测iter2
                next(iter2)
            except StopIteration:
                # iter1迭代结束的同时，iter2也迭代结束，此时可说明 self 和 other 是相等的
                return True
            return False
        # other 是 MultiDict 的实例。
        if len(self) != len(other):
            return False
        for key, values in iterlists(self):
            # key 可能在 other 字典中，也可能不在，
            # 在的时候，返回key对应的值列表，不再的时候，返回空列表。
            if other.getlist(key) != values:
                # 列表的长度不想等或列表中的值不相等
                return False
        # 有序字典中的键值对和普通字典 other 中的键值对相等
        return True

    __hash__ = None  # 有序字典不可以进行哈希

    def __ne__(self, other):
        return not self.__eq__(other)

    def __reduce_ex__(self, protocol):
        # method of builtins.function instance helper for pickle
        return type(self), (list(iteritems(self, multi=True)),)

    def __getstate__(self):
        return list(iteritems(self, multi=True))

    def __setstate__(self, values):
        dict.clear(self) # 清除有序字典
        for key, value in values:
            # 往有序字典添加键值对
            self.add(key, value)

    def __getitem__(self, key):
        if key in self:
            # 获取链表中key对应的第一个list的omd_bucket对象的值
            return dict.__getitem__(self, key)[0].value
        # 键不存在于字典中
        raise exceptions.BadRequestKeyError(key)

    def __setitem__(self, key, value):
        self.poplist(key)  # 将字典中中键对应的值列表弹出
        self.add(key, value)

    def __delitem__(self, key):
        self.pop(key)

    def keys(self):
        return (key for key, value in iteritems(self))

    __iter__ = keys

    def values(self):
        return (value for key, value in iteritems(self))

    def items(self, multi=False):
        ptr = self._first_bucket
        if multi:
            while ptr is not None:
                yield ptr.key, ptr.value
                ptr = ptr.next
        else:
            returned_keys = set()
            while ptr is not None:
                if ptr.key not in returned_keys:
                    returned_keys.add(ptr.key)
                    yield ptr.key, ptr.value
                ptr = ptr.next

    def lists(self):
        returned_keys = set()
        ptr = self._first_bucket
        while ptr is not None:
            if ptr.key not in returned_keys:
                yield ptr.key, self.getlist(ptr.key)
                returned_keys.add(ptr.key)
            ptr = ptr.next

    def listvalues(self):
        # 生成键对应的值列表
        for _key, values in iterlists(self):
            yield values

    def add(self, key, value):
        # 往链表中添加元素
        dict.setdefault(self, key, []).append(_omd_bucket(self, key, value))

    def getlist(self, key, type=None):
        """获取键对应的值列表
        """
        try:
            rv = dict.__getitem__(self, key)
        except KeyError:
            return []
        if type is None:
            return [x.value for x in rv]
        result = []
        for item in rv:
            try:
                result.append(type(item.value))
            except ValueError:
                pass
        return result

    def setlist(self, key, new_list):
        self.poplist(key)  # 清空字典
        for value in new_list:
            self.add(key, value)

    def setlistdefault(self, key, default_list=None):
        raise TypeError("setlistdefault is unsupported for ordered multi dicts")

    def update(self, mapping):
        """更新字典，往字典中添加新元素"""
        for key, value in iter_multi_items(mapping):
            OrderedMultiDict.add(self, key, value)

    def poplist(self, key):
        """弹出一个键对应的值列表
        
        >>> d = OrderedMultiDict()
        >>> d.add("hello", "world")
        >>> d.add("halov, "world")
        >>> d.add("hello", "hello world")
        >>> d
        OrderedMultiDict([("hello", "world"), ("halo", "world"), ("hello", "hello world")])
        >>> d.poplist("hello")
        ['world', 'hello world']
        >>> d
        OrderedMultiDict([("halo", "world")])
        """
        # TODO: 似乎可以将O(2n) 降到 O(n)呢？
        buckets = dict.pop(self, key, ())
        for bucket in buckets:
            bucket.unlink(self)
        return [x.value for x in buckets]

    def pop(self, key, default=_missing):
        """弹出一个键对应列表中的第一个值，并且删除键对应的所有值。

        >>> d = OrderedMultiDict()
        >>> d
        OrderedMultiDict([])
        >>> d.add("hello", "world")
        >>> d.add("halov, "world")
        >>> d.add("hello", "hello world")
        >>> d
        OrderedMultiDict([("hello", "world"), ("halo", "world"), ("hello", "hello world")])
        >>> d.pop("hello")
        'world'
        >>> d
        OrderedMultiDict([("halo", "world")])
        """
        try:
            buckets = dict.pop(self, key)
        except KeyError:
            if default is not _missing:
                return default
            raise exceptions.BadRequestKeyError(key)
        for bucket in buckets:
            bucket.unlink(self)
        return buckets[0].value

    def popitem(self):
        """弹出键值对，但是只取键对应的值列表的第一个

        >>> d = OrderedMultiDict()
        >>> d
        OrderedMultiDict([])
        >>> d.add('a', 'aa')
        >>> d.add('a', 'bb')
        >>> d.add('b', 'abb')
        >>> d.add('c', 'ccccc')
        >>> d.add('c', 'abc')
        >>> d.add('a', 'world')
        >>> d  # 键按字典进行排序
        OrderedMultiDict([('a', 'aa'), ('a', 'bb'), ('b', 'abb'), ('c', 'ccccc'), ('c', 'abc'), ('a', 'world')])
        >>> d.popitem()
        ('c', 'ccccc')  # 从最大的键pop，然后取键对应的值列表的第一个元素
        >>> d.popitem()
        ('b', 'abb')
        """
        try:
            key, buckets = dict.popitem(self)
        except KeyError as e:
            raise exceptions.BadRequestKeyError(e.args[0])
        for bucket in buckets:
            bucket.unlink(self)
        return key, buckets[0].value

    def popitemlist(self):
        """弹出一个最大键的值列表
        >>> d = OrderedMultiDict()
        >>> d
        OrderedMultiDict([])
        >>> d.add('a', 'aa')
        >>> d.add('a', 'bb')
        >>> d.add('b', 'abb')
        >>> d.add('c', 'ccccc')
        >>> d.add('c', 'abc')
        >>> d.add('a', 'world')
        >>> d  # 键按字典进行排序
        OrderedMultiDict([('a', 'aa'), ('a', 'bb'), ('b', 'abb'), ('c', 'ccccc'), ('c', 'abc'), ('a', 'world')])
        >>> d.popitemlist()
        ('c', ['ccccc', 'abc'])  # 从最大的键pop，然后取键对应的值列表的第一个元素
        >>> d
        OrderedMultiDict([('a', 'aa'), ('a', 'bb'), ('b', 'abb'), ('a', 'world')])
        >>> d.popitemlist()
        ('b', 'abb')
        >>> d
        OrderedMultiDict([('a', 'aa'), ('a', 'bb'), ('a', 'world')])
        """
        try:
            key, buckets = dict.popitem(self)
        except KeyError as e:
            raise exceptions.BadRequestKeyError(e.args[0])
        for bucket in buckets:
            bucket.unlink(self)
        return key, [x.value for x in buckets]


def _options_header_vkw(value, kw):
    """
    >>> _options_header_vkw('attachment', filename='foo.png')
    'attachment; filename=foo.png'
    """
    return dump_options_header(
        value, dict((k.replace("_", "-"), v) for k, v in kw.items())
    )


def _unicodify_header_value(value):
    """
    >>> _unicodify_header_value(b'hello')
    'hello'

    >>> _unicodify_header_value(1234)
    '1234'
    """
    if isinstance(value, bytes):
        value = value.decode("latin-1")
    if not isinstance(value, text_type):
        # value = str(value)
        value = text_type(value)
    return value


@native_itermethods(["keys", "values", "items"])
class Headers(object):
    """存储一些头部的一个对象。这个对象有一个类似字典的接口，但是是被排好序的并且能够多次存储相同的键。
    
    An object that stores some headers.  It has a dict-like interface
    but is ordered and can store the same keys multiple times.

    这个数据结构非常有用，如果想要一种更好的方式来处理作为元组存储在一个列表中的WSGI头部。

    从Werkzeug 0.3 往前，有这类引起的:exc:`KeyError`异常也是一个:class:`~exceptions.BadRequest` HTTP 异常的子类，
    并且如果在所有的HTTP异常捕获中被捕获，则会渲染一个``400 BAD REQUEST``的页面出来。
    

    Headers大部分与Python :class:`wsgiref.headers.Headers`类相兼容，除了`__getitem__`之外。
    :mod:`wsgiref`当``headers['missing`]``时，返回`None`，然而:class:`Headers`会引起
    :class:`KeyError`异常。

    为了创建一个新的:class:`Headers`对象，给它传一个用来作为默认值的头部列表或字典。
    这不会重用传递给构造函数以供内部使用的列表。
    

    :param defaults: 传递给:class:`Headers`的默认值列表。

    .. versionchanged:: 0.9
        这个数据结构存储unicode值的方式类似于multi dict处理它的方式。
        主要的不同点是字节数据也能够被设置，它能够自动地被 lating1 解码。

    .. versionchanged:: 0.9
        :meth:`linked`函数无可替代地被移除了，因为它是一个不支持改变编码模型的的API。
    """

    def __init__(self, defaults=None):
        self._list = []
        if defaults is not None:
            if isinstance(defaults, (list, Headers)):
                self._list.extend(defaults)
            else:
                self.extend(defaults)

    def __getitem__(self, key, _get_mode=False):
        if not _get_mode:
            if isinstance(key, integer_types):
                return self._list[key]
            elif isinstance(key, slice):
                return self.__class__(self._list[key])
        if not isinstance(key, string_types):
            raise exceptions.BadRequestKeyError(key)
        ikey = key.lower()
        for k, v in self._list:
            if k.lower() == ikey:
                return v
        # 小小的优化：如果处在get模式中，这将会捕获一个堆栈层级的异常，
        # 因此可以引起一个标准的异常而不是特殊的异常。
        if _get_mode:
            raise KeyError()
        raise exceptions.BadRequestKeyError(key)

    def __eq__(self, other):
        return other.__class__ is self.__class__ and set(other._list) == set(self._list)

    __hash__ = None

    def __ne__(self, other):
        return not self.__eq__(other)

    def get(self, key, default=None, type=None, as_bytes=False):
        """如果请求的数据不存在，返回默认值。如果提供`type`，并且是一个可调用对象，那么应该是转换这个值，
        并返回它或者假设不能进行转换时，则引起:exc:`ValueError`异常。在这个例子中，这个函数将返回默认值，
        就好像这个值没有被找到一样：

        >>> d = Headers([('Content-Length', '42')])
        >>> d.get('Content-Length', type=int)
        42

        如果一个头部对象被绑定，则禁止添加unicode字符串，因为不会进行编码。

        .. versionadded:: 0.9
            添加`as_bytes`支持。

        :param key: 被查询的键。
        :param default: 键不能被找到时返回的默认值。如果没有特别指定，则返回`None`。
        :param type: 用来在:class:`Headers`中转换值类型的可调用对象。
                     如果这个可调用对象引起:exc:`ValueError`异常，则返回默认值。
        :param as_bytes: 返回字节数据而不是unicode字符串。
        """
        try:
            rv = self.__getitem__(key, _get_mode=True)
        except KeyError:
            return default
        if as_bytes:
            rv = rv.encode("latin1")
        if type is None:
            return rv
        try:
            return type(rv)
        except ValueError:
            return default

    def getlist(self, key, type=None, as_bytes=False):
        """返回一个键的值列表。如果这个键不在:class:`Headers`中，返回值将会是一个空列表。
        就像:meth:`get`一样，:meth:`getlist`接受一个`type`参数。所有放入返回列表中的值
        将使用这个可调用对象来转换。

        .. versionadded:: 0.9
           添加`as_bytes`支持。

        :param key: 被查询的键。
        :param type: 用来转换存储在:class:`Headers`对象中的值的可调用对象。
                     如果这个可调用对象引起:exc:`ValueError`异常，这个值将
                     不会放入返回的列表中。
        :return: 键对应的所有的值的列表。
        :param as_bytes: 返回字节数据而不是unicode字符串。
        """
        ikey = key.lower()
        result = []
        for k, v in self:
            if k.lower() == ikey:
                if as_bytes:
                    v = v.encode("latin1")
                if type is not None:
                    try:
                        v = type(v)
                    except ValueError:
                        continue
                result.append(v)
        return result

    def get_all(self, name):
        """返回命名字段的所有值的一个列表。

        这个方法与 :mod:`wsgiref` 的 :meth:`~wsgiref.headers.Headers.get_all` 方法相兼容。
        """
        return self.getlist(name)

    def items(self, lower=False):
        for key, value in self:
            if lower:
                key = key.lower()
            yield key, value

    def keys(self, lower=False):
        """生成Hearder对象中所有的键
        """
        for key, _ in iteritems(self, lower):
            yield key

    def values(self):
        """生成Hearder对象中所有的值
        """
        for _, value in iteritems(self):
            yield value

    def extend(self, iterable):
        """使用一个字典或可生成键和值的可迭代对象来扩充头部对象。
        """
        if isinstance(iterable, dict):
            for key, value in iteritems(iterable):
                if isinstance(value, (tuple, list)):
                    for v in value:
                        self.add(key, v)
                else:
                    self.add(key, value)
        else:
            for key, value in iterable:
                self.add(key, value)

    def __delitem__(self, key, _index_operation=True):
        if _index_operation and isinstance(key, (integer_types, slice)):
            del self._list[key]
            return
        key = key.lower()
        new = []
        for k, v in self._list:
            if k.lower() != key:
                new.append((k, v))
        self._list[:] = new

    def remove(self, key):
        """Remove a key.

        :param key: The key to be removed.
        """
        return self.__delitem__(key, _index_operation=False)

    def pop(self, key=None, default=_missing):
        """Removes and returns a key or index.

        :param key: The key to be popped.  If this is an integer the item at
                    that position is removed, if it's a string the value for
                    that key is.  If the key is omitted or `None` the last
                    item is removed.
        :return: an item.
        """
        if key is None:
            return self._list.pop()
        if isinstance(key, integer_types):
            return self._list.pop(key)
        try:
            rv = self[key]
            self.remove(key)
        except KeyError:
            if default is not _missing:
                return default
            raise
        return rv

    def popitem(self):
        """Removes a key or index and returns a (key, value) item."""
        return self.pop()

    def __contains__(self, key):
        """Check if a key is present."""
        try:
            self.__getitem__(key, _get_mode=True)
        except KeyError:
            return False
        return True

    has_key = __contains__

    def __iter__(self):
        """Yield ``(key, value)`` tuples."""
        return iter(self._list)

    def __len__(self):
        return len(self._list)

    def add(self, _key, _value, **kw):
        """Add a new header tuple to the list.

        Keyword arguments can specify additional parameters for the header
        value, with underscores converted to dashes::

        >>> d = Headers()
        >>> d.add('Content-Type', 'text/plain')
        >>> d.add('Content-Disposition', 'attachment', filename='foo.png')

        The keyword argument dumping uses :func:`dump_options_header`
        behind the scenes.

        .. versionadded:: 0.4.1
            keyword arguments were added for :mod:`wsgiref` compatibility.
        """
        if kw:
            _value = _options_header_vkw(_value, kw)
        _key = _unicodify_header_value(_key)
        _value = _unicodify_header_value(_value)
        self._validate_value(_value)
        self._list.append((_key, _value))

    def _validate_value(self, value):
        if not isinstance(value, text_type):
            raise TypeError("Value should be unicode.")
        if u"\n" in value or u"\r" in value:
            raise ValueError(
                "Detected newline in header value.  This is "
                "a potential security problem"
            )

    def add_header(self, _key, _value, **_kw):
        """Add a new header tuple to the list.

        An alias for :meth:`add` for compatibility with the :mod:`wsgiref`
        :meth:`~wsgiref.headers.Headers.add_header` method.
        """
        self.add(_key, _value, **_kw)

    def clear(self):
        """Clears all headers."""
        del self._list[:]

    def set(self, _key, _value, **kw):
        """Remove all header tuples for `key` and add a new one.  The newly
        added key either appears at the end of the list if there was no
        entry or replaces the first one.

        Keyword arguments can specify additional parameters for the header
        value, with underscores converted to dashes.  See :meth:`add` for
        more information.

        .. versionchanged:: 0.6.1
           :meth:`set` now accepts the same arguments as :meth:`add`.

        :param key: The key to be inserted.
        :param value: The value to be inserted.
        """
        if kw:
            _value = _options_header_vkw(_value, kw)
        _key = _unicodify_header_value(_key)
        _value = _unicodify_header_value(_value)
        self._validate_value(_value)
        if not self._list:
            self._list.append((_key, _value))
            return
        listiter = iter(self._list)
        ikey = _key.lower()
        for idx, (old_key, _old_value) in enumerate(listiter):
            if old_key.lower() == ikey:
                # replace first ocurrence
                self._list[idx] = (_key, _value)
                break
        else:
            self._list.append((_key, _value))
            return
        self._list[idx + 1 :] = [t for t in listiter if t[0].lower() != ikey]

    def setdefault(self, key, default):
        """Returns the value for the key if it is in the dict, otherwise it
        returns `default` and sets that value for `key`.

        :param key: The key to be looked up.
        :param default: The default value to be returned if the key is not
                        in the dict.  If not further specified it's `None`.
        """
        if key in self:
            return self[key]
        self.set(key, default)
        return default

    def __setitem__(self, key, value):
        """Like :meth:`set` but also supports index/slice based setting."""
        if isinstance(key, (slice, integer_types)):
            if isinstance(key, integer_types):
                value = [value]
            value = [
                (_unicodify_header_value(k), _unicodify_header_value(v))
                for (k, v) in value
            ]
            [self._validate_value(v) for (k, v) in value]
            if isinstance(key, integer_types):
                self._list[key] = value[0]
            else:
                self._list[key] = value
        else:
            self.set(key, value)

    def to_wsgi_list(self):
        """Convert the headers into a list suitable for WSGI.

        The values are byte strings in Python 2 converted to latin1 and unicode
        strings in Python 3 for the WSGI server to encode.

        :return: list
        """
        if PY2:
            return [(to_native(k), v.encode("latin1")) for k, v in self]
        return list(self)

    def copy(self):
        return self.__class__(self._list)

    def __copy__(self):
        return self.copy()

    def __str__(self):
        """Returns formatted headers suitable for HTTP transmission."""
        strs = []
        for key, value in self.to_wsgi_list():
            strs.append("%s: %s" % (key, value))
        strs.append("\r\n")
        return "\r\n".join(strs)

    def __repr__(self):
        return "%s(%r)" % (self.__class__.__name__, list(self))


class ImmutableHeadersMixin(object):
    """Makes a :class:`Headers` immutable.  We do not mark them as
    hashable though since the only usecase for this datastructure
    in Werkzeug is a view on a mutable structure.

    .. versionadded:: 0.5

    :private:
    """

    def __delitem__(self, key, **kwargs):
        is_immutable(self)

    def __setitem__(self, key, value):
        is_immutable(self)

    set = __setitem__

    def add(self, item):
        is_immutable(self)

    remove = add_header = add

    def extend(self, iterable):
        is_immutable(self)

    def insert(self, pos, value):
        is_immutable(self)

    def pop(self, index=-1):
        is_immutable(self)

    def popitem(self):
        is_immutable(self)

    def setdefault(self, key, default):
        is_immutable(self)


class EnvironHeaders(ImmutableHeadersMixin, Headers):
    """Read only version of the headers from a WSGI environment.  This
    provides the same interface as `Headers` and is constructed from
    a WSGI environment.

    From Werkzeug 0.3 onwards, the `KeyError` raised by this class is also a
    subclass of the :exc:`~exceptions.BadRequest` HTTP exception and will
    render a page for a ``400 BAD REQUEST`` if caught in a catch-all for
    HTTP exceptions.
    """

    def __init__(self, environ):
        self.environ = environ

    def __eq__(self, other):
        return self.environ is other.environ

    __hash__ = None

    def __getitem__(self, key, _get_mode=False):
        # _get_mode is a no-op for this class as there is no index but
        # used because get() calls it.
        if not isinstance(key, string_types):
            raise KeyError(key)
        key = key.upper().replace("-", "_")
        if key in ("CONTENT_TYPE", "CONTENT_LENGTH"):
            return _unicodify_header_value(self.environ[key])
        return _unicodify_header_value(self.environ["HTTP_" + key])

    def __len__(self):
        # the iter is necessary because otherwise list calls our
        # len which would call list again and so forth.
        return len(list(iter(self)))

    def __iter__(self):
        for key, value in iteritems(self.environ):
            if key.startswith("HTTP_") and key not in (
                "HTTP_CONTENT_TYPE",
                "HTTP_CONTENT_LENGTH",
            ):
                yield (
                    key[5:].replace("_", "-").title(),
                    _unicodify_header_value(value),
                )
            elif key in ("CONTENT_TYPE", "CONTENT_LENGTH") and value:
                yield (key.replace("_", "-").title(), _unicodify_header_value(value))

    def copy(self):
        raise TypeError("cannot create %r copies" % self.__class__.__name__)


@native_itermethods(["keys", "values", "items", "lists", "listvalues"])
class CombinedMultiDict(ImmutableMultiDictMixin, MultiDict):
    """A read only :class:`MultiDict` that you can pass multiple :class:`MultiDict`
    instances as sequence and it will combine the return values of all wrapped
    dicts:

    >>> from werkzeug.datastructures import CombinedMultiDict, MultiDict
    >>> post = MultiDict([('foo', 'bar')])
    >>> get = MultiDict([('blub', 'blah')])
    >>> combined = CombinedMultiDict([get, post])
    >>> combined['foo']
    'bar'
    >>> combined['blub']
    'blah'

    This works for all read operations and will raise a `TypeError` for
    methods that usually change data which isn't possible.

    From Werkzeug 0.3 onwards, the `KeyError` raised by this class is also a
    subclass of the :exc:`~exceptions.BadRequest` HTTP exception and will
    render a page for a ``400 BAD REQUEST`` if caught in a catch-all for HTTP
    exceptions.
    """

    def __reduce_ex__(self, protocol):
        return type(self), (self.dicts,)

    def __init__(self, dicts=None):
        self.dicts = dicts or []

    @classmethod
    def fromkeys(cls):
        raise TypeError("cannot create %r instances by fromkeys" % cls.__name__)

    def __getitem__(self, key):
        for d in self.dicts:
            if key in d:
                return d[key]
        raise exceptions.BadRequestKeyError(key)

    def get(self, key, default=None, type=None):
        for d in self.dicts:
            if key in d:
                if type is not None:
                    try:
                        return type(d[key])
                    except ValueError:
                        continue
                return d[key]
        return default

    def getlist(self, key, type=None):
        rv = []
        for d in self.dicts:
            rv.extend(d.getlist(key, type))
        return rv

    def _keys_impl(self):
        """This function exists so __len__ can be implemented more efficiently,
        saving one list creation from an iterator.

        Using this for Python 2's ``dict.keys`` behavior would be useless since
        `dict.keys` in Python 2 returns a list, while we have a set here.
        """
        rv = set()
        for d in self.dicts:
            rv.update(iterkeys(d))
        return rv

    def keys(self):
        return iter(self._keys_impl())

    __iter__ = keys

    def items(self, multi=False):
        found = set()
        for d in self.dicts:
            for key, value in iteritems(d, multi):
                if multi:
                    yield key, value
                elif key not in found:
                    found.add(key)
                    yield key, value

    def values(self):
        for _key, value in iteritems(self):
            yield value

    def lists(self):
        rv = {}
        for d in self.dicts:
            for key, values in iterlists(d):
                rv.setdefault(key, []).extend(values)
        return iteritems(rv)

    def listvalues(self):
        return (x[1] for x in self.lists())

    def copy(self):
        """Return a shallow mutable copy of this object.

        This returns a :class:`MultiDict` representing the data at the
        time of copying. The copy will no longer reflect changes to the
        wrapped dicts.

        .. versionchanged:: 0.15
            Return a mutable :class:`MultiDict`.
        """
        return MultiDict(self)

    def to_dict(self, flat=True):
        """Return the contents as regular dict.  If `flat` is `True` the
        returned dict will only have the first item present, if `flat` is
        `False` all values will be returned as lists.

        :param flat: If set to `False` the dict returned will have lists
                     with all the values in it.  Otherwise it will only
                     contain the first item for each key.
        :return: a :class:`dict`
        """
        rv = {}
        for d in reversed(self.dicts):
            rv.update(d.to_dict(flat))
        return rv

    def __len__(self):
        return len(self._keys_impl())

    def __contains__(self, key):
        for d in self.dicts:
            if key in d:
                return True
        return False

    has_key = __contains__

    def __repr__(self):
        return "%s(%r)" % (self.__class__.__name__, self.dicts)


class FileMultiDict(MultiDict):
    """A special :class:`MultiDict` that has convenience methods to add
    files to it.  This is used for :class:`EnvironBuilder` and generally
    useful for unittesting.

    .. versionadded:: 0.5
    """

    def add_file(self, name, file, filename=None, content_type=None):
        """Adds a new file to the dict.  `file` can be a file name or
        a :class:`file`-like or a :class:`FileStorage` object.

        :param name: the name of the field.
        :param file: a filename or :class:`file`-like object
        :param filename: an optional filename
        :param content_type: an optional content type
        """
        if isinstance(file, FileStorage):
            value = file
        else:
            if isinstance(file, string_types):
                if filename is None:
                    filename = file
                file = open(file, "rb")
            if filename and content_type is None:
                content_type = (
                    mimetypes.guess_type(filename)[0] or "application/octet-stream"
                )
            value = FileStorage(file, filename, name, content_type)

        self.add(name, value)


class ImmutableDict(ImmutableDictMixin, dict):
    """An immutable :class:`dict`.

    .. versionadded:: 0.5
    """

    def __repr__(self):
        return "%s(%s)" % (self.__class__.__name__, dict.__repr__(self))

    def copy(self):
        """Return a shallow mutable copy of this object.  Keep in mind that
        the standard library's :func:`copy` function is a no-op for this class
        like for any other python immutable type (eg: :class:`tuple`).
        """
        return dict(self)

    def __copy__(self):
        return self


class ImmutableMultiDict(ImmutableMultiDictMixin, MultiDict):
    """An immutable :class:`MultiDict`.

    .. versionadded:: 0.5
    """

    def copy(self):
        """Return a shallow mutable copy of this object.  Keep in mind that
        the standard library's :func:`copy` function is a no-op for this class
        like for any other python immutable type (eg: :class:`tuple`).
        """
        return MultiDict(self)

    def __copy__(self):
        return self


class ImmutableOrderedMultiDict(ImmutableMultiDictMixin, OrderedMultiDict):
    """An immutable :class:`OrderedMultiDict`.

    .. versionadded:: 0.6
    """

    def _iter_hashitems(self):
        return enumerate(iteritems(self, multi=True))

    def copy(self):
        """Return a shallow mutable copy of this object.  Keep in mind that
        the standard library's :func:`copy` function is a no-op for this class
        like for any other python immutable type (eg: :class:`tuple`).
        """
        return OrderedMultiDict(self)

    def __copy__(self):
        return self


@native_itermethods(["values"])
class Accept(ImmutableList):
    """An :class:`Accept` object is just a list subclass for lists of
    ``(value, quality)`` tuples.  It is automatically sorted by specificity
    and quality.

    All :class:`Accept` objects work similar to a list but provide extra
    functionality for working with the data.  Containment checks are
    normalized to the rules of that header:

    >>> a = CharsetAccept([('ISO-8859-1', 1), ('utf-8', 0.7)])
    >>> a.best
    'ISO-8859-1'
    >>> 'iso-8859-1' in a
    True
    >>> 'UTF8' in a
    True
    >>> 'utf7' in a
    False

    To get the quality for an item you can use normal item lookup:

    >>> print a['utf-8']
    0.7
    >>> a['utf7']
    0

    .. versionchanged:: 0.5
       :class:`Accept` objects are forced immutable now.
    """

    def __init__(self, values=()):
        if values is None:
            list.__init__(self)
            self.provided = False
        elif isinstance(values, Accept):
            self.provided = values.provided
            list.__init__(self, values)
        else:
            self.provided = True
            values = sorted(
                values,
                key=lambda x: (self._specificity(x[0]), x[1], x[0]),
                reverse=True,
            )
            list.__init__(self, values)

    def _specificity(self, value):
        """Returns a tuple describing the value's specificity."""
        return (value != "*",)

    def _value_matches(self, value, item):
        """Check if a value matches a given accept item."""
        return item == "*" or item.lower() == value.lower()

    def __getitem__(self, key):
        """Besides index lookup (getting item n) you can also pass it a string
        to get the quality for the item.  If the item is not in the list, the
        returned quality is ``0``.
        """
        if isinstance(key, string_types):
            return self.quality(key)
        return list.__getitem__(self, key)

    def quality(self, key):
        """Returns the quality of the key.

        .. versionadded:: 0.6
           In previous versions you had to use the item-lookup syntax
           (eg: ``obj[key]`` instead of ``obj.quality(key)``)
        """
        for item, quality in self:
            if self._value_matches(key, item):
                return quality
        return 0

    def __contains__(self, value):
        for item, _quality in self:
            if self._value_matches(value, item):
                return True
        return False

    def __repr__(self):
        return "%s([%s])" % (
            self.__class__.__name__,
            ", ".join("(%r, %s)" % (x, y) for x, y in self),
        )

    def index(self, key):
        """Get the position of an entry or raise :exc:`ValueError`.

        :param key: The key to be looked up.

        .. versionchanged:: 0.5
           This used to raise :exc:`IndexError`, which was inconsistent
           with the list API.
        """
        if isinstance(key, string_types):
            for idx, (item, _quality) in enumerate(self):
                if self._value_matches(key, item):
                    return idx
            raise ValueError(key)
        return list.index(self, key)

    def find(self, key):
        """Get the position of an entry or return -1.

        :param key: The key to be looked up.
        """
        try:
            return self.index(key)
        except ValueError:
            return -1

    def values(self):
        """Iterate over all values."""
        for item in self:
            yield item[0]

    def to_header(self):
        """Convert the header set into an HTTP header string."""
        result = []
        for value, quality in self:
            if quality != 1:
                value = "%s;q=%s" % (value, quality)
            result.append(value)
        return ",".join(result)

    def __str__(self):
        return self.to_header()

    def _best_single_match(self, match):
        for client_item, quality in self:
            if self._value_matches(match, client_item):
                # self is sorted by specificity descending, we can exit
                return client_item, quality

    def best_match(self, matches, default=None):
        """Returns the best match from a list of possible matches based
        on the specificity and quality of the client. If two items have the
        same quality and specificity, the one is returned that comes first.

        :param matches: a list of matches to check for
        :param default: the value that is returned if none match
        """
        result = default
        best_quality = -1
        best_specificity = (-1,)
        for server_item in matches:
            match = self._best_single_match(server_item)
            if not match:
                continue
            client_item, quality = match
            specificity = self._specificity(client_item)
            if quality <= 0 or quality < best_quality:
                continue
            # better quality or same quality but more specific => better match
            if quality > best_quality or specificity > best_specificity:
                result = server_item
                best_quality = quality
                best_specificity = specificity
        return result

    @property
    def best(self):
        """The best match as value."""
        if self:
            return self[0][0]


class MIMEAccept(Accept):
    """Like :class:`Accept` but with special methods and behavior for
    mimetypes.
    """

    def _specificity(self, value):
        return tuple(x != "*" for x in value.split("/", 1))

    def _value_matches(self, value, item):
        def _normalize(x):
            x = x.lower()
            return ("*", "*") if x == "*" else x.split("/", 1)

        # this is from the application which is trusted.  to avoid developer
        # frustration we actually check these for valid values
        if "/" not in value:
            raise ValueError("invalid mimetype %r" % value)
        value_type, value_subtype = _normalize(value)
        if value_type == "*" and value_subtype != "*":
            raise ValueError("invalid mimetype %r" % value)

        if "/" not in item:
            return False
        item_type, item_subtype = _normalize(item)
        if item_type == "*" and item_subtype != "*":
            return False
        return (
            item_type == item_subtype == "*" or value_type == value_subtype == "*"
        ) or (
            item_type == value_type
            and (
                item_subtype == "*"
                or value_subtype == "*"
                or item_subtype == value_subtype
            )
        )

    @property
    def accept_html(self):
        """True if this object accepts HTML."""
        return (
            "text/html" in self or "application/xhtml+xml" in self or self.accept_xhtml
        )

    @property
    def accept_xhtml(self):
        """True if this object accepts XHTML."""
        return "application/xhtml+xml" in self or "application/xml" in self

    @property
    def accept_json(self):
        """True if this object accepts JSON."""
        return "application/json" in self


class LanguageAccept(Accept):
    """Like :class:`Accept` but with normalization for languages."""

    def _value_matches(self, value, item):
        def _normalize(language):
            return _locale_delim_re.split(language.lower())

        return item == "*" or _normalize(value) == _normalize(item)


class CharsetAccept(Accept):
    """Like :class:`Accept` but with normalization for charsets."""

    def _value_matches(self, value, item):
        def _normalize(name):
            try:
                return codecs.lookup(name).name
            except LookupError:
                return name.lower()

        return item == "*" or _normalize(value) == _normalize(item)


def cache_property(key, empty, type):
    """Return a new property object for a cache header.  Useful if you
    want to add support for a cache extension in a subclass."""
    return property(
        lambda x: x._get_cache_value(key, empty, type),
        lambda x, v: x._set_cache_value(key, v, type),
        lambda x: x._del_cache_value(key),
        "accessor for %r" % key,
    )


class _CacheControl(UpdateDictMixin, dict):
    """Subclass of a dict that stores values for a Cache-Control header.  It
    has accessors for all the cache-control directives specified in RFC 2616.
    The class does not differentiate between request and response directives.

    Because the cache-control directives in the HTTP header use dashes the
    python descriptors use underscores for that.

    To get a header of the :class:`CacheControl` object again you can convert
    the object into a string or call the :meth:`to_header` method.  If you plan
    to subclass it and add your own items have a look at the sourcecode for
    that class.

    .. versionchanged:: 0.4

       Setting `no_cache` or `private` to boolean `True` will set the implicit
       none-value which is ``*``:

       >>> cc = ResponseCacheControl()
       >>> cc.no_cache = True
       >>> cc
       <ResponseCacheControl 'no-cache'>
       >>> cc.no_cache
       '*'
       >>> cc.no_cache = None
       >>> cc
       <ResponseCacheControl ''>

       In versions before 0.5 the behavior documented here affected the now
       no longer existing `CacheControl` class.
    """

    no_cache = cache_property("no-cache", "*", None)
    no_store = cache_property("no-store", None, bool)
    max_age = cache_property("max-age", -1, int)
    no_transform = cache_property("no-transform", None, None)

    def __init__(self, values=(), on_update=None):
        dict.__init__(self, values or ())
        self.on_update = on_update
        self.provided = values is not None

    def _get_cache_value(self, key, empty, type):
        """Used internally by the accessor properties."""
        if type is bool:
            return key in self
        if key in self:
            value = self[key]
            if value is None:
                return empty
            elif type is not None:
                try:
                    value = type(value)
                except ValueError:
                    pass
            return value

    def _set_cache_value(self, key, value, type):
        """Used internally by the accessor properties."""
        if type is bool:
            if value:
                self[key] = None
            else:
                self.pop(key, None)
        else:
            if value is None:
                self.pop(key)
            elif value is True:
                self[key] = None
            else:
                self[key] = value

    def _del_cache_value(self, key):
        """Used internally by the accessor properties."""
        if key in self:
            del self[key]

    def to_header(self):
        """Convert the stored values into a cache control header."""
        return dump_header(self)

    def __str__(self):
        return self.to_header()

    def __repr__(self):
        return "<%s %s>" % (
            self.__class__.__name__,
            " ".join("%s=%r" % (k, v) for k, v in sorted(self.items())),
        )


class RequestCacheControl(ImmutableDictMixin, _CacheControl):
    """A cache control for requests.  This is immutable and gives access
    to all the request-relevant cache control headers.

    To get a header of the :class:`RequestCacheControl` object again you can
    convert the object into a string or call the :meth:`to_header` method.  If
    you plan to subclass it and add your own items have a look at the sourcecode
    for that class.

    .. versionadded:: 0.5
       In previous versions a `CacheControl` class existed that was used
       both for request and response.
    """

    max_stale = cache_property("max-stale", "*", int)
    min_fresh = cache_property("min-fresh", "*", int)
    no_transform = cache_property("no-transform", None, None)
    only_if_cached = cache_property("only-if-cached", None, bool)


class ResponseCacheControl(_CacheControl):
    """A cache control for responses.  Unlike :class:`RequestCacheControl`
    this is mutable and gives access to response-relevant cache control
    headers.

    To get a header of the :class:`ResponseCacheControl` object again you can
    convert the object into a string or call the :meth:`to_header` method.  If
    you plan to subclass it and add your own items have a look at the sourcecode
    for that class.

    .. versionadded:: 0.5
       In previous versions a `CacheControl` class existed that was used
       both for request and response.
    """

    public = cache_property("public", None, bool)
    private = cache_property("private", "*", None)
    must_revalidate = cache_property("must-revalidate", None, bool)
    proxy_revalidate = cache_property("proxy-revalidate", None, bool)
    s_maxage = cache_property("s-maxage", None, None)


# attach cache_property to the _CacheControl as staticmethod
# so that others can reuse it.
_CacheControl.cache_property = staticmethod(cache_property)


class CallbackDict(UpdateDictMixin, dict):
    """A dict that calls a function passed every time something is changed.
    The function is passed the dict instance.
    """

    def __init__(self, initial=None, on_update=None):
        dict.__init__(self, initial or ())
        self.on_update = on_update

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, dict.__repr__(self))


class HeaderSet(collections_abc.MutableSet):
    """Similar to the :class:`ETags` class this implements a set-like structure.
    Unlike :class:`ETags` this is case insensitive and used for vary, allow, and
    content-language headers.

    If not constructed using the :func:`parse_set_header` function the
    instantiation works like this:

    >>> hs = HeaderSet(['foo', 'bar', 'baz'])
    >>> hs
    HeaderSet(['foo', 'bar', 'baz'])
    """

    def __init__(self, headers=None, on_update=None):
        self._headers = list(headers or ())
        self._set = set([x.lower() for x in self._headers])
        self.on_update = on_update

    def add(self, header):
        """Add a new header to the set."""
        self.update((header,))

    def remove(self, header):
        """Remove a header from the set.  This raises an :exc:`KeyError` if the
        header is not in the set.

        .. versionchanged:: 0.5
            In older versions a :exc:`IndexError` was raised instead of a
            :exc:`KeyError` if the object was missing.

        :param header: the header to be removed.
        """
        key = header.lower()
        if key not in self._set:
            raise KeyError(header)
        self._set.remove(key)
        for idx, key in enumerate(self._headers):
            if key.lower() == header:
                del self._headers[idx]
                break
        if self.on_update is not None:
            self.on_update(self)

    def update(self, iterable):
        """Add all the headers from the iterable to the set.

        :param iterable: updates the set with the items from the iterable.
        """
        inserted_any = False
        for header in iterable:
            key = header.lower()
            if key not in self._set:
                self._headers.append(header)
                self._set.add(key)
                inserted_any = True
        if inserted_any and self.on_update is not None:
            self.on_update(self)

    def discard(self, header):
        """Like :meth:`remove` but ignores errors.

        :param header: the header to be discarded.
        """
        try:
            return self.remove(header)
        except KeyError:
            pass

    def find(self, header):
        """Return the index of the header in the set or return -1 if not found.

        :param header: the header to be looked up.
        """
        header = header.lower()
        for idx, item in enumerate(self._headers):
            if item.lower() == header:
                return idx
        return -1

    def index(self, header):
        """Return the index of the header in the set or raise an
        :exc:`IndexError`.

        :param header: the header to be looked up.
        """
        rv = self.find(header)
        if rv < 0:
            raise IndexError(header)
        return rv

    def clear(self):
        """Clear the set."""
        self._set.clear()
        del self._headers[:]
        if self.on_update is not None:
            self.on_update(self)

    def as_set(self, preserve_casing=False):
        """Return the set as real python set type.  When calling this, all
        the items are converted to lowercase and the ordering is lost.

        :param preserve_casing: if set to `True` the items in the set returned
                                will have the original case like in the
                                :class:`HeaderSet`, otherwise they will
                                be lowercase.
        """
        if preserve_casing:
            return set(self._headers)
        return set(self._set)

    def to_header(self):
        """Convert the header set into an HTTP header string."""
        return ", ".join(map(quote_header_value, self._headers))

    def __getitem__(self, idx):
        return self._headers[idx]

    def __delitem__(self, idx):
        rv = self._headers.pop(idx)
        self._set.remove(rv.lower())
        if self.on_update is not None:
            self.on_update(self)

    def __setitem__(self, idx, value):
        old = self._headers[idx]
        self._set.remove(old.lower())
        self._headers[idx] = value
        self._set.add(value.lower())
        if self.on_update is not None:
            self.on_update(self)

    def __contains__(self, header):
        return header.lower() in self._set

    def __len__(self):
        return len(self._set)

    def __iter__(self):
        return iter(self._headers)

    def __nonzero__(self):
        return bool(self._set)

    def __str__(self):
        return self.to_header()

    def __repr__(self):
        return "%s(%r)" % (self.__class__.__name__, self._headers)


class ETags(collections_abc.Container, collections_abc.Iterable):
    """一个用于检测是否一个标签出现在一个标签集合中的集合。
    """

    def __init__(self, strong_etags=None, weak_etags=None, star_tag=False):
        self._strong = frozenset(not star_tag and strong_etags or ())
        self._weak = frozenset(weak_etags or ())
        self.star_tag = star_tag

    def as_set(self, include_weak=False):
        """将`Etags`对象转换成一个Python集合。每个默认的所有弱标签不是这个集合的一部分。"""
        rv = set(self._strong)
        if include_weak:
            rv.update(self._weak)
        return rv

    def is_weak(self, etag):
        """检测一个标签是否是弱标签。"""
        return etag in self._weak

    def is_strong(self, etag):
        """检测一个标签是否是强标签。"""
        return etag in self._strong

    def contains_weak(self, etag):
        """检测一个标签是否是一个包含弱标签和强标签的集合的一部分。"""
        return self.is_weak(etag) or self.contains(etag)

    def contains(self, etag):
        """检测一个标签是否是一个忽略了弱标签的集合的一部分。也可以使用``in``操作符。
        """
        if self.star_tag:
            return True
        return self.is_strong(etag)

    def contains_raw(self, etag):
        """传递一个带引号的标签的时候，将会检查这个标签是否是标签集合的一部分。如果这个标签是
        弱标签，则会检查弱标签和强标签，否则为只能是强标签。
        """
        etag, weak = unquote_etag(etag)
        if weak:
            return self.contains_weak(etag)
        return self.contains(etag)

    def to_header(self):
        """将标签集合转换成HTTP头部中的字符串。"""
        if self.star_tag:
            return "*"
        return ", ".join(
            ['"%s"' % x for x in self._strong] + ['W/"%s"' % x for x in self._weak]
        )

    def __call__(self, etag=None, data=None, include_weak=False):
        if [etag, data].count(None) != 1:
            raise TypeError("either tag or data required, but at least one")
        if etag is None:
            etag = generate_etag(data)
        if include_weak:
            if etag in self._weak:
                return True
        return etag in self._strong

    def __bool__(self):
        return bool(self.star_tag or self._strong or self._weak)

    __nonzero__ = __bool__

    def __str__(self):
        return self.to_header()

    def __iter__(self):
        return iter(self._strong)

    def __contains__(self, etag):
        return self.contains(etag)

    def __repr__(self):
        return "<%s %r>" % (self.__class__.__name__, str(self))


class IfRange(object):
    """以解析后的形式表示`If-range`头部的简单的对象。Very simple object that represents the `If-Range` header in parsed
    form.  它的值要么是etag和date两者之一，要么就都不是。

    .. versionadded:: 0.7
    """

    def __init__(self, etag=None, date=None):
        #: 解析和取消引号之后的etag。Ranges总是操作强etags，所以弱信息就没必要了。
        self.etag = etag
        #: 解析格式的date或者为`None`。The date in parsed format or `None`.
        self.date = date

    def to_header(self):
        """将对象转换回一个HTTP头部。"""
        if self.date is not None:
            return http_date(self.date)
        if self.etag is not None:
            return quote_etag(self.etag)
        return ""

    def __str__(self):
        return self.to_header()

    def __repr__(self):
        return "<%s %r>" % (self.__class__.__name__, str(self))


class Range(object):
    """Represents a ``Range`` header. All methods only support only
    bytes as the unit. Stores a list of ranges if given, but the methods
    only work if only one range is provided.

    :raise ValueError: If the ranges provided are invalid.

    .. versionchanged:: 0.15
        The ranges passed in are validated.

    .. versionadded:: 0.7
    """

    def __init__(self, units, ranges):
        #: The units of this range.  Usually "bytes".
        self.units = units
        #: A list of ``(begin, end)`` tuples for the range header provided.
        #: The ranges are non-inclusive.
        self.ranges = ranges

        for start, end in ranges:
            if start is None or (end is not None and (start < 0 or start >= end)):
                raise ValueError("{} is not a valid range.".format((start, end)))

    def range_for_length(self, length):
        """If the range is for bytes, the length is not None and there is
        exactly one range and it is satisfiable it returns a ``(start, stop)``
        tuple, otherwise `None`.
        """
        if self.units != "bytes" or length is None or len(self.ranges) != 1:
            return None
        start, end = self.ranges[0]
        if end is None:
            end = length
            if start < 0:
                start += length
        if is_byte_range_valid(start, end, length):
            return start, min(end, length)

    def make_content_range(self, length):
        """Creates a :class:`~werkzeug.datastructures.ContentRange` object
        from the current range and given content length.
        """
        rng = self.range_for_length(length)
        if rng is not None:
            return ContentRange(self.units, rng[0], rng[1], length)

    def to_header(self):
        """Converts the object back into an HTTP header."""
        ranges = []
        for begin, end in self.ranges:
            if end is None:
                ranges.append("%s-" % begin if begin >= 0 else str(begin))
            else:
                ranges.append("%s-%s" % (begin, end - 1))
        return "%s=%s" % (self.units, ",".join(ranges))

    def to_content_range_header(self, length):
        """Converts the object into `Content-Range` HTTP header,
        based on given length
        """
        range_for_length = self.range_for_length(length)
        if range_for_length is not None:
            return "%s %d-%d/%d" % (
                self.units,
                range_for_length[0],
                range_for_length[1] - 1,
                length,
            )
        return None

    def __str__(self):
        return self.to_header()

    def __repr__(self):
        return "<%s %r>" % (self.__class__.__name__, str(self))


class ContentRange(object):
    """表示内容范围头部。

    .. versionadded:: 0.7
    """

    def __init__(self, units, start, stop, length=None, on_update=None):
        assert is_byte_range_valid(start, stop, length), "Bad range provided"
        self.on_update = on_update
        self.set(start, stop, length, units)

    def _callback_property(name):  # noqa: B902
        def fget(self):
            return getattr(self, name)

        def fset(self, value):
            setattr(self, name, value)
            if self.on_update is not None:
                self.on_update(self)

        return property(fget, fset)

    #：使用单位，通常是"bytes"
    units = _callback_property("_units")
    #：内容范围的起点或者为`None`。
    start = _callback_property("_start")
    #：内容范围的终点（不包含）或者为`None`。如果起点也为`None`，终点只能为`None`。
    stop = _callback_property("_stop")
    #： 内容范围的长度或者为`None`。
    length = _callback_property("_length")
    del _callback_property

    def set(self, start, stop, length=None, units="bytes"):
        """用于更新内容范围的简单方法"""
        assert is_byte_range_valid(start, stop, length), "Bad range provided"
        self._units = units
        self._start = start
        self._stop = stop
        self._length = length
        if self.on_update is not None:
            self.on_update(self)

    def unset(self):
        """设置单位为`None`，表明这个头部不应该再被使用。
        """
        self.set(None, None, units=None)

    def to_header(self):
        if self.units is None:
            return ""
        if self.length is None:
            length = "*"
        else:
            length = self.length
        if self.start is None:
            return "%s */%s" % (self.units, length)
        return "%s %s-%s/%s" % (self.units, self.start, self.stop - 1, length)

    def __nonzero__(self):
        return self.units is not None

    __bool__ = __nonzero__

    def __str__(self):
        return self.to_header()

    def __repr__(self):
        return "<%s %r>" % (self.__class__.__name__, str(self))


class Authorization(ImmutableDictMixin, dict):
    """表示客户端发送的`Authorization` HTTP头部。不应该自己创建这种对象，而是当
    `parse_authorization_header`函数返回时，使用这个对象。

    这个对象是字典的子类，并且能够通过设置字典的项来改变，但是应该考虑当它由客户端返回和不可
    修改的时候，使用不可变对象。

    .. versionchanged:: 0.5
       这个对象变成不可变对象。
    """

    def __init__(self, auth_type, data=None):
        dict.__init__(self, data or {})
        self.type = auth_type

    username = property(
        lambda self: self.get("username"),
        doc="""
        传输的用户名。一直为basic 和 digest auth而设置""",
    )
    password = property(
        lambda self: self.get("password"),
        doc="""
        当认证类型是basic的时候，这是有客户端传输的密码，否则是`None`。""",
    )
    realm = property(
        lambda self: self.get("realm"),
        doc="""
        发送回来的HTTP digest 认证服务器领域。""",
    )
    nonce = property(
        lambda self: self.get("nonce"),
        doc="""
        服务器发送回给客户端用于digest认证的特定信息。每次HTTP摘要产生的401响应的时候，
        一份特定信息都是唯一的。""",
    )
    uri = property(
        lambda self: self.get("uri"),
        doc="""
        浏览器请求行的请求URI。因为代理在传输的过程中允许修改请求行，所以是重复的。
        只用于HTTP digest 认证。""",
    )
    nc = property(
        lambda self: self.get("nc"),
        doc="""
        如果qop-header也被传输，客户端中传输特定信息的计数值。只用于HTTP digest 认证。""",
    )
    cnonce = property(
        lambda self: self.get("cnonce"),
        doc="""
        如果服务器在``WWW-Authenticate``头部中发送qop-header，客户端得提供用于HTTP
        digest 认证的值。参阅RFC获取更多信息。""",
    )
    response = property(
        lambda self: self.get("response"),
        doc="""
        A string of 32 hex digits computed as defined in RFC 2617, which
        proves that the user knows a password.  Digest auth only.""",
    )
    opaque = property(
        lambda self: self.get("opaque"),
        doc="""
        客户端未改变并且返回的来自服务器的不透明头部。推荐这个字符串使用base64或者是十六进制
        的数据。仅用于Digest 认证。""",
    )
    qop = property(
        lambda self: self.get("qop"),
        doc="""
        暗示客户端对HTTP digest 认证信息应用的“资格保护”。注意这个是单独token，而不是一个
        作为在WWW-Authenticate中第二选择的加引号的列表。""",
    )


class WWWAuthenticate(UpdateDictMixin, dict):
    """Provides simple access to `WWW-Authenticate` headers."""

    #: list of keys that require quoting in the generated header
    _require_quoting = frozenset(["domain", "nonce", "opaque", "realm", "qop"])

    def __init__(self, auth_type=None, values=None, on_update=None):
        dict.__init__(self, values or ())
        if auth_type:
            self["__auth_type__"] = auth_type
        self.on_update = on_update

    def set_basic(self, realm="authentication required"):
        """Clear the auth info and enable basic auth."""
        dict.clear(self)
        dict.update(self, {"__auth_type__": "basic", "realm": realm})
        if self.on_update:
            self.on_update(self)

    def set_digest(
        self, realm, nonce, qop=("auth",), opaque=None, algorithm=None, stale=False
    ):
        """Clear the auth info and enable digest auth."""
        d = {
            "__auth_type__": "digest",
            "realm": realm,
            "nonce": nonce,
            "qop": dump_header(qop),
        }
        if stale:
            d["stale"] = "TRUE"
        if opaque is not None:
            d["opaque"] = opaque
        if algorithm is not None:
            d["algorithm"] = algorithm
        dict.clear(self)
        dict.update(self, d)
        if self.on_update:
            self.on_update(self)

    def to_header(self):
        """Convert the stored values into a WWW-Authenticate header."""
        d = dict(self)
        auth_type = d.pop("__auth_type__", None) or "basic"
        return "%s %s" % (
            auth_type.title(),
            ", ".join(
                [
                    "%s=%s"
                    % (
                        key,
                        quote_header_value(
                            value, allow_token=key not in self._require_quoting
                        ),
                    )
                    for key, value in iteritems(d)
                ]
            ),
        )

    def __str__(self):
        return self.to_header()

    def __repr__(self):
        return "<%s %r>" % (self.__class__.__name__, self.to_header())

    def auth_property(name, doc=None):  # noqa: B902
        """A static helper function for subclasses to add extra authentication
        system properties onto a class::

            class FooAuthenticate(WWWAuthenticate):
                special_realm = auth_property('special_realm')

        For more information have a look at the sourcecode to see how the
        regular properties (:attr:`realm` etc.) are implemented.
        """

        def _set_value(self, value):
            if value is None:
                self.pop(name, None)
            else:
                self[name] = str(value)

        return property(lambda x: x.get(name), _set_value, doc=doc)

    def _set_property(name, doc=None):  # noqa: B902
        def fget(self):
            def on_update(header_set):
                if not header_set and name in self:
                    del self[name]
                elif header_set:
                    self[name] = header_set.to_header()

            return parse_set_header(self.get(name), on_update)

        return property(fget, doc=doc)

    type = auth_property(
        "__auth_type__",
        doc="""The type of the auth mechanism. HTTP currently specifies
        ``Basic`` and ``Digest``.""",
    )
    realm = auth_property(
        "realm",
        doc="""A string to be displayed to users so they know which
        username and password to use. This string should contain at
        least the name of the host performing the authentication and
        might additionally indicate the collection of users who might
        have access.""",
    )
    domain = _set_property(
        "domain",
        doc="""A list of URIs that define the protection space. If a URI
        is an absolute path, it is relative to the canonical root URL of
        the server being accessed.""",
    )
    nonce = auth_property(
        "nonce",
        doc="""
        A server-specified data string which should be uniquely generated
        each time a 401 response is made. It is recommended that this
        string be base64 or hexadecimal data.""",
    )
    opaque = auth_property(
        "opaque",
        doc="""A string of data, specified by the server, which should
        be returned by the client unchanged in the Authorization header
        of subsequent requests with URIs in the same protection space.
        It is recommended that this string be base64 or hexadecimal
        data.""",
    )
    algorithm = auth_property(
        "algorithm",
        doc="""A string indicating a pair of algorithms used to produce
        the digest and a checksum. If this is not present it is assumed
        to be "MD5". If the algorithm is not understood, the challenge
        should be ignored (and a different one used, if there is more
        than one).""",
    )
    qop = _set_property(
        "qop",
        doc="""A set of quality-of-privacy directives such as auth and
        auth-int.""",
    )

    @property
    def stale(self):
        """A flag, indicating that the previous request from the client
        was rejected because the nonce value was stale.
        """
        val = self.get("stale")
        if val is not None:
            return val.lower() == "true"

    @stale.setter
    def stale(self, value):
        if value is None:
            self.pop("stale", None)
        else:
            self["stale"] = "TRUE" if value else "FALSE"

    auth_property = staticmethod(auth_property)
    del _set_property


class FileStorage(object):
    """The :class:`FileStorage` class is a thin wrapper over incoming files.
    It is used by the request object to represent uploaded files.  All the
    attributes of the wrapper stream are proxied by the file storage so
    it's possible to do ``storage.read()`` instead of the long form
    ``storage.stream.read()``.
    """

    def __init__(
        self,
        stream=None,
        filename=None,
        name=None,
        content_type=None,
        content_length=None,
        headers=None,
    ):
        self.name = name
        self.stream = stream or BytesIO()

        # if no filename is provided we can attempt to get the filename
        # from the stream object passed.  There we have to be careful to
        # skip things like <fdopen>, <stderr> etc.  Python marks these
        # special filenames with angular brackets.
        if filename is None:
            filename = getattr(stream, "name", None)
            s = make_literal_wrapper(filename)
            if filename and filename[0] == s("<") and filename[-1] == s(">"):
                filename = None

            # On Python 3 we want to make sure the filename is always unicode.
            # This might not be if the name attribute is bytes due to the
            # file being opened from the bytes API.
            if not PY2 and isinstance(filename, bytes):
                filename = filename.decode(get_filesystem_encoding(), "replace")

        self.filename = filename
        if headers is None:
            headers = Headers()
        self.headers = headers
        if content_type is not None:
            headers["Content-Type"] = content_type
        if content_length is not None:
            headers["Content-Length"] = str(content_length)

    def _parse_content_type(self):
        if not hasattr(self, "_parsed_content_type"):
            self._parsed_content_type = parse_options_header(self.content_type)

    @property
    def content_type(self):
        """The content-type sent in the header.  Usually not available"""
        return self.headers.get("content-type")

    @property
    def content_length(self):
        """The content-length sent in the header.  Usually not available"""
        return int(self.headers.get("content-length") or 0)

    @property
    def mimetype(self):
        """Like :attr:`content_type`, but without parameters (eg, without
        charset, type etc.) and always lowercase.  For example if the content
        type is ``text/HTML; charset=utf-8`` the mimetype would be
        ``'text/html'``.

        .. versionadded:: 0.7
        """
        self._parse_content_type()
        return self._parsed_content_type[0].lower()

    @property
    def mimetype_params(self):
        """The mimetype parameters as dict.  For example if the content
        type is ``text/html; charset=utf-8`` the params would be
        ``{'charset': 'utf-8'}``.

        .. versionadded:: 0.7
        """
        self._parse_content_type()
        return self._parsed_content_type[1]

    def save(self, dst, buffer_size=16384):
        """Save the file to a destination path or file object.  If the
        destination is a file object you have to close it yourself after the
        call.  The buffer size is the number of bytes held in memory during
        the copy process.  It defaults to 16KB.

        For secure file saving also have a look at :func:`secure_filename`.

        :param dst: a filename or open file object the uploaded file
                    is saved to.
        :param buffer_size: the size of the buffer.  This works the same as
                            the `length` parameter of
                            :func:`shutil.copyfileobj`.
        """
        from shutil import copyfileobj

        close_dst = False
        if isinstance(dst, string_types):
            dst = open(dst, "wb")
            close_dst = True
        try:
            copyfileobj(self.stream, dst, buffer_size)
        finally:
            if close_dst:
                dst.close()

    def close(self):
        """Close the underlying file if possible."""
        try:
            self.stream.close()
        except Exception:
            pass

    def __nonzero__(self):
        return bool(self.filename)

    __bool__ = __nonzero__

    def __getattr__(self, name):
        try:
            return getattr(self.stream, name)
        except AttributeError:
            # SpooledTemporaryFile doesn't implement IOBase, get the
            # attribute from its backing file instead.
            # https://github.com/python/cpython/pull/3249
            if hasattr(self.stream, "_file"):
                return getattr(self.stream._file, name)
            raise

    def __iter__(self):
        return iter(self.stream)

    def __repr__(self):
        return "<%s: %r (%r)>" % (
            self.__class__.__name__,
            self.filename,
            self.content_type,
        )


# circular dependencies
from . import exceptions
from .http import dump_header
from .http import dump_options_header
from .http import generate_etag
from .http import http_date
from .http import is_byte_range_valid
from .http import parse_options_header
from .http import parse_set_header
from .http import quote_etag
from .http import quote_header_value
from .http import unquote_etag
