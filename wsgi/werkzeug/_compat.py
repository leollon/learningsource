# flake8: noqa
# This whole file is full of lint errors
import functools
import operator
import sys

try:
    import builtins
except ImportError:
    import __builtin__ as builtins


PY2 = sys.version_info[0] == 2
WIN = sys.platform.startswith("win")

_identity = lambda x: x

if PY2:
    unichr = unichr
    text_type = unicode
    string_types = (str, unicode)
    integer_types = (int, long)

    iterkeys = lambda d, *args, **kwargs: d.iterkeys(*args, **kwargs)
    itervalues = lambda d, *args, **kwargs: d.itervalues(*args, **kwargs)
    iteritems = lambda d, *args, **kwargs: d.iteritems(*args, **kwargs)

    iterlists = lambda d, *args, **kwargs: d.iterlists(*args, **kwargs)
    iterlistvalues = lambda d, *args, **kwargs: d.iterlistvalues(
        *args, **kwargs
    )

    int_to_byte = chr
    iter_bytes = iter

    import collections as collections_abc

    exec("def reraise(tp, value, tb=None):\n raise tp, value, tb")

    def fix_tuple_repr(obj):
        """
        >>> fix_tuple_repr(collections_abc.namedtuple("_URLTuple", ("scheme", "netloc", "path", "query", "fragments")))
        <class '__main__._URLTuple'>
        """

        def __repr__(self):
            cls = self.__class__
            return "%s(%s)" % (
                cls.__name__,
                ", ".join(
                    "%s=%r" % (field, self[index])
                    for index, field in enumerate(cls._fields)
                ),
            )

        obj.__repr__ = __repr__
        return obj

    def implements_iterator(cls):
        cls.next = cls.__next__
        del cls.__next__
        return cls

    def implements_to_string(cls):
        cls.__unicode__ = cls.__str__
        cls.__str__ = lambda x: x.__unicode__().encode("utf-8")
        return cls

    def native_string_result(func):
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs).encode("utf-8")

        return functools.update_wrapper(wrapper, func)

    def implements_bool(cls):
        cls.__nonzero__ = cls.__bool__
        del cls.__bool__
        return cls

    from itertools import imap, izip, ifilter

    range_type = xrange

    from StringIO import StringIO
    from cStringIO import StringIO as BytesIO

    NativeStringIO = BytesIO

    def make_literal_wrapper(reference):
        return _identity

    def normalize_string_tuple(tup):
        """Normalizes a string tuple to a common type. Following Python 2
        rules, upgrades to unicode are implicit.
        """
        if any(isinstance(x, text_type) for x in tup):
            return tuple(to_unicode(x) for x in tup)
        return tup

    def try_coerce_native(s):
        """如果有可能，尝试强制将一个unicode字符串变成原始的类型。否则按照原来的unicode保留下来。
        """
        try:
            return to_native(s)
        except UnicodeError:
            return s

    wsgi_get_bytes = _identity

    def wsgi_decoding_dance(s, charset="utf-8", errors="replace"):
        return s.decode(charset, errors)

    def wsgi_encoding_dance(s, charset="utf-8", errors="replace"):
        if isinstance(s, bytes):
            return s
        return s.encode(charset, errors)

    def to_bytes(x, charset=sys.getdefaultencoding(), errors="strict"):
        """转成字节类型数据"""
        if x is None:
            return None
        if isinstance(x, (bytes, bytearray, buffer)):
            return bytes(x)
        if isinstance(x, unicode):
            return x.encode(charset, errors)
        raise TypeError("Expected bytes")

    def to_native(x, charset=sys.getdefaultencoding(), errors="strict"):
        if x is None or isinstance(x, str):
            return x
        # 将x编码成系统默认编码的x
        return x.encode(charset, errors)


else:
    unichr = chr
    text_type = str
    string_types = (str,)
    integer_types = (int,)

    iterkeys = lambda d, *args, **kwargs: iter(d.keys(*args, **kwargs))
    itervalues = lambda d, *args, **kwargs: iter(d.values(*args, **kwargs))
    iteritems = lambda d, *args, **kwargs: iter(d.items(*args, **kwargs))

    iterlists = lambda d, *args, **kwargs: iter(d.lists(*args, **kwargs))
    iterlistvalues = lambda d, *args, **kwargs: iter(
        d.listvalues(*args, **kwargs)
    )

    int_to_byte = operator.methodcaller("to_bytes", 1, "big")
    iter_bytes = functools.partial(map, int_to_byte)

    import collections.abc as collections_abc

    def reraise(tp, value, tb=None):
        if value.__traceback__ is not tb:
            raise value.with_traceback(tb)
        raise value

    fix_tuple_repr = _identity
    implements_iterator = _identity
    implements_to_string = _identity
    implements_bool = _identity
    native_string_result = _identity
    imap = map
    izip = zip
    ifilter = filter
    range_type = range

    from io import StringIO, BytesIO

    NativeStringIO = StringIO

    _latin1_encode = operator.methodcaller("encode", "latin1")

    def make_literal_wrapper(reference):
        """返回一个函数对象"""
        if isinstance(reference, text_type):
            return _identity
        return _latin1_encode

    def normalize_string_tuple(tup):
        """确保元组中的所有类型是字符串类型或者是字节类型。
        """
        tupiter = iter(tup)  # 迭代器
        is_text = isinstance(next(tupiter, None), text_type)
        for arg in tupiter:
            if isinstance(arg, text_type) != is_text:
                raise TypeError(
                    "Cannot mix str and bytes arguments (got %s)" % repr(tup)
                )
        return tup

    try_coerce_native = _identity
    wsgi_get_bytes = _latin1_encode

    def wsgi_decoding_dance(s, charset="utf-8", errors="replace"):
        return s.encode("latin1").decode(charset, errors)

    def wsgi_encoding_dance(s, charset="utf-8", errors="replace"):
        if isinstance(s, text_type):
            s = s.encode(charset)
        return s.decode("latin1", errors)

    def to_bytes(x, charset=sys.getdefaultencoding(), errors="strict"):
        """转成字节类型数据"""
        if x is None:
            return None
        if isinstance(x, (bytes, bytearray, memoryview)):  # noqa
            return bytes(x)
        if isinstance(x, str):
            return x.encode(charset, errors)
        raise TypeError("Expected bytes")

    def to_native(x, charset=sys.getdefaultencoding(), errors="strict"):
        if x is None or isinstance(x, str):
            return x
        # 将x解码成系统默认编码的x
        return x.decode(charset, errors)


def to_unicode(
    x,
    charset=sys.getdefaultencoding(),
    errors="strict",
    allow_none_charset=False,
):
    """使用系统默认的编码对x进行解码
    """
    if x is None:
        return None
    if not isinstance(x, bytes):
        # 转成unicode编码
        return text_type(x)
    if charset is None and allow_none_charset:
        return x
    # 对x解码
    return x.decode(charset, errors)
