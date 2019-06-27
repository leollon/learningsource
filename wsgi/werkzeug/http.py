# -*- coding: utf-8 -*-
"""
    werkzeug.http
    ~~~~~~~~~~~~~

    Werkzeug的许多实用程序帮助Werkzeug处理HTTP数据。这个模块提供的大部分类和函数都被包装器
    使用到，但是它们自身也是有用处的，尤其是如果响应和请求对象不被使用的时候。

    这个涵盖了一些WSGI更中心的HTTP特性，一些其他实用程序比如cookie处理被放在
    `werkzeug.utils`模块中。

    :copyright: 2007 Pallets
    :license: BSD-3-Clause
"""
import base64
import re
import warnings
from datetime import datetime
from datetime import timedelta
from hashlib import md5
from time import gmtime
from time import time

from ._compat import integer_types
from ._compat import iteritems
from ._compat import PY2
from ._compat import string_types
from ._compat import text_type
from ._compat import to_bytes
from ._compat import to_unicode
from ._compat import try_coerce_native
from ._internal import _cookie_parse_impl
from ._internal import _cookie_quote
from ._internal import _make_cookie_domain

try:
    from email.utils import parsedate_tz
except ImportError:
    from email.Utils import parsedate_tz

try:
    from urllib.request import parse_http_list as _parse_list_header
    from urllib.parse import unquote_to_bytes as _unquote
except ImportError:
    from urllib2 import parse_http_list as _parse_list_header
    from urllib2 import unquote as _unquote

_cookie_charset = "latin1"  # cookie 字符集
_basic_auth_charset = "utf-8"  # 基本授权字符集
# “媒体-范围”等的解释，参阅RFC7231 5.3.{1,2}部分
# Accept: text/plain; q=0.5, text/html,text/x-dvi; q=0.8, text/x-c
_accept_re = re.compile(
    r"""
    (                       # 媒体范围捕捉括号
      [^\s;,]+              # type/subtype
      (?:[ \t]*;[ \t]*      # ";"
        (?:                 # parameter non-capturing-parenthesis
          [^\s;,q][^\s;,]*  # 不是"q"开头的token
        |                   # 或是
          q[^\s;,=][^\s;,]* # 不仅仅是"q"的token
        )
      )*                    # 零或N次
    )                       # 媒体范围结束
    (?:[ \t]*;[ \t]*q=      # 权重参数"q"
      (\d*(?:\.\d+)?)       # q值捕捉括号
      [^,]*                 # “扩展”accept参数：管它呢？
    )?                      # accept 参数是可选的
    """,
    re.VERBOSE,
)
_token_chars = frozenset(
    "!#$%&'*+-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ^_`abcdefghijklmnopqrstuvwxyz|~"
)
# HTTP中的etag字段
_etag_re = re.compile(r'([Ww]/)?(?:"(.*?)"|(.*?))(?:\s*,\s*|$)')
_unsafe_header_chars = set('()<>@,;:"/[]?={} \t')
# 可选的HTTP头部信息
_option_header_piece_re = re.compile(
    r"""
    ;\s*,?\s*  # 使用逗号代替换行符号
    (?P<key>
        "[^"\\]*(?:\\.[^"\\]*)*"  # 被引用的字符串
    |
        [^\s;,=*]+  # token
    )
    (?:\*(?P<count>\d+))?  # *1，可选的连续索引
    \s*
    (?:  # 可选的伴随有=value
        (?:  # 等号，可能含有编码信息
            \*\s*=\s*  # * 意味着扩展的注记
            (?:  # 可选编码信息
                (?P<encoding>[^\s]+?)
                '(?P<language>[^\s]*?)'
            )?
        |
            =\s*  # 基本的注记
        )
        (?P<value>
            "[^"\\]*(?:\\.[^"\\]*)*"  # 引用的字符串
        |
            [^;,]+  # token
        )?
    )?
    \s*
    """,
    flags=re.VERBOSE,
)
_option_header_start_mime_type = re.compile(r",\s*([^;,\s]+)([;,]\s*.+)?")

# 关于实体的HTTP首部
_entity_headers = frozenset(
    [
        "allow",
        "content-encoding",
        "content-language",
        "content-length",
        "content-location",
        "content-md5",
        "content-range",
        "content-type",
        "expires",
        "last-modified",
    ]
)
# 关于网络连接传输层中的HTTP头部
_hop_by_hop_headers = frozenset(
    [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ]
)

# HTTP状态码
HTTP_STATUS_CODES = {
    100: "Continue",
    101: "Switching Protocols",
    102: "Processing",
    200: "OK",
    201: "Created",
    202: "Accepted",
    203: "Non Authoritative Information",
    204: "No Content",
    205: "Reset Content",
    206: "Partial Content",
    207: "Multi Status",
    226: "IM Used",  # see RFC 3229
    300: "Multiple Choices",
    301: "Moved Permanently",
    302: "Found",
    303: "See Other",
    304: "Not Modified",
    305: "Use Proxy",
    307: "Temporary Redirect",
    308: "Permanent Redirect",
    400: "Bad Request",
    401: "Unauthorized",
    402: "Payment Required",  # unused
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    406: "Not Acceptable",
    407: "Proxy Authentication Required",
    408: "Request Timeout",
    409: "Conflict",
    410: "Gone",
    411: "Length Required",
    412: "Precondition Failed",
    413: "Request Entity Too Large",
    414: "Request URI Too Long",
    415: "Unsupported Media Type",
    416: "Requested Range Not Satisfiable",
    417: "Expectation Failed",
    418: "I'm a teapot",  # see RFC 2324
    421: "Misdirected Request",  # see RFC 7540
    422: "Unprocessable Entity",
    423: "Locked",
    424: "Failed Dependency",
    426: "Upgrade Required",
    428: "Precondition Required",  # see RFC 6585
    429: "Too Many Requests",
    431: "Request Header Fields Too Large",
    449: "Retry With",  # proprietary MS extension
    451: "Unavailable For Legal Reasons",
    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
    505: "HTTP Version Not Supported",
    507: "Insufficient Storage",
    510: "Not Extended",
}


def wsgi_to_bytes(data):
    """强制WSGI unicode 数据使用字节表示"""
    if isinstance(data, bytes):
        return data
    return data.encode("latin1")  # XXX: utf8 fallback?


def bytes_to_wsgi(data):
    assert isinstance(data, bytes), "data must be bytes"
    if isinstance(data, str):
        # unicode
        return data
    else:
        return data.decode("latin1")


def quote_header_value(value, extra_chars="", allow_token=True):
    """如果有必要，则引用一个头部。

    .. versionadded:: 0.5

    :param value: 引用的值。
    :param extra_chars: 一个用于跳过引用的额外字符序列。
    :param allow_token: 如果为True，token值原样返回。
    """
    if isinstance(value, bytes):
        value = bytes_to_wsgi(value)
    value = str(value)
    if allow_token:
        token_chars = _token_chars | set(extra_chars) # 取并集
        if set(value).issubset(token_chars):
            return value
    return '"%s"' % value.replace("\\", "\\\\").replace('"', '\\"')


def unquote_header_value(value, is_filename=False):
    r"""取消引用一个头部的值。（与:func:`quote_header_header`函数功能相反。）
    不是真正地取消引用，而是实际上浏览器用什么去引用。

    .. versionadded:: 0.5

    :param value: 取消引用的头部值。
    """
    if value and value[0] == value[-1] == '"':
        # 这不是真正的不引用，而是修复它，目的是满足RFC，这在IE中会产生bugs并且在其他浏览器
        # 中也有可能。例如，IE上传文件时使用"C:\foo\bar.txt"作为文件名。
        value = value[1:-1]

        # 如果是一个文件并且开始字符看起来像是UNC路径，那么不加引号而直接返回。在UNC路径上
        # 使用下面的替换序列会将头两个斜杠变成单个杠，那么_fix_ie_filename()不能正确的工
        # 作。参阅 #458
        if not is_filename or value[:2] != "\\\\":
            return value.replace("\\\\", "\\").replace('\\"', '"')
    return value


def dump_options_header(header, options):
    """:func:`parse_options_header`的相反函数.

    :param header: 要转存的头部
    :param options: 要添加的选项的字典
    """
    segments = []
    if header is not None:
        segments.append(header)
    for key, value in iteritems(options):
        if value is None:
            segments.append(key)
        else:
            segments.append("%s=%s" % (key, quote_header_value(value)))
    return "; ".join(segments)


def dump_header(iterable, allow_token=True):
    """再次转存HTTP头部。:func:`parse_list_header`，:func:`parse_set_header`和
    :func:`parse_dict_header`的相反函数。引用包含等号的字符串，除非使用键值对的字典进行传
    递。

    >>> dump_header({'foo': 'bar baz'})
    'foo="bar baz"'
    >>> dump_header(('foo', 'bar baz'))
    'foo, "bar baz"'

    :param iterable: 要引用的可迭代对象或键值对字典。
    :param allow_token: 如果设置为`False`，则不允许tokens值。
                        参阅:func:`quote_header_value`获取更多细节。
    """
    if isinstance(iterable, dict):
        items = []
        for key, value in iteritems(iterable):
            if value is None:
                items.append(key)
            else:
                items.append(
                    "%s=%s" % (key, quote_header_value(value, allow_token=allow_token))
                )
    else:
        items = [quote_header_value(x, allow_token=allow_token) for x in iterable]
    return ", ".join(items)


def parse_list_header(value):
    """根据RFC 2068 Section 2描述来解析列表。

    特别地，解析逗号分割的且列表中的元素可能含有引用的字符串的列表。加引号的字符串可能包含逗号。
    未加引号的字符串可能有引号在中间。在解析之后引号被自动移除。

    基本上像:func:`parse_set_header`一样的功能，只是那一项可能会出现多次并且区分大小的保留
    了下来。

    返回值是一个标准的:class:`list`：

    >>> parse_list_header('token, "quoted value"')
    ['token', 'quoted value']

    为了再次从这个:class:`list`创建出一个头部，需使用:func:`dump_header`函数。

    :param value: 含有头部列表在其中的字符串
    :return: :class:`list`
    """
    result = []
    for item in _parse_list_header(value):
        if item[:1] == item[-1:] == '"':
            # '"quoted value"' -> quoted value
            item = unquote_header_value(item[1:-1])
        result.append(item)
    return result


def parse_dict_header(value, cls=dict):
    """根据RFC 2068 Section 2 的描述解析键值对列表并且将它们转换成python字典（或者通过
    含有一个dict的类型，就像是通过`cls`参数来提供的接口一样，来创建的任何其他映射对象）：

    >>> d = parse_dict_header('foo="is a fish", bar="as well"')
    >>> type(d) is dict
    True
    >>> sorted(d.items())
    [('bar', 'as well'), ('foo', 'is a fish')]

    如果一个键没有对应的值，那么这个键对应的值是`None`：

    >>> parse_dict_header('key_without_value')
    {'key_without_value': None}

    可以使用:func:`dump_header`函数再次从:class:`dict`创建出一个头部。

    .. versionchanged:: 0.9
       添加`cls`参数支持。

    :param value: 含有字典头部的字符串
    :param cls: 用于解析后的结果存储的可调用对象callable to use for storage of parsed results.
    :return: an instance of `cls`
    """
    result = cls()
    if not isinstance(value, text_type):
        # XXX: validate
        value = bytes_to_wsgi(value)
    for item in _parse_list_header(value):
        if "=" not in item:
            result[item] = None
            continue
        name, value = item.split("=", 1)
        if value[:1] == value[-1:] == '"':
            value = unquote_header_value(value[1:-1])
        result[name] = value
    return result


def parse_options_header(value, multiple=False):
    """将像``Content-Type``这样的HTTP头部解析成包含内容类型和选项的元组：

    >>> parse_options_header('text/html; charset=utf8')
    ('text/html', {'charset': 'utf8'})

    不应该使用这个函数来解析像``Cache-control``这样子稍微使用了不同格式的HTTP头部。对于这
    种头部，使用:func:``parse_dict_header``函数。

    .. versionchanged:: 0.15
        :rfc:`2231` 处理参数连续

    .. versionadded:: 0.5

    :param value: 要解析的头部。
    :param multiple: 尝试解析并且返回多个MIME types
    :return: (mimetype, options) or (mimetype, options, mimetype, options, …)
             if multiple=True
    """
    if not value:
        # value == None or value == ""
        return "", {}

    result = []

    # value = 'text/html; charset=utf-8'
    value = "," + value.replace("\n", ",")  # ',text/html; charset=utf-8'
    while value:
        match = _option_header_start_mime_type.match(value)
        if not match:
            break
        result.append(match.group(1))  # mimetype, text/html(Content-type)
        options = {}
        # 解析选项
        rest = match.group(2)  # ; charset=utf-8
        continued_encoding = None
        while rest:
            optmatch = _option_header_piece_re.match(rest)
            if not optmatch:
                break
            option, count, encoding, language, option_value = optmatch.groups()  # ('charset, None, None, None, 'utf-8')
            # 首行后的连续行不需要提供编码。如果处于连续行，使用当前的编码当作后续行的编码。
            # 当连续行结束的时候进行重置。
            if not count:
                continued_encoding = None
            else:
                if not encoding:
                    encoding = continued_encoding
                continued_encoding = encoding
            option = unquote_header_value(option)
            if option_value is not None:
                option_value = unquote_header_value(option_value, option == "filename")
                if encoding is not None:
                    option_value = _unquote(option_value).decode(encoding)
            if count:
                # 连续添加到正存在的的值，为了简洁性，忽略了不该产生的乱许索引的可能性。
                options[option] = options.get(option, "") + option_value
            else:
                options[option] = option_value
            rest = rest[optmatch.end() :]
        result.append(options)
        if multiple is False:
            return tuple(result)
        value = rest

    return tuple(result) if result else ("", {})


def parse_accept_header(value, cls=None):
    """解析HTTP Accept-* 头部。未实现完整且有效的算法但是至少支持值（value)和权重(quality)
    的解析。

    返回新的:class:`Accept`对象（基本上是通过含有额外存储器方法的权重排序后的一个
    ``(value, quality)``列表。

    第二个参数可能是由解析后的值创建并返回的:class:`Accept` 的子类。

    :param value: 被解析的accept头部字符串
    :param cls: 返回值的包装类（可能是:class:`Accept`或:class:`Accept`的子类）
    :return: 返回`cls`的一个实例。
    """
    if cls is None:
        cls = Accept

    if not value:
        return cls(None)

    result = []
    for match in _accept_re.finditer(value):
        quality = match.group(2)
        if not quality:
            quality = 1
        else:
            quality = max(min(float(quality), 1), 0)
        result.append((match.group(1), quality))
    return cls(result)


def parse_cache_control_header(value, on_update=None, cls=None):
    """解析缓存控制头部。RFC定义了不同的响应和请求的缓存控制，但是这个方法并不这么做。别使用
    错误控制表达式是开发者的职责。

    .. versionadded:: 0.5
       添加`cls`。如果未被指定，则返回一个不可变的
       :class:`~werkzeug.datastructrues.RequestCacheControl对象。

    :param value: 要解析的缓存控制头。
    :param on_update: 每当:class:`~werkzeug.datastructures.CacheControl的对象上的
                      有一个值发生改变时，调用一个可选的可调用对象。
    :param cls: 返回对象的类。默认使用
                :class:`~werkzeug.datastructures.RequestCacheControl`。
    :return: 一个`cls`的对象。
    """
    if cls is None:
        cls = RequestCacheControl
    if not value:
        return cls(None, on_update)
    return cls(parse_dict_header(value), on_update)


def parse_set_header(value, on_update=None):
    """解析类似集合的头部并且返回一个:class:`~werkzeug.datastructures.HeaderSet`对象：

    >>> hs = parse_set_header('token, "quoted value"')

    返回值是一个忽略大小写并且保持每项顺序的对象：

    >>> 'TOKEN' in hs
    True
    >>> hs.index('quoted value')
    1
    >>> hs
    HeaderSet(['token', 'quoted value'])

    为了从:class:`HeaderSet`再次创建一个头部，需使用:func:`dump_header`函数。

    :param value: 被解析的一系列头部。
    :param on_update: 每当:class:`~werkzeug.datastructures.HeaderSet`的对象上的
                      有一个值发生改变时，调用一个可选的可调用对象。
    :return: 一个:class:`~werkzeug.datastructures.HeaderSet`的对象。
    """
    if not value:
        return HeaderSet(None, on_update)
    return HeaderSet(parse_list_header(value), on_update)


def parse_authorization_header(value):
    """解析浏览器发送的HTTP basic/digest 授权头部。如果头部无效或是没有给定，则返回是None，
    否则返回一个:class:`~werkzeug.datastructures.Authorization`对象。

    :param value: 要解析的授权HTTP头部
    :return: :class:`~werkzeug.datastructures.Authorization`对象或者None。
    """
    if not value:
        return
    value = wsgi_to_bytes(value)  # 字节类型数据，或是使用latin1编码后的数据
    try:
        auth_type, auth_info = value.split(None, 1)
        auth_type = auth_type.lower()
    except ValueError:
        return
    if auth_type == b"basic":
        try:
            username, password = base64.b64decode(auth_info).split(b":", 1)  # base64解码
        except Exception:
            return
        return Authorization(
            "basic",
            {
                "username": to_unicode(username, _basic_auth_charset),
                "password": to_unicode(password, _basic_auth_charset),
            },
        )
    elif auth_type == b"digest":
        auth_map = parse_dict_header(auth_info)  # 返回数据字典
        for key in "username", "realm", "nonce", "uri", "response":
            if key not in auth_map:
                return
        if "qop" in auth_map:
            if not auth_map.get("nc") or not auth_map.get("cnonce"):
                return
        return Authorization("digest", auth_map)


def parse_www_authenticate_header(value, on_update=None):
    """解析HTTP WWW-Authenticate 头部成一个
    :class:`~werkzeug.datastructures.WWWAuthenticate`对象。

    :param value: 要解析的WWW-Authenticate头部。
    :param on_update: 每当:class:`~werkzeug.datastructures.WWWAuthenticate`的对象
                      上的有一个值发生改变时，调用一个可选的可调用对象。
    :return: 一个 :class:`~werkzeug.datastructures.WWWAuthenticate` 对象。
    """
    if not value:
        return WWWAuthenticate(on_update=on_update)
    try:
        auth_type, auth_info = value.split(None, 1)
        auth_type = auth_type.lower()
    except (ValueError, AttributeError):
        return WWWAuthenticate(value.strip().lower(), on_update=on_update)
    return WWWAuthenticate(auth_type, parse_dict_header(auth_info), on_update)


def parse_if_range_header(value):
    """解析值可能是etag或者日期的if-range头部。返回一个
    :class:`~werkzeug.datastructures.IfRange`对象。

    .. versionadded:: 0.7
    """
    if not value:
        return IfRange()
    date = parse_date(value)
    if date is not None:
        return IfRange(date=date)
    # 丢弃弱信息
    return IfRange(unquote_etag(value)[0])


def parse_range_header(value):
    """解析range头部成一个:class:`~werkug.datastructures.Range`对象。如果缺少这个头部
    或是构成有问题，则返回`None`。`ranges`是一个``(start, stop)``元组的列表，元组中的范
    围都是不互相包含的。

    .. versionadded:: 0.7
    """
    if not value or "=" not in value:
        return None

    # value= "bytes=5001-10000"
    ranges = []
    last_end = 0
    units, rng = value.split("=", 1) # 'bytes', '5001-10000，10001-15000, -'
    units = units.strip().lower()

    for item in rng.split(","):
        item = item.strip()
        if "-" not in item:
            return None
        if item.startswith("-"):
            # '-15001, --15001, -abc, etc
            if last_end < 0:
                # 有待商榷的地方，假设last_end的值为None，此时会产生异常了呀
                return None
            try:
                begin = int(item)
            except ValueError:
                return None
            end = None
            last_end = -1  # -15001
        elif "-" in item:
            # 5001-10000, 10001-1500, 15001-,etc
            begin, end = item.split("-", 1)  # 5001, 10000
            begin = begin.strip()
            end = end.strip()
            if not begin.isdigit():
                return None
            begin = int(begin)
            if begin < last_end or last_end < 0:
                # 范围重叠或没有结尾
                return None
            if end:
                if not end.isdigit():
                    return None
                end = int(end) + 1
                if begin >= end:
                    return None
            else:
                # value='bytes=15001-', then end=''
                # value=bytes='5001-10000, 10001-15000, 150001-, 20000-'
                end = None
            last_end = end
        ranges.append((begin, end))

    return Range(units, ranges)


def parse_content_range_header(value, on_update=None):
    """解析一个range 头部形成一个:class:`~werkzeug.datastructures.ContentRange`对象
    或如果解析过程不可能发生，则是`None`。

    .. versionadded:: 0.7

    :param value: 被解析的内容范围头部。
    :param on_update: 每当:class:`~werkzeug.datastructures.ContentRange`的对象
                      上的有一个值发生改变时，调用一个可选的可调用对象。
    """
    # testcase
    # 1.value='bytes 0-98/*'
    # 2.value='bytes 0-98/*asdfsa'
    # 3.value='bytes 0-99/100'
    # 4.value='bytes */100'
    # 5.value='bytes 0-9o/90'
    # 6.value=None
    # 7.value='bytes /'
    # 8.value=''
    # 9.value='bytes 90'
    # 10.value='bytes 90/0'
    if value is None:
        # 6.value=None
        return None
    try:
        # 8.value=''
        units, rangedef = (value or "").strip().split(None, 1)
    except ValueError:
        return None

    if "/" not in rangedef:
        # 9.value='bytes 90'
        return None
    rng, length = rangedef.split("/", 1)
    if length == "*":
        # 1.value='bytes 0-98/*'
        length = None
    elif length.isdigit():
        length = int(length)
    else:
        # 2.value='bytes 0-98/*asdfsa'
        return None

    if rng == "*":
        # 4.value='bytes */100'
        return ContentRange(units, None, None, length, on_update=on_update)
    elif "-" not in rng:
        # 10.value='bytes 90/0'
        return None

    start, stop = rng.split("-", 1)
    try:
        start = int(start)
        stop = int(stop) + 1
    except ValueError:
        # 2.value='bytes 0-98/*asdfsa'
        # 5.value='bytes 0-9o/90'
        return None

    if is_byte_range_valid(start, stop, length):
        # 1.value='bytes 0-98/*'
        return ContentRange(units, start, stop, length, on_update=on_update)


def quote_etag(etag, weak=False):
    """引用一个etag。

    :param etag: 引用的etag。
    :param weak: 设置为`True`来表示弱标签。
    """
    if '"' in etag:
        raise ValueError("invalid etag")
    etag = '"%s"' % etag
    if weak:
        etag = "W/" + etag
    return etag


def unquote_etag(etag):
    """取消引用一个单独的etag。

    >>> unquote_etag('W/"bar"')
    ('bar', True)
    >>> unquote_etag('"bar"')
    ('bar', False)

    :param etag: 取消引用的标签标识。
    :return: 一个``(etag, weak))``元组。
    """
    if not etag:
        return None, None
    etag = etag.strip()
    weak = False
    if etag.startswith(("W/", "w/")):
        weak = True
        etag = etag[2:]
    if etag[:1] == etag[-1:] == '"':
        etag = etag[1:-1]
    return etag, weak


def parse_etags(value):
    """解析一个标签头部。

    :param value: 解析的标签头部。
    :return: 一个:class:`~werkzeug.datastructures.ETags` 对象。
    """
    if not value:
        return ETags()
    strong = []
    weak = []
    end = len(value)
    pos = 0
    while pos < end:
        # _etag_re = re.compile(r'([Ww]/)?(?:"(.*?)"|(.*?))(?:\s*,\s*|$)')
        match = _etag_re.match(value, pos)
        if match is None:
            break
        is_weak, quoted, raw = match.groups()
        if raw == "*":
            return ETags(star_tag=True)
        elif quoted:
            raw = quoted
        if is_weak:
            weak.append(raw)
        else:
            strong.append(raw)
        pos = match.end()
    return ETags(strong, weak)


def generate_etag(data):
    """为某些数据生成一个标签。"""
    return md5(data).hexdigest()


def parse_date(value):
    """解析下方日期格式之一形成datetime对象：

    .. sourcecode:: text

        Sun, 06 Nov 1994 08:49:37 GMT  ; RFC 822, updated by RFC 1123
        Sunday, 06-Nov-94 08:49:37 GMT ; RFC 850, obsoleted by RFC 1036
        Sun Nov  6 08:49:37 1994       ; ANSI C's asctime() format

    如果解析失败，返回值为`None`。

    :param value: 支持日期格式的字符串。
    :return: 一个:class:`datetime.datetime`对象。
    """
    if value:
        t = parsedate_tz(value.strip())  # 返回元组(yyyy, mm, dd, HH, MM, SS, 0, 1, -1, tzoffset)
        if t is not None:
            try:
                year = t[0]
                # 不巧的是，那个函数并没有告诉两位数的年份是字符串的一部分，或者是否使用了
                # 两个00作为前缀。因此，得假设69-99指的是1900，低于的这个范围的指的是2000。
                if year >= 0 and year <= 68:
                    year += 2000
                elif year >= 69 and year <= 99:
                    year += 1900
                return datetime(*((year,) + t[1:7])) - timedelta(seconds=t[-1] or 0)
            except (ValueError, OverflowError):
                return None


def _dump_date(d, delim):
    """用于`http_date` 和 `cookie_date`。
    >>> d = None
    >>> _dump_date(d, ' ')
    ...
    >>> from datetime import datetime
    >>> d = datetime.now()
    >>> _dump_date(d, ' ')
    ...
    >>> d = datetime.now().timestamp()
    >>> _dump_date(d, ' ')
    ...
    """
    if d is None:
        d = gmtime()  # 取当前时间并进行转换，gmtime() -> time.struct_time() 对象
    elif isinstance(d, datetime):
        d = d.utctimetuple()  # d.utctimetuple() -> time.struct_time() 对象
    elif isinstance(d, (integer_types, float)):
        d = gmtime(d)  # time.struct_time() 对象，d = datetime.datetime.now().timestamp()
    return "%s, %02d%s%s%s%s %02d:%02d:%02d GMT" % (
        ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")[d.tm_wday],
        d.tm_mday,
        delim,
        (
            "Jan",
            "Feb",
            "Mar",
            "Apr",
            "May",
            "Jun",
            "Jul",
            "Aug",
            "Sep",
            "Oct",
            "Nov",
            "Dec",
        )[d.tm_mon - 1],
        delim,
        str(d.tm_year),
        d.tm_hour,
        d.tm_min,
        d.tm_sec,
    )


def cookie_date(expires=None):
    """格式化时间以确保兼容Netscape'cookie标准。

    自从进入epoch以来，接收一个用浮点数表达的秒数，一个datetime对象或timetuple。所有的时间
    都是属于UTC。能够调用:func:`parse_date`来解析这样子的日期。

    输出格式为``Wdy, DD-Mon-YYYY HH:MM:SS GMT``的字符串。

    :param expires: 如果提供了日期，那么则使用那个日期，否则，使用当前的日期。
    """
    return _dump_date(expires, "-")


def http_date(timestamp=None):
    """格式化时间来匹配RFC1123的日期格式。

    自从进入epoch以来，接收一个用浮点数表达的秒数，一个datetime对象或timetuple。所有的时间
    都是属于UTC。能够调用:func:`parse_date`来解析这样子的日期。

    输出格式为``Wdy, DD-Mon-YYYY HH:MM:SS GMT``的字符串。

    :param timestamp: 如果提供了日期，那么则使用那个日期，否则，使用当前的日期。
    """
    return _dump_date(timestamp, " ")


def parse_age(value=None):
    """将十进制的秒数解析成timedelta。

    如果解析失败，返回值为`None`。

    :param value: 有以十为基数表示的整数构成的字符串。
    :return: 一个:class:`datetime.timedelta`对象或者为 `None`.
    """
    if not value:
        return None
    try:
        seconds = int(value)
    except ValueError:
        return None
    if seconds < 0:
        return None
    try:
        return timedelta(seconds=seconds)
    except OverflowError:
        return None


def dump_age(age=None):
    """格式化duration成以十为基数。

    :param age: 应该是整数的秒数，一个`datetime.timedelta`对象，或，如果age是未知的，
                `None`（默认值）。
    """
    if age is None:
        return
    if isinstance(age, timedelta):
        # 做和Python 2.7' timedelta.total_seconds()同样的事情，
        # 但是不用管小数位数后面的秒数
        age = age.seconds + (age.days * 24 * 3600)  # 转换成秒数

    age = int(age)
    if age < 0:
        raise ValueError("age cannot be negative")

    return str(age)


def is_resource_modified(
    environ, etag=None, data=None, last_modified=None, ignore_if_range=True
):
    """条件请求的便捷方法。

    :param environ: 被检查的请求的WSGI环境。
    :param etag: 用于比较的响应etag。
    :param data: 或是使用:func:`generate_etag`自动生成的相应数据作为另外一种选择。
    :param last_modified: 最后一次修改的的可选日期。
    :param ignore_if_range: 如果为`False`，将判断`If-Range`头部。
    :return: 如果资源被修改了，则为`True`, 否则为`False`。
    """
    if etag is None and data is not None:
        etag = generate_etag(data)
    elif data is not None:
        raise TypeError("both data and etag given")
    if environ["REQUEST_METHOD"] not in ("GET", "HEAD"):
        return False

    unmodified = False
    if isinstance(last_modified, string_types):
        last_modified = parse_date(last_modified)  # datetime object

    # 确保微秒是零，因为HTTP规范也不传输并且可能还有一些错误的整数。查阅 issue #39
    if last_modified is not None:
        last_modified = last_modified.replace(microsecond=0)

    if_range = None
    if not ignore_if_range and "HTTP_RANGE" in environ:
        # https://tools.ietf.org/html/rfc7233#section-3.2
        # 请求中不包含Range头部字段，但是服务器收到的请求中包含有If-Range头部字段，服务器
        # 必须忽略它。
        if_range = parse_if_range_header(environ.get("HTTP_IF_RANGE"))

    if if_range is not None and if_range.date is not None:
        modified_since = if_range.date
    else:
        modified_since = parse_date(environ.get("HTTP_IF_MODIFIED_SINCE"))

    if modified_since and last_modified and last_modified <= modified_since:
        unmodified = True

    if etag:
        etag, _ = unquote_etag(etag)
        if if_range is not None and if_range.etag is not None:
            unmodified = parse_etags(if_range.etag).contains(etag)
        else:
            if_none_match = parse_etags(environ.get("HTTP_IF_NONE_MATCH"))
            if if_none_match:
                # https://tools.ietf.org/html/rfc7232#section-3.2
                # “接收端必须使用弱比较函数，当为了If-None-Match而比较entity-tags的时候”
                unmodified = if_none_match.contains_weak(etag)

            # https://tools.ietf.org/html/rfc7232#section-3.1
            # “源服务器必须使用强比较函数，当为了If-Match而比较entity-tags的时候”
            if_match = parse_etags(environ.get("HTTP_IF_MATCH"))
            if if_match:
                unmodified = not if_match.is_strong(etag)

    return not unmodified


def remove_entity_headers(headers, allowed=("expires", "content-location")):
    """从一个列表或:class:`Headers`对象中移除所有的实体首部。这些操作是原地进行。
    `Expires`和`Content-Location`头部是默认被移除的。这么做的原因的是:rfc:`2616` 的
    10.3.5部分指定了应该发送的一些实体首部。

    .. versionchanged:: 0.5
       添加`allowed`参数。

    :param headers: 一个列表或:class:`Headers`对象。
    :param allowed: 仍然应该允许的头部的一个列表，即使它们是实体首部。
    """
    allowed = set(x.lower() for x in allowed)
    headers[:] = [
        (key, value)
        for key, value in headers
        if not is_entity_header(key) or key.lower() in allowed
    ]


def remove_hop_by_hop_headers(headers):
    """从一个列表或:class:`Headers`对象中移除所有的HTTP/1.1 "Hop-by-Hop"首部。
    这些操作是原地进行。

    .. versionadded:: 0.5

    :param headers: 一个列表或:class:`Headers`对象。
    """
    headers[:] = [
        (key, value) for key, value in headers if not is_hop_by_hop_header(key)
    ]


def is_entity_header(header):
    """检查一个头部是否是实体首部。

    .. versionadded:: 0.5

    :param header: 要测试的头部。
    :return: 如果是一个实体首部，则为`True`, 否则是`False`。
    """
    return header.lower() in _entity_headers


def is_hop_by_hop_header(header):
    """检查一个头部是否是一个HTTP/1.1 "Hop-by-Hop"头部。

    .. versionadded:: 0.5

    :param header: 要测试的头部。
    :return: 如果是一个HTTP/1.1 "Hop-by-Hop"头部，则为True，否则是`False`。
    """
    return header.lower() in _hop_by_hop_headers


def parse_cookie(header, charset="utf-8", errors="replace", cls=None):
    """解析cookie。cookie来自一个字符串或WSGI 环境。

    默认的编码错误是被忽略的。如果想要不同的行为，可以设置`error`为``'replace'``
    或``'strict'``。在strict模式中，将会引发:exc:`HTTPUnicodeError`异常。

    .. versionchanged:: 0.5
       现在这个函数返回一个:class:`TypeConversionDict`对象，而不是一个普通的字典。添加
       `cls`参数。

    :param header: 用来解析cookie的头部。WSGI环境能够作为备选。
    :param charset: cookie值的字符集。
    :param errors: 使用字符集解码时的错误行为。
    :param cls: 可供选择使用的字典类。如果没有制定或者是`None`，则使用默认的
                :class:`TypeConversionDict`.
    """
    if isinstance(header, dict):
        header = header.get("HTTP_COOKIE", "")
    elif header is None:
        header = ""

    # 如果这个值是unicode字符串，则使用latin1进行编码。因为在Python 3 的 PEP 3333中，
    # 所有头部都假设使用的是latin字符集，然而对于cookie来说，这是不正确的，cookie在页面
    # 编码中被发送。
    if isinstance(header, text_type):
        header = header.encode("latin1", "replace")

    if cls is None:
        cls = TypeConversionDict

    def _parse_pairs():
        """生成器函数，生成cookie的键值元组。"""
        for key, val in _cookie_parse_impl(header):
            key = to_unicode(key, charset, errors, allow_none_charset=True)
            if not key:
                continue
            val = to_unicode(val, charset, errors, allow_none_charset=True)
            yield try_coerce_native(key), val

    return cls(_parse_pairs())


def dump_cookie(
    key,
    value="",
    max_age=None,
    expires=None,
    path="/",
    domain=None,
    secure=False,
    httponly=False,
    charset="utf-8",
    sync_expires=True,
    max_size=4093,
    samesite=None,
):
    """Creates a new Set-Cookie header without the ``Set-Cookie`` prefix
    The parameters are the same as in the cookie Morsel object in the
    Python standard library but it accepts unicode data, too.

    On Python 3 the return value of this function will be a unicode
    string, on Python 2 it will be a native string.  In both cases the
    return value is usually restricted to ascii as the vast majority of
    values are properly escaped, but that is no guarantee.  If a unicode
    string is returned it's tunneled through latin1 as required by
    PEP 3333.

    The return value is not ASCII safe if the key contains unicode
    characters.  This is technically against the specification but
    happens in the wild.  It's strongly recommended to not use
    non-ASCII values for the keys.

    :param max_age: should be a number of seconds, or `None` (default) if
                    the cookie should last only as long as the client's
                    browser session.  Additionally `timedelta` objects
                    are accepted, too.
    :param expires: should be a `datetime` object or unix timestamp.
    :param path: limits the cookie to a given path, per default it will
                 span the whole domain.
    :param domain: Use this if you want to set a cross-domain cookie. For
                   example, ``domain=".example.com"`` will set a cookie
                   that is readable by the domain ``www.example.com``,
                   ``foo.example.com`` etc. Otherwise, a cookie will only
                   be readable by the domain that set it.
    :param secure: The cookie will only be available via HTTPS
    :param httponly: disallow JavaScript to access the cookie.  This is an
                     extension to the cookie standard and probably not
                     supported by all browsers.
    :param charset: the encoding for unicode values.
    :param sync_expires: automatically set expires if max_age is defined
                         but expires not.
    :param max_size: Warn if the final header value exceeds this size. The
        default, 4093, should be safely `supported by most browsers
        <cookie_>`_. Set to 0 to disable this check.
    :param samesite: Limits the scope of the cookie such that it will only
                     be attached to requests if those requests are "same-site".

    .. _`cookie`: http://browsercookielimits.squawky.net/
    """
    key = to_bytes(key, charset)
    value = to_bytes(value, charset)

    if path is not None:
        path = iri_to_uri(path, charset)
    domain = _make_cookie_domain(domain)
    if isinstance(max_age, timedelta):
        max_age = (max_age.days * 60 * 60 * 24) + max_age.seconds
    if expires is not None:
        if not isinstance(expires, string_types):
            expires = cookie_date(expires)
    elif max_age is not None and sync_expires:
        expires = to_bytes(cookie_date(time() + max_age))

    samesite = samesite.title() if samesite else None
    if samesite not in ("Strict", "Lax", None):
        raise ValueError("invalid SameSite value; must be 'Strict', 'Lax' or None")

    buf = [key + b"=" + _cookie_quote(value)]

    # XXX: In theory all of these parameters that are not marked with `None`
    # should be quoted.  Because stdlib did not quote it before I did not
    # want to introduce quoting there now.
    for k, v, q in (
        (b"Domain", domain, True),
        (b"Expires", expires, False),
        (b"Max-Age", max_age, False),
        (b"Secure", secure, None),
        (b"HttpOnly", httponly, None),
        (b"Path", path, False),
        (b"SameSite", samesite, False),
    ):
        if q is None:
            if v:
                buf.append(k)
            continue

        if v is None:
            continue

        tmp = bytearray(k)
        if not isinstance(v, (bytes, bytearray)):
            v = to_bytes(text_type(v), charset)
        if q:
            v = _cookie_quote(v)
        tmp += b"=" + v
        buf.append(bytes(tmp))

    # The return value will be an incorrectly encoded latin1 header on
    # Python 3 for consistency with the headers object and a bytestring
    # on Python 2 because that's how the API makes more sense.
    rv = b"; ".join(buf)
    if not PY2:
        rv = rv.decode("latin1")

    # Warn if the final value of the cookie is less than the limit. If the
    # cookie is too large, then it may be silently ignored, which can be quite
    # hard to debug.
    cookie_size = len(rv)

    if max_size and cookie_size > max_size:
        value_size = len(value)
        warnings.warn(
            'The "{key}" cookie is too large: the value was {value_size} bytes'
            " but the header required {extra_size} extra bytes. The final size"
            " was {cookie_size} bytes but the limit is {max_size} bytes."
            " Browsers may silently ignore cookies larger than this.".format(
                key=key,
                value_size=value_size,
                extra_size=cookie_size - value_size,
                cookie_size=cookie_size,
                max_size=max_size,
            ),
            stacklevel=2,
        )

    return rv


def is_byte_range_valid(start, stop, length):
    """根据长度检查给定的字节内容范围是否有效。

    .. versionadded:: 0.7
    """
    if (start is None) != (stop is None):
        # either start is None or stop is None
        return False
    elif start is None:
        return length is None or length >= 0
    elif length is None:
        return 0 <= start < stop
    elif start >= stop:
        return False
    return 0 <= start < length


# circular dependency fun
from .datastructures import Accept
from .datastructures import Authorization
from .datastructures import ContentRange
from .datastructures import ETags
from .datastructures import HeaderSet
from .datastructures import IfRange
from .datastructures import Range
from .datastructures import RequestCacheControl
from .datastructures import TypeConversionDict
from .datastructures import WWWAuthenticate
from .urls import iri_to_uri
