# -*- coding: utf-8 -*-
"""
    werkzeug.wsgi
    ~~~~~~~~~~~~~

    这个模块实现WSGI相关的助手函数

    :copyright: 2007 Pallets
    :license: BSD-3-Clause
"""
import io
import re
from functools import partial
from functools import update_wrapper
from itertools import chain

from ._compat import BytesIO
from ._compat import implements_iterator
from ._compat import make_literal_wrapper
from ._compat import string_types
from ._compat import text_type
from ._compat import to_bytes
from ._compat import to_unicode
from ._compat import try_coerce_native
from ._compat import wsgi_get_bytes
from ._internal import _encode_idna
from .urls import uri_to_iri
from .urls import url_join
from .urls import url_parse
from .urls import url_quote


def responder(f):
    """标记一个函数为响应器。使用它来装饰一个函数并且自动的将函数的返回值视作WSGI应用程序。
    
    例子::

        @responder
        def application(environ, start_response):
            return Response('Hello World!')
    """
    # update_wrapper(wrapper, wrapped)
    # wrapper 是一个被更新的函数
    # wrapped 是原始函数
    return update_wrapper(lambda *a: f(*a)(*a[-2:]), f)


def get_current_url(
    environ,
    root_only=False,
    strip_querystring=False,
    host_only=False,
    trusted_hosts=None,
):
    """一个给当前请求或部分请求而重新创建完整URL形成IRI的快捷助手函数。举个例子：
    
    >>> from werkzeug.test import create_environ
    >>> env = create_environ("/?param=foo", "http://localhost/script")
    >>> get_current_url(env)
    'http://localhost/script/?param=foo'
    >>> get_current_url(env, root_only=True)
    'http://localhost/script/'
    >>> get_current_url(env, host_only=True)
    'http://localhost/'
    >>> get_current_url(env, strip_querystring=True)
    'http://localhost/script/'

    验证主机是否在可信任的主机里面，这是可选的。如果这个主机不再那里面，将会引发一个
    :exc:`~werkzeug.exceptions.SecurityError`一场。

    注意这个返回的字符串可能包含unicode字符，因为表现形式是IRI而不知URI。如果只需要ASCII
    表示形式，可以使用:func:`~werkzeug.urls.iri_to_uri` 函数：

    >>> from werkzeug.urls import iri_to_uri
    >>> iri_to_uri(get_current_url(env))
    'http://localhost/script/?param=foo'

    :param environ: 可以从中获取当前URL的WSGI环境变量
    :param root_only: 如果只想获取根URL，设置为`True`
    :param strip_querystring: 不想要查询字符串，可以设置为`True`
    :param host_only: 如果返回主机URL，设置为`True`
    :param trusted_hosts: 可信任主机列表，更多信息查看:func:`host_is_trusted`
    """
    tmp = [environ["wsgi.url_scheme"], "://", get_host(environ, trusted_hosts)]
    cat = tmp.append
    if host_only:
        # 返回主机地址
        return uri_to_iri("".join(tmp) + "/")
    cat(url_quote(wsgi_get_bytes(environ.get("SCRIPT_NAME", ""))).rstrip("/"))  # 往列表中添加脚本名字或空字符串，并将字符串转换成符合URL格式的字符串
    cat("/")  # 末尾添加反斜杠
    if not root_only:
        cat(url_quote(wsgi_get_bytes(environ.get("PATH_INFO", "")).lstrip(b"/")))  # 获取请求路径并将路径最左边斜杠去掉，并将该字符串转换成为符合URL格式的字符串
        if not strip_querystring:
            # 获取URL中的查询字符串
            qs = get_query_string(environ)
            if qs:
                cat("?" + qs)
    # 连接成字符串，转换成IRI格式的字符串
    return uri_to_iri("".join(tmp))


def host_is_trusted(hostname, trusted_list):
    """检查一个主机地址是否不在一个主机列表中。还考虑到了端口。

    .. versionadded:: 0.9

    :param hostname: 要检查的主机名字
    :param trusted_list: 用于核对的主机名列表。如果主机名以点号开头，将会匹配所有的子域名。
    """
    if not hostname:
        return False

    if isinstance(trusted_list, string_types):
        trusted_list = [trusted_list]

    def _normalize(hostname):
        if ":" in hostname:
            # 取第一个冒号之前的字符串
            hostname = hostname.rsplit(":", 1)[0]
        return _encode_idna(hostname)

    try:
        # 将主机名规范化
        hostname = _normalize(hostname)
    except UnicodeError:
        return False
    for ref in trusted_list:
        if ref.startswith("."):
            ref = ref[1:]
            suffix_match = True
        else:
            suffix_match = False
        try:
            ref = _normalize(ref)
        except UnicodeError:
            return False
        if ref == hostname:
            return True
        if suffix_match and hostname.endswith(b"." + ref):
            return True
    return False


def get_host(environ, trusted_hosts=None):
    """根据给定的WSGI环境变量，获取主机并返回。这是第一次检测HTTP协议中的``Host``头部。
    如果不存在，那么使用``SERVER_NAME``和 ``SERVER_PORT``。如果与协议的标准端口不一样，
    这个主机将只包含端口。

    可选择使用:func:`host_is_trusted`来验证返回的主机，并且如果不是可信任的主机，则引发
    :exc:`~werkzeug.exceptions.SecurityError`异常。

    :param environ: 获取主机名的WSGI环境变量。
    :param trusted_hosts: 一个可信任的主机列表。
    :return: 主机名，如果有必要的话，带上端口号。
    :raise ~werkzeug.exceptions.SecurityError: 如果主机不可信任。
    """
    if "HTTP_HOST" in environ:
        rv = environ["HTTP_HOST"]
        if environ["wsgi.url_scheme"] == "http" and rv.endswith(":80"):
            rv = rv[:-3]
        elif environ["wsgi.url_scheme"] == "https" and rv.endswith(":443"):
            rv = rv[:-4]
    else:
        rv = environ["SERVER_NAME"]
        if (environ["wsgi.url_scheme"], environ["SERVER_PORT"]) not in (
            ("https", "443"),
            ("http", "80"),
        ):
            rv += ":" + environ["SERVER_PORT"]
    if trusted_hosts is not None:
        if not host_is_trusted(rv, trusted_hosts):
            from .exceptions import SecurityError

            raise SecurityError('Host "%s" is not trusted' % rv)
    return rv


def get_content_length(environ):
    """从WSGI环境变量中获取内容长度，作为一个整形类型的值进行返回。如果它不可用或者使用了
    分块传输编码，则返回``None``.

    .. versionadded:: 0.9

    :param environ: 从中的获取的内容长度的的WSGI环境变量。
    """
    if environ.get("HTTP_TRANSFER_ENCODING", "") == "chunked":
        return None

    content_length = environ.get("CONTENT_LENGTH")
    if content_length is not None:
        try:
            return max(0, int(content_length))
        except (ValueError, TypeError):
            pass


def get_input_stream(environ, safe_fallback=True):
    """从WSGI中返回输入流并且用可能最合理的方式进行包装它。大多数情况下，返回的流不是原来
    的WSGI流，但是一个确认的事情是不用考虑内容长度，可以从该输入流中安全的读取数据。
    

    如果内容长度没有设置，出于安全的考虑，这个流将会是空的。如果WSGI服务器支持分块或者无线流，
    那么它应该在WSGI环境中设置``wsgi.input_terminated``的值来暗示。

    .. versionadded:: 0.9

    :param environ: 从中获取流的WSGI环境变量
    :param safe_fallback: 当HTTP头中的内容长度没有设置的时候，使用空流作为安全的值。
    关闭这个将会允许无限流，这可能会出现拒绝式服务（denial-of-service）的风险。
    """
    stream = environ["wsgi.input"]
    content_length = get_content_length(environ)

    # wsgi 扩展告诉是否这个输入可以被终止。这种情况下，我们可以返回未改变的流，因为可以进行
    # 安全地读取直到结束。
    if environ.get("wsgi.input_terminated"):
        return stream

    # 如果请求没有指定内容长度，将要返回的流是存在潜在的危险的，因为它可能是无限，恶意也可能不是。
    # 如果safe_fallback 为 true，为了安全，得返回空流。
    if content_length is None:
        return BytesIO() if safe_fallback else stream

    # 否则限制流的内容长度
    return LimitedStream(stream, content_length)


def get_query_string(environ):
    """从WSGI环境变量中获取`QUERY_STRING`并返回。这也考虑到了Python3 环境中作为原始字符
    串的WSGI解码操作。返回的字符串被限制为只包含ASCII字符。

    .. versionadded:: 0.9

    :param environ: 从中获取查询字符串的WSGI环境变量。
    """
    qs = wsgi_get_bytes(environ.get("QUERY_STRING", ""))
    # QUERY_STRING 应该是ascii字符，但是一些浏览器会发送一些unicode的东西（比如IE）。
    # 在那种情况下，我们想要urllib糟糕地引用。
    return try_coerce_native(url_quote(qs, safe=":&%=+$!*'(),"))


def get_path_info(environ, charset="utf-8", errors="replace"):
    """从WSGI环境变量中获取`PATH_INFO`并返回它并且适当地对它进行编码。这也考虑到了在
    Python3 环境上WSGI的编码操作。如果`charset`设置为`None`，则返回bytestring。

    .. versionadded:: 0.9

    :param environ: 从中获取路径的WSGI环境对象。
    :param charset: 解码路径信息使用的字符集，或者如果无需解码，则为`None`。
    :param errors: 解码的错误处理。
    """
    path = wsgi_get_bytes(environ.get("PATH_INFO", ""))
    return to_unicode(path, charset, errors, allow_none_charset=True)


def get_script_name(environ, charset="utf-8", errors="replace"):
    """从WSGI环境变量中获取并返回`SCRIPT_NAME`并且适当地进行解码。也考虑了Python3环境上的
    WSGI的解码操作。如果`charset`设置为`None`，则返回bytestring。

    .. versionadded:: 0.9

    :param environ: 从中获取路径的环境变量对象。
    :param charset: 解码路径使用的字符集，或者如果无需解码，则为`None`。
    :param errors: 解码的错误处理。
    """
    path = wsgi_get_bytes(environ.get("SCRIPT_NAME", ""))
    return to_unicode(path, charset, errors, allow_none_charset=True)


def pop_path_info(environ, charset="utf-8", errors="replace"):
    """移除并返回下一个`PATH_INFO`的分段，将其连接到`SCRIPT_NAME`后面。如果`PATH_INFO`
    为空，则返回`None`。

    如果`charset`设置为`None`，则返回bytestring。

    如果有空的分段，忽略它们，但是适当地与`SCRIPT_NAME`进行连接：

    >>> env = {'SCRIPT_NAME': '/foo', 'PATH_INFO': '/a/b'}
    >>> pop_path_info(env)
    'a'
    >>> env['SCRIPT_NAME']
    '/foo/a'
    >>> pop_path_info(env)
    'b'
    >>> env['SCRIPT_NAME']
    '/foo/a/b'

    .. versionadded:: 0.5

    .. versionchanged:: 0.9
       路径现在是编码过后的并且提供字符集和编码参数。

    :param environ: 被修改的WSGI环境变量。
    """
    path = environ.get("PATH_INFO")
    if not path:
        return None

    script_name = environ.get("SCRIPT_NAME", "")

    # shift multiple leading slashes over
    old_path = path
    path = path.lstrip("/")
    if path != old_path:
        script_name += "/" * (len(old_path) - len(path))

    if "/" not in path:
        environ["PATH_INFO"] = ""
        environ["SCRIPT_NAME"] = script_name + path
        rv = wsgi_get_bytes(path)
    else:
        segment, path = path.split("/", 1)
        environ["PATH_INFO"] = "/" + path
        environ["SCRIPT_NAME"] = script_name + segment
        rv = wsgi_get_bytes(segment)

    return to_unicode(rv, charset, errors, allow_none_charset=True)


def peek_path_info(environ, charset="utf-8", errors="replace"):
    """返回`PATH_INFO`的下一个分段或者如果PATH_INFO为空的话，返回`None`。
    像:func:`pop_path_info`一样的功能，但是不修改环境变量的内容：

    >>> env = {'SCRIPT_NAME': '/foo', 'PATH_INFO': '/a/b'}
    >>> peek_path_info(env)
    'a'
    >>> peek_path_info(env)
    'a'

    如果设置`charset`为`None`，则返回bytestring。

    .. versionadded:: 0.5

    .. versionchanged:: 0.9
       现在路径是编码后的并且提供字符集和编码参数。

    :param environ: 需要检查的WSGI环境变量。
    """
    # 取出开头的反斜杠，并分割字符串一次，最后生成一个列表。
    segments = environ.get("PATH_INFO", "").lstrip("/").split("/", 1)
    if segments:
        return to_unicode(
            wsgi_get_bytes(segments[0]), charset, errors, allow_none_charset=True
        )


def extract_path_info(
    environ_or_baseurl,
    path_or_url,
    charset="utf-8",
    errors="werkzeug.url_quote",
    collapse_http_schemes=True,
):
    """从给定的URL（或WSGI环境）和路径中中提取出路径信息。返回的路径信息是unicode字符串，
    不是适合于WSGI环境的bytestring。URLs也有可能是IRIs。

    如果路径信息不能确定，则返回`None`。

    一些例子:

    >>> extract_path_info('http://example.com/app', '/app/hello')
    u'/hello'
    >>> extract_path_info('http://example.com/app',
    ...                   'https://example.com/app/hello')
    u'/hello'
    >>> extract_path_info('http://example.com/app',
    ...                   'https://example.com/app/hello',
    ...                   collapse_http_schemes=False) is None
    True

    你也可以传递WSGI环境而不是提供一个基地址（base url）。

    :param environ_or_baseurl: 一个WSGI环境字典，基地址或基IRI。这是应用的根目录。
    :param path_or_url: 来自服务器根的绝对路径，相对路径（这种情况下就是WSGI中的
                        PATH INFO）或者完整的URL。还可接收IRIs和unicode参数。
    :param charset: 用于URLs中字节数据的字符集
    :param errors: 解码时错误处理
    :param collapse_http_schemes: 如果设置为`False`，算法并不假设http和https指向在
                                  相同服务器上相同的资源。

    .. versionchanged:: 0.15
        ``errors``参数默认为留下的无效的字节引用而不是替换他们。

    .. versionadded:: 0.6
    """

    def _normalize_netloc(scheme, netloc):
        """使网络地址变得符合规范
        """
        parts = netloc.split(u"@", 1)[-1].split(u":", 1)
        if len(parts) == 2:
            netloc, port = parts
            if (scheme == u"http" and port == u"80") or (
                scheme == u"https" and port == u"443"
            ):
                port = None
        else:
            netloc = parts[0]
            port = None
        if port is not None:
            netloc += u":" + port
        return netloc

    # 确保无论我们处理什么都能够是IRI并且对它进行解析
    path = uri_to_iri(path_or_url, charset, errors)
    if isinstance(environ_or_baseurl, dict):
        environ_or_baseurl = get_current_url(environ_or_baseurl, root_only=True)
    base_iri = uri_to_iri(environ_or_baseurl, charset, errors)
    # 从url中解析出网络协议，基网络地址，基路径
    base_scheme, base_netloc, base_path = url_parse(base_iri)[:3]
    cur_scheme, cur_netloc, cur_path, = url_parse(url_join(base_iri, path))[:3]

    # 使网络地址变得规范
    base_netloc = _normalize_netloc(base_scheme, base_netloc)
    cur_netloc = _normalize_netloc(cur_scheme, cur_netloc)

    # IRI是不是在已知的HTTP方案
    if collapse_http_schemes:
        for scheme in base_scheme, cur_scheme:
            if scheme not in (u"http", u"https"):
                return None
    else:
        if not (base_scheme in (u"http", u"https") and base_scheme == cur_scheme):
            return None

    # 网络地址兼容吗？
    if base_netloc != cur_netloc:
        return None

    # 是不是在应用路径之下？
    base_path = base_path.rstrip(u"/")
    if not cur_path.startswith(base_path):
        return None

    return u"/" + cur_path[len(base_path) :].lstrip(u"/")


@implements_iterator
class ClosingIterator(object):
    """WSGI规范要求所有的中间件和网关遵守应用返回的可迭代对象的`close`回调。
    因为往一个返回的可迭代对象添加另一个关闭操作很有用并且添加可自定义的可迭代对象是一项枯燥的
    任务，这个类可以这样子使用：

        return ClosingIterator(app(environ, start_response), [cleanup_session,
                                                              cleanup_locals])

    如果只有一个关闭（close）函数而不是这个列表可以被传递。

    如果应用使用响应对象则不需要一个关闭的迭代器并且如果开始响应了，则结束处理过程：

        try:
            return response(environ, start_response)
        finally:
            cleanup_session()
            cleanup_locals()
    """

    def __init__(self, iterable, callbacks=None):
        iterator = iter(iterable)
        self._next = partial(next, iterator)
        if callbacks is None:
            callbacks = []
        elif callable(callbacks):
            callbacks = [callbacks]
        else:
            callbacks = list(callbacks)
        iterable_close = getattr(iterable, "close", None)
        if iterable_close:
            callbacks.insert(0, iterable_close)
        self._callbacks = callbacks

    def __iter__(self):
        return self

    def __next__(self):
        return self._next()

    def close(self):
        for callback in self._callbacks:
            callback()


def wrap_file(environ, file, buffer_size=8192):
    """包装一个文件。如果可用，则使用WSGI服务器的文件包装器，否则使用通用类
    :class:`FileWrapper`。

    .. versionadded:: 0.5

    如果使用的是WSGI服务器的文件包装器，重要的是不要从应用内部进行迭代它而是保持不变地传递它。
    如果想在一个响应对象内部往外传一个文件包装器，那么得设置
    :attr:`~BaseResponse.direct_passthrough` 为True。

    更多信息关于文件包装器查看:pep:`333`。

    :param file: 一个含有:meth:`~file.read`方法的:class:`file-like`的对象。
    :param buffer_size: 一次迭代的字节数量。
    """
    return environ.get("wsgi.file_wrapper", FileWrapper)(file, buffer_size)


@implements_iterator
class FileWrapper(object):
    """这个类用于将一个:class:`file-like`对象转换成一个可迭代对象。它生成`buffer_size`
    块知道文件完成地读取完。

    不应该直接使用这个类，而是如果WSGI服务器的文件包装器可用，则使用能够调用WSGI服务器提供的文件
    包装器的:func:`wrap_file`函数。

    .. versionadded:: 0.5

    如果将这个对象和:class:`BaseResponse`一起使用，得使用`direct_passthrough`模式。

    :param file: 一个有:meth:`~file.read`方法的相似于:class:`file`的对象。
    :param buffer_size: 一次迭代的字节数量。
    """

    def __init__(self, file, buffer_size=8192):
        self.file = file
        self.buffer_size = buffer_size

    def close(self):
        if hasattr(self.file, "close"):
            self.file.close()

    def seekable(self):
        if hasattr(self.file, "seekable"):
            return self.file.seekable()
        if hasattr(self.file, "seek"):
            return True
        return False

    def seek(self, *args):
        if hasattr(self.file, "seek"):
            self.file.seek(*args)

    def tell(self):
        if hasattr(self.file, "tell"):
            return self.file.tell()
        return None

    def __iter__(self):
        return self

    def __next__(self):
        data = self.file.read(self.buffer_size)
        if data:
            return data
        raise StopIteration()


@implements_iterator
class _RangeWrapper(object):
    # 现在为私有类，但是未来是否应该公开？

    """这个类用来将一个可迭代对象转换成一个只生成一小部分底层内容的可迭代对象。一直生成块直到
    完整地读取完底层流范围。生成的块大小不能超过初始迭代器定义的块大小，但是可小于。

    如果将这个对象和:class:`BaseResponse`一起使用，那得设置`direct_passthrough`模式。

    :param iterable: 含有:meth:`__next__`方法的可迭代对象。
    :param start_byte: 开始读取的字节
    :param byte_range: 要读取的字节数量。
    """

    def __init__(self, iterable, start_byte=0, byte_range=None):
        self.iterable = iter(iterable)
        self.byte_range = byte_range
        self.start_byte = start_byte
        self.end_byte = None
        if byte_range is not None:
            self.end_byte = self.start_byte + self.byte_range
        self.read_length = 0
        self.seekable = hasattr(iterable, "seekable") and iterable.seekable()
        self.end_reached = False

    def __iter__(self):
        return self

    def _next_chunk(self):
        try:
            chunk = next(self.iterable)
            self.read_length += len(chunk)
            return chunk
        except StopIteration:
            self.end_reached = True
            raise

    def _first_iteration(self):
        # 首次从迭代对象读取数据
        chunk = None
        if self.seekable:
            self.iterable.seek(self.start_byte)
            self.read_length = self.iterable.tell()  # 已经读取的长度
            contextual_read_length = self.read_length  # 读取的上下文长度
        else:
            while self.read_length <= self.start_byte:
                chunk = self._next_chunk()
            if chunk is not None:
                chunk = chunk[self.start_byte - self.read_length :]
            contextual_read_length = self.start_byte
        # 读取的块，读取的上下文长度
        return chunk, contextual_read_length

    def _next(self):
        if self.end_reached:
            raise StopIteration()
        chunk = None
        contextual_read_length = self.read_length
        if self.read_length == 0:
            # 第一次读取数据
            chunk, contextual_read_length = self._first_iteration()
        if chunk is None:
            # 读取下一块
            chunk = self._next_chunk()
        if self.end_byte is not None and self.read_length >= self.end_byte:
            # 读取迭代对象的末尾了
            # 假设read_length = 5, end_byte = 5，此时读取的上下文长度
            # contextual_read_length为 为 4。
            self.end_reached = True
            return chunk[: self.end_byte - contextual_read_length]
        return chunk

    def __next__(self):
        chunk = self._next()
        if chunk:
            return chunk
        self.end_reached = True
        raise StopIteration()

    def close(self):
        if hasattr(self.iterable, "close"):
            self.iterable.close()


def _make_chunk_iter(stream, limit, buffer_size):
    """用于行和块迭代函数的生成器辅助。"""
    if isinstance(stream, (bytes, bytearray, text_type)):
        raise TypeError(
            "Passed a string or byte object instead of true iterator or stream."
        )
    if not hasattr(stream, "read"):
        for item in stream:
            if item:
                yield item
        return
    if not isinstance(stream, LimitedStream) and limit is not None:
        stream = LimitedStream(stream, limit)
    _read = stream.read
    while 1:
        item = _read(buffer_size)
        if not item:
            break
        yield item


def make_line_iter(stream, limit=None, buffer_size=10 * 1024, cap_at_buffer=False):
    """安全地按行迭代输入流。如果输入流不是:class:`LimitedStream`的对象，那么参数`limit`
    是要强制进行赋值的。

    内部地使用流的:meth:`~file.read`而不是不安全的:meth:`~file.readine`方法并且只能在违
    反WSGI规范的时候使用。同样的问题也适用于会调用没有参数的:meth:`~file.readline`方法的
    输入流的`__iter__`函数。

    如果需要一行接一行地处理，强烈推荐使用这个辅助函数来迭代输入流。

    .. versionchanged:: 0.8
       这个函数现在确保这个限制是可以到达的。

    .. versionadded:: 0.9
       添加支持输入流的迭代器。

    .. versionadded:: 0.11.10
       添加`cap_at_buffer`参数支持。

    :param stream: 迭代的流或可迭代对象。
    :param limit: 限制流的字节。（通常是内容的长度。如果`stream`是
                  :class:`LimitedStream`的类型，那么就没有必要。）
    :param buffer_size: 可选的缓冲区大小。
    :param cap_at_buffer: 如果设置了这个参数，那么如果块的长度长过缓冲区大小，块将会被分割。
                          然而，内部实现的缓冲区大小可能被消耗两倍。
    """
    _iter = _make_chunk_iter(stream, limit, buffer_size)  # 生成器

    first_item = next(_iter, "")
    if not first_item:
        return

    s = make_literal_wrapper(first_item)
    empty = s("")
    cr = s("\r")
    lf = s("\n")
    crlf = s("\r\n")

    _iter = chain((first_item,), _iter)

    def _iter_basic_lines():
        _join = empty.join
        buffer = []
        while 1:
            new_data = next(_iter, "")
            if not new_data:
                # new_data = ""
                break
            new_buf = []
            buf_size = 0
            # str.splitlines(True) 按行（根据换行符）进行分割，返回一个列表，True为保留换行符，空或
            # False则不保留，使用''代替原来的换行符。
            for item in chain(buffer, new_data.splitlines(True)):
                new_buf.append(item)
                buf_size += len(item)
                if item and item[-1:] in crlf:
                    yield _join(new_buf)
                    new_buf = []
                elif cap_at_buffer and buf_size >= buffer_size:
                    rv = _join(new_buf)
                    while len(rv) >= buffer_size:
                        yield rv[:buffer_size]
                        rv = rv[buffer_size:]
                    new_buf = [rv]
            buffer = new_buf
        if buffer:
            yield _join(buffer)

    # 如果不凑巧，到达了块的边界，有必要将'foo\r'和'\n'两个合并成一个'foo\r\n'。
    previous = empty
    for item in _iter_basic_lines():
        if item == lf and previous[-1:] == cr:
            previous += item
            item = empty
        if previous:
            yield previous
        previous = item
    if previous:
        yield previous


def make_chunk_iter(
    stream, separator, limit=None, buffer_size=10 * 1024, cap_at_buffer=False
):
    """功能类似于:func:`make_line_iter`，但是接收多接手一个分割块的分割符。如果想基于新行
    处理，则应该使用:func:`make_line_iter`来代替，因为它支持任意的换行标记。

    .. versionadded:: 0.8

    .. versionadded:: 0.9
       添加支持输入流的迭代器。

    .. versionadded:: 0.11.10
       添加`cap_at_buffer`参数。

    :param stream: 要迭代的流或可迭代对象
    :param separator: 分割块的分割符。
    :param limit: 流的限制字节。（通常是内容的长度。否则如果流已经被限制了，
                  那么就没有必要了。）
    :param buffer_size: 可选的缓冲区大小。
    :param cap_at_buffer: 如果设置了这个参数，如果块的长度大于缓冲区大小，块会被分割。
                          内部实现的缓冲区大小可能被消耗两倍。if this is set chunks are split if they are longer
                          than the buffer size.  Internally this is implemented
                          that the buffer size might be exhausted by a factor
                          of two however.
    """
    _iter = _make_chunk_iter(stream, limit, buffer_size)  # 迭代器

    first_item = next(_iter, "")  # 取第一块，或者等于""
    if not first_item:
        return

    _iter = chain((first_item,), _iter)
    if isinstance(first_item, text_type):
        # str 类型
        separator = to_unicode(separator)  # 编码分割符
        _split = re.compile(r"(%s)" % re.escape(separator)).split
        _join = u"".join
    else:
        separator = to_bytes(separator)  # 转成字节类型
        _split = re.compile(b"(" + re.escape(separator) + b")").split
        _join = b"".join

    buffer = []
    while 1:
        new_data = next(_iter, "")
        if not new_data:
            break
        chunks = _split(new_data)
        new_buf = []
        buf_size = 0
        for item in chain(buffer, chunks):
            if item == separator:
                yield _join(new_buf)
                new_buf = []
                buf_size = 0
            else:
                buf_size += len(item)
                new_buf.append(item)

                if cap_at_buffer and buf_size >= buffer_size:
                    rv = _join(new_buf)
                    while len(rv) >= buffer_size:
                        yield rv[:buffer_size]
                        rv = rv[buffer_size:]
                    new_buf = [rv]
                    buf_size = len(rv)

        buffer = new_buf
    if buffer:
        yield _join(buffer)


@implements_iterator
class LimitedStream(io.IOBase):
    """包转一个流，为的是它不让它读取超过n个字节。如果流读取完了并且调用方尝试从中获取更多的
    字节，则调用默认返回空字符串的:func:`on_exhausted`。这个函数的返回值转发给读取函数。
    所以如果返回空字符串，则:meth:`read`也会返回空字符串。

    但是，这个限制必须小于或等于这个流能够输出的。否则:meth:`realines`将尝试读取超过这个限制的流。

    .. admonition:: 注意WSGI兼容性

       调用:meth:`realine` 和 :meth:`readlines` 是不兼容的，因为需要向readline方法传
       递一个size参数。不巧的是，WSGI PEP没有安全地实现没有size参数的:meth:`readline`，
       因为在流中没有EOF标记器。因此，不鼓励使用:meth:`readline`方法。

       考虑到相同的原因，迭代:class:`LimitedStream`不是可移植的。它的内部调用了
       :meth:`readline`。

       强烈建议使用:meth:`read` 或者使用安全地按行进行迭代WSGI输入流的
       :func:`make_line_iter`。

    :param stream: 要包装的流
    :param limit: 流的限制，如果流的末尾没有`EOF`（比如`wsgi.input`），禁止读取流的限制
    长度长于字符串所能提供的。
    """

    def __init__(self, stream, limit):
        self._read = stream.read
        self._readline = stream.readline
        self._pos = 0
        self.limit = limit

    def __iter__(self):
        return self

    @property
    def is_exhausted(self):
        """如果流读取完了，这个属性的值为`True`。"""
        return self._pos >= self.limit

    def on_exhausted(self):
        """当流尝试读取超过限制的时候，调用这个方法。这个函数的返回值由读取函数进行返回。
        """
        #读取空字节为的是可以获取到正确的流标记结尾。
        return self._read(0)

    def on_disconnect(self):
        """如果断开链接被探测到，应该发生什么？万一客户端断开了，这个函数的返回值由读取函数
        返回。默认引发:exc:`~werkzeug.exceptions.ClientDisconnected`异常。
        """
        from .exceptions import ClientDisconnected

        raise ClientDisconnected()

    def exhaust(self, chunk_size=1024 * 64):
        """读取流。读取所有剩下来的数据直到到达限制的值。

        :param chunk_size: 块的大小。读取块直到流被读取完并且返回结果。
        """
        to_read = self.limit - self._pos
        chunk = chunk_size
        while to_read > 0:
            chunk = min(to_read, chunk)
            self.read(chunk)
            to_read -= chunk

    def read(self, size=None):
        """读取字节的数量或如果size为None，读取所有的内容。

        :param size: 读取的字节数量。
        """
        if self._pos >= self.limit:
            return self.on_exhausted()
        if size is None or size == -1:  # -1 是为了与文件一致
            size = self.limit
        to_read = min(self.limit - self._pos, size)
        try:
            read = self._read(to_read)
        except (IOError, ValueError):
            return self.on_disconnect()
        if to_read and len(read) != to_read:
            return self.on_disconnect()
        self._pos += len(read)
        return read

    def readline(self, size=None):
        """从流中读取一行。"""
        if self._pos >= self.limit:
            return self.on_exhausted()
        if size is None:
            size = self.limit - self._pos
        else:
            size = min(size, self.limit - self._pos)
        try:
            line = self._readline(size)
        except (ValueError, IOError):
            return self.on_disconnect()
        if size and not line:
            return self.on_disconnect()
        self._pos += len(line)
        return line

    def readlines(self, size=None):
        """读取一个文件构成一个字符串列表。调用:meth:`readline`读取直到读到文件结尾。支持
        可选的`size`参数，如果底层流`readline`支持这个参数的话。
        """
        last_pos = self._pos
        result = []
        if size is not None:
            end = min(self.limit, last_pos + size)
        else:
            end = self.limit
        while 1:
            if size is not None:
                size -= last_pos - self._pos
            if self._pos >= end:
                break
            result.append(self.readline(size))
            if size is not None:
                last_pos = self._pos
        return result

    def tell(self):
        """返回流的位置。

        .. versionadded:: 0.9
        """
        return self._pos

    def __next__(self):
        line = self.readline()
        if not line:
            raise StopIteration()
        return line

    def readable(self):
        return True
