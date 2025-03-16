import functools
import warnings

from LnkParse3.utils import parse_dostime
from LnkParse3.utils import parse_filetime
from LnkParse3.utils import parse_packed_uuid
from LnkParse3.utils import parse_uuid


def must_be(expected):
    def outer(func):
        @functools.wraps(func)
        def inner(self, *args, **kwargs):
            result = func(self, *args, **kwargs)

            if result != expected:
                msg = "%s must be %s: %s" % (func.__name__, expected, result)
                warnings.warn(msg)

            return result

        return inner

    return outer


def uuid(func):
    @functools.wraps(func)
    def inner(self, *args, **kwargs):
        binary = func(self, *args, **kwargs)

        return parse_uuid(binary)

    return inner


def packed_uuid(func):
    @functools.wraps(func)
    def inner(self, *args, **kwargs):
        text = func(self, *args, **kwargs)

        return parse_packed_uuid(text)

    return inner


def filetime(func):
    @functools.wraps(func)
    def inner(self, *args, **kwargs):
        binary = func(self, *args, **kwargs)

        return parse_filetime(binary)

    return inner


def dostime(func):
    @functools.wraps(func)
    def inner(self, *args, **kwargs):
        binary = func(self, *args, **kwargs)

        return parse_dostime(binary)

    return inner
