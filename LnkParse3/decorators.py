from datetime import datetime
from datetime import timezone
from struct import unpack
import functools
import sys
import warnings

from LnkParse3.utils import parse_uuid, parse_packed_uuid, parse_filetime, parse_dostime


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
