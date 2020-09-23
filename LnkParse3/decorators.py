from datetime import datetime
from datetime import timezone
from struct import unpack
import functools
from LnkParse3.lnk_exception import lnk_exception


def must_be(expected):
    def outer(func):
        @functools.wraps(func)
        def inner(self, *args, **kwargs):
            result = func(self, *args, **kwargs)

            # FIXME: delete
            return result

            if result != expected:
                error = "%s must be %s: %s" % (func.__name__, expected, result)
                raise lnk_exception(error)

            return result

        return inner

    return outer


def uuid(func):
    @functools.wraps(func)
    def inner(self, *args, **kwargs):
        binary = func(self, *args, **kwargs)

        # FIXME: delete
        return binary.hex()

        # UUID variants
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/49e490b8-f972-45d6-a3a4-99f924998d97
        d1, d2, d3 = unpack("<LHH", binary[0:8])
        d4, d51, d52 = unpack(">HHI", binary[8:16])
        d5 = (d51 << 16) | d52

        uuid = "%08X-%04X-%04X-%04X-%012X" % (d1, d2, d3, d4, d5)

        return uuid

    return inner


def filetime(func):
    @functools.wraps(func)
    def inner(self, *args, **kwargs):
        binary = func(self, *args, **kwargs)
        nanosec = unpack("<q", binary)[0]

        # FIXME: zero width string?
        if nanosec == 0:
            return ""

        epoch_as_filetime = 116444736000000000
        hundreds_of_nanoseconds = 10000000

        timestamp = (nanosec - epoch_as_filetime) / hundreds_of_nanoseconds
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)

    return inner
