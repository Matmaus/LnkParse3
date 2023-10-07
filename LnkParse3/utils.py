from datetime import datetime
from datetime import timezone
from struct import unpack
import functools
import sys
import warnings


def parse_uuid(binary):
    # UUID variants
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/49e490b8-f972-45d6-a3a4-99f924998d97
    # Also see Java implementation (mslinks)
    # https://github.com/DmitriiShamrikov/mslinks/blob/master/src/mslinks/data/GUID.java#L51
    d1, d2, d3 = unpack("<LHH", binary[0:8])
    d4, d51, d52 = unpack(">HHI", binary[8:16])

    uuid = "%08X-%04X-%04X-%04X-%04X%08X" % (d1, d2, d3, d4, d51, d52)

    return uuid


def _quad_to_hex(quad):
    # An implemetation is based on
    # https://metadataconsulting.blogspot.com/2019/12/CSharp-Convert-a-GUID-to-a-Darwin-Descriptor-and-back.html
    base_85 = "!$%&'()*+,-.0123456789=?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{}~"
    i = 5
    ddec = 0
    while i >= 1:
        char = quad[i - 1]
        b85 = base_85.find(char)
        ddec = ddec + b85
        if i > 1:
            ddec = ddec * 85
        i -= 1

    return f"{ddec:08X}"


def parse_packed_uuid(text):
    if text is None:
        return None

    # An implemetation is based on
    # https://metadataconsulting.blogspot.com/2019/12/CSharp-Convert-a-GUID-to-a-Darwin-Descriptor-and-back.html
    quad1 = _quad_to_hex(text[0:5])
    quad2 = _quad_to_hex(text[5:10])
    quad3 = _quad_to_hex(text[10:15])
    quad4 = _quad_to_hex(text[15:20])
    quads = quad1 + quad2 + quad3 + quad4

    d1 = quads[:8]
    d2 = quads[12:16]
    d3 = quads[8:12]
    d41 = quads[22:24]
    d42 = quads[20:22]
    d51 = quads[18:20]
    d52 = quads[16:18]
    d53 = quads[30:32]
    d54 = quads[28:30]
    d55 = quads[26:28]
    d56 = quads[24:26]

    uuid = "%s-%s-%s-%s%s-%s%s%s%s%s%s" % (
        d1,
        d2,
        d3,
        d41,
        d42,
        d51,
        d52,
        d53,
        d54,
        d55,
        d56,
    )

    return uuid


def parse_filetime(binary):
    #
    # Source:
    #   https://gist.github.com/Mostafa-Hamdy-Elgiar/9714475f1b3bc224ea063af81566d873
    #   https://stackoverflow.com/questions/38878647/python-convert-filetime-to-datetime-for-dates-before-1970
    #   https://computerforensics.parsonage.co.uk/downloads/TheMeaningofLIFE.pdf
    try:
        nanosec = unpack("<q", binary)[0]

        if nanosec == 0:
            # If the date is 0 it means that the file has been created in an
            # application, then saved from it, and never ever opened.
            return None

        epoch_as_filetime = 116444736000000000
        hundreds_of_nanoseconds = 10000000

        timestamp = (nanosec - epoch_as_filetime) / hundreds_of_nanoseconds
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        if sys.version_info < (3, 8, 0):
            # HACK for older versions for bytes.hex()
            # https://docs.python.org/3.9/library/stdtypes.html?highlight=hex#bytes.hex
            iterator = iter(binary.hex())
            invalid_date = " ".join(a + b for a, b in zip(iterator, iterator))
        else:
            invalid_date = binary.hex(" ")
        msg = "Invalid filetime: %s" % invalid_date
        warnings.warn(msg)
        return None


def parse_dostime(binary):
    r"""
    The DOS date/time format is a bitmask:
    24                16                 8                 0
     +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+
     |h|h|h|h|h|m|m|m| |m|m|m|s|s|s|s|s| |Y|Y|Y|Y|Y|Y|Y|M| |M|M|M|D|D|D|D|D|
     +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+
     \________/\____________/\_________/ \____________/\________/\_________/
        hour       minute      second         year       month       day
    The year is stored as an offset from 1980.
    Seconds are stored in two-second increments.
    (So if the "second" value is 15, it actually represents 30 seconds.)
    """

    #
    # Source:
    #   https://github.com/log2timeline/dfdatetime/blob/main/dfdatetime/fat_date_time.py
    #   https://stackoverflow.com/questions/15763259/unix-timestamp-to-fat-timestamp
    #   https://docs.microsoft.com/pl-pl/windows/desktop/api/winbase/nf-winbase-dosdatetimetofiletime
    #   https://github.com/log2timeline/dfdatetime/wiki/Date-and-time-values
    #
    try:
        dos = unpack("<I", binary)[0]
        # NOTE An alternative solution for DOS conversion is to use
        # `dfdatetime` package. It returns the same date-time for all
        # currently available tests.
        # from dfdatetime.fat_date_time import FATDateTime
        # timestamp = FATDateTime(dos).CopyToPosixTimestamp()
        # return datetime.fromtimestamp(timestamp, tz=timezone.utc)

        if dos == 0:
            # If the date is 0 it means that the file has been created in an
            # application, then saved from it, and never ever opened.
            return None

        ymdhms = (
            ((dos & 0x0000FE00) >> 9) + 1980,
            ((dos & 0x000001E0) >> 5),
            ((dos & 0x0000001F) >> 0),
            ((dos & 0xF8000000) >> 27),
            ((dos & 0x07E00000) >> 21),
            ((dos & 0x001F0000) >> 16) * 2,
        )

        return datetime(*ymdhms, tzinfo=timezone.utc)
    except ValueError:
        if sys.version_info < (3, 8, 0):
            # HACK for older versions for bytes.hex()
            # https://docs.python.org/3.9/library/stdtypes.html?highlight=hex#bytes.hex
            iterator = iter(binary.hex())
            invalid_date = " ".join(a + b for a, b in zip(iterator, iterator))
        else:
            invalid_date = binary.hex(" ")
        msg = "Invalid dostime: %s" % invalid_date
        warnings.warn(msg)
        return None
