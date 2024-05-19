"""
Structures of the Shell Link Binary File Format can define strings in
fixed-length fields, strings MUST be null-terminated. If a string is smaller
than the size of the field that contains it, the bytes in the field following
the terminating null character are undefined and can have any value. The
undefined bytes MUST NOT be used.
"""

import warnings


class TextProcessor:
    def __init__(self, cp=None):
        self.cp = cp if cp else "cp1252"

    def read_strings(self, binary):
        chars = []

        def _chars_to_string(lst):
            bin_string = b"".join(lst)
            try:
                string = bin_string.decode(self.cp)
            except UnicodeDecodeError:
                # Fallback to UTF-8 before giving up.
                try:
                    string = bin_string.decode("utf-8")
                except UnicodeDecodeError as e:
                    string = bin_string.decode(self.cp, errors="replace")
                    msg = f"Error while decoding string `{string}` ({e})"
                    warnings.warn(msg)
            yield string

        for char in binary:
            if char == 0x00:
                yield from _chars_to_string(chars)
                chars = []
            else:
                chars.append(bytes([char]))

        yield from _chars_to_string(chars)

    def read_string(self, binary):
        it = self.read_strings(binary)
        return next(it)

    def read_unicode_strings(self, binary):
        chars = []

        def _chars_to_string(lst):
            bin_string = b"".join(lst)
            try:
                string = bin_string.decode("utf-16le")
            except UnicodeDecodeError as e:
                string = bin_string.decode("utf-16le", errors="replace")
                msg = f"Error while decoding string `{string}` ({e})"
                warnings.warn(msg)
            yield string

        for char in self._2bytes_each(binary):
            if char == b"\x00\x00":
                yield from _chars_to_string(chars)
                chars = []
            else:
                chars.append(char)

        yield from _chars_to_string(chars)

    def read_unicode_string(self, binary):
        it = self.read_unicode_strings(binary)
        return next(it)

    @staticmethod
    def _2bytes_each(binary):
        it = iter(binary)
        while True:
            tmp = None
            try:
                tmp = bytes([next(it)])
                tmp += bytes([next(it)])
                yield tmp
            except StopIteration:
                if tmp:
                    yield tmp
                return None
