import warnings
from struct import error as StructError  # noqa: N812
from struct import unpack

from LnkParse3.extra.terminal import Terminal
from LnkParse3.extra.unknown import Unknown
from LnkParse3.extra_factory import ExtraFactory


"""
EXTRA_DATA:
A structure consisting of zero or more property data blocks followed by a terminal block (section 2.5).
"""


class ExtraData:
    def __init__(self, indata=None, cp=None, allow_terminal_blocks=True):
        self.cp = cp
        self._raw = indata
        self.allow_terminal_blocks = allow_terminal_blocks

        self.process()

    def __iter__(self):
        return iter(self.data)

    def process(self):
        self.data = []
        rest = self._raw
        while rest:
            factory = ExtraFactory(indata=rest)
            try:
                size = factory.item_size()
            except StructError as e:
                warnings.warn(f"Error while parsing extra data: {e!r}")
                break

            if not size:
                break

            data, rest = rest[:size], rest[size:]

            cls = factory.extra_class()
            if cls:
                extra = cls(indata=data, cp=self.cp)
                self.data.append(extra)

        # If there is data following the Terminal Block, we should take note of it and tell the user.
        if self.allow_terminal_blocks and len(rest) > 4 and unpack("<I", rest[:4])[0] < 0x00000004:
            extra = Terminal(indata=rest, cp=self.cp)
            self.data.append(extra)

    def size(self) -> int:
        return sum(extra.size() for extra in self.data)

    def as_dict(self):
        res = {}
        for extra in self:
            try:
                if isinstance(extra, Unknown):
                    if extra.name() not in res:
                        res[extra.name()] = []
                    res[extra.name()].append(extra.as_dict())
                else:
                    res[extra.name()] = extra.as_dict()
            except (StructError, ValueError) as e:
                msg = "Error while parsing `%s` (%s)" % (extra.name(), e)
                warnings.warn(msg)
                continue
        return res
