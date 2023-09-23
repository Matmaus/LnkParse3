import warnings
from struct import error as StructError

from LnkParse3.extra_factory import ExtraFactory

"""
EXTRA_DATA:
Zero or more ExtraData structures (section 2.5).
"""


class ExtraData:
    def __init__(self, indata=None, cp=None):
        self.cp = cp
        self._raw = indata

    def __iter__(self):
        return self._iter()

    def _iter(self):
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
                yield cls(indata=data, cp=self.cp)

    def as_dict(self):
        res = {}
        for extra in self:
            try:
                res[extra.name()] = extra.as_dict()
            except (StructError, ValueError) as e:
                msg = "Error while parsing `%s` (%s)" % (extra.name(), e)
                warnings.warn(msg)
                continue
        return res
