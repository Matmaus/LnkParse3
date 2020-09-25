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
            size = factory.item_size()

            if not size:
                break

            data, rest = rest[:size], rest[size:]

            cls = factory.extra_class()
            if cls:
                yield cls(indata=data, cp=self.cp)
