from struct import unpack
from LnkParse3.target_factory import TargetFactory

"""
LINKTARGET_IDLIST:
An optional LinkTargetIDList structure (section 2.2), which specifies the
target of the link. The presence of this structure is specified by the
HasLinkTargetIDList bit (LinkFlags section 2.1.1) in the ShellLinkHeader.

------------------------------------------------------------------
|     0-7b     |     8-15b     |     16-23b     |     24-31b     |
------------------------------------------------------------------
|         IDListSize           |         IDList (variable)       |
|-------------------------------                                 |
|                             ...                                |
------------------------------------------------------------------
"""
import warnings


class LnkTargets:
    SIZE_OF_ID_LIST_SIZE = 2

    def __init__(self, indata=None, cp=None):
        self._targets = {}
        self.cp = cp
        self._raw = indata

        start = self.SIZE_OF_ID_LIST_SIZE
        end = self.size()
        self._raw_targets = self._raw[start:end]

    def __iter__(self):
        return self._id_lists()

    def size(self):
        """
        Including IDListSize section itself
        """
        return self.id_list_size() + self.SIZE_OF_ID_LIST_SIZE

    def id_list_size(self):
        """IDListSize (2 bytes):
        The size, in bytes, of the IDList field.
        """
        start, end = 0, self.SIZE_OF_ID_LIST_SIZE
        size = unpack("<H", self._raw[start:end])[0]
        return size

    def _id_lists(self):
        """ItemIDList (variable):
        An array of zero or more ItemID structures (section 2.2.2), which
        contains the item ID list. An IDList structure conforms to the
        following ABNF [RFC5234]:

            IDLIST = *ITEMID TERMINALID

        ------------------------------------------------------------------
        |     0-7b     |     8-15b     |     16-23b     |     24-31b     |
        ------------------------------------------------------------------
        |                       ItemIDList (variable)                    |
        ------------------------------------------------------------------
        |                             ...                                |
        |-----------------------------------------------------------------
        |         TerminalID           |
        --------------------------------
        """
        rest = self._raw_targets
        while rest:
            factory = TargetFactory(indata=rest)
            target_class = factory.target_class()

            if not target_class:
                break

            target = target_class(indata=rest, cp=self.cp)

            size = factory.item_size()
            rest = rest[size:]
            yield target

    def as_list(self):
        res = []
        for target in self:
            try:
                res.append(target.as_item())
            except KeyError as e:
                msg = "Error while target `%s` (KeyError %s)" % (target.name, e)
                warnings.warn(msg)
                continue
        return res
