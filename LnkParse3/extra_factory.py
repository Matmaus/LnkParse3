from struct import unpack
from LnkParse3.extra.environment import environment
from LnkParse3.extra.console import console
from LnkParse3.extra.distributed_tracker import distributed_tracker
from LnkParse3.extra.code_page import code_page
from LnkParse3.extra.special_folder import special_folder
from LnkParse3.extra.darwin import darwin
from LnkParse3.extra.icon import icon
from LnkParse3.extra.shim_layer import shim_layer
from LnkParse3.extra.metadata import metadata
from LnkParse3.extra.known_folder import known_folder
from LnkParse3.extra.shell_item import shell_item

"""
------------------------------------------------------------------
|     0-7b     |     8-15b     |     16-23b     |     24-31b     |
------------------------------------------------------------------
|              <u_int32> BlockSize == 0x00000314                 |
------------------------------------------------------------------
|            <u_int32> BlockSignature == 0xA0000001              |
------------------------------------------------------------------
"""


class extra_factory:
    EXTRA_SIGS = {
        "a0000001": environment,
        "a0000002": console,
        "a0000003": distributed_tracker,
        "a0000004": code_page,
        "a0000005": special_folder,
        "a0000006": darwin,
        "a0000007": icon,
        "a0000008": shim_layer,
        "a0000009": metadata,
        "a000000b": known_folder,
        "a000000c": shell_item,
    }

    def __init__(self, indata):
        self._raw = indata

    def item_size(self):
        start, end = 0, 4
        size = unpack("<I", self._raw[start:end])[0]
        return size

    def _rsig(self):
        start, end = 4, 8
        rsig = unpack("<I", self._raw[start:end])[0]
        return rsig

    def extra_class(self):
        sig = str(hex(self._rsig()))[2:]  # huh?
        return self.EXTRA_SIGS.get(sig)
