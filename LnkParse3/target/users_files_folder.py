from struct import unpack

from LnkParse3.decorators import uuid
from LnkParse3.target.lnk_target_base import LnkTargetBase
from LnkParse3.target.shell_fs_folder import ShellFSFolder


"""
----------------------------------------------------------------------
|              0-7b              |               8-15b               |
----------------------------------------------------------------------
| ClassTypeIndicator == 0x74    |            Unknown                 |
----------------------------------------------------------------------
|      <u_int16> InnerDataSize   |                                   |
----------------------------------------------------------------------
Inner data:
----------------------------------------------------------------------
|              Signature == "CFSF" (0x46534643)                      |
|                              4 B                                   |
----------------------------------------------------------------------
|   <u_int16> FileEntrySize      |  FileEntryShellItem (variable)    |
|                              ? B                                   |
----------------------------------------------------------------------
After inner data:
----------------------------------------------------------------------
|                    <GUID> DelegateClassID                          |
|                             16 B                                   |
----------------------------------------------------------------------
|                    <GUID> DelegateFolderID                         |
|                             16 B                                   |
----------------------------------------------------------------------
"""


# https://github.com/libyal/libfwsi/blob/main/documentation/Windows%20Shell%20Item%20format.asciidoc#43-delegate-folder-shell-items
class UsersFilesFolder(LnkTargetBase):
    def __init__(self, *args, **kwargs):
        self.name = "Users files folder"
        super().__init__(*args, **kwargs)

    def inner_data_size(self):
        return unpack("<H", self._raw_target[2:4])[0]

    def signature(self):
        return self._raw_target[4:8]

    def file_entry_size(self):
        return unpack("<H", self._raw_target[8:10])[0]

    def file_entry(self):
        return ShellFSFolder(indata=self._raw_target[8:], cp=self.cp)

    def _delegate_offset(self):
        return 4 + self.inner_data_size()

    @uuid
    def delegate_class_id(self):
        offset = self._delegate_offset()
        return self._raw_target[offset : offset + 16]

    @uuid
    def delegate_folder_id(self):
        offset = self._delegate_offset() + 16
        return self._raw_target[offset : offset + 16]

    def as_item(self):
        item = super().as_item()
        item["signature"] = self.signature().decode("ascii", errors="replace")
        item["file_entry"] = self.file_entry().as_item()
        item["delegate_class_id"] = self.delegate_class_id()
        item["delegate_folder_id"] = self.delegate_folder_id()
        return item
