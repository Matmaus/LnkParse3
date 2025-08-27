from LnkParse3.target.lnk_target_base import LnkTargetBase


"""
----------------------------------------------------------------------
|              0-7b              |               8-15b               |
----------------------------------------------------------------------
| ClassTypeIndicator == 0x20-0x2F|            UnknownData            |
----------------------------------                                   |
|                                             ? B                    |
----------------------------------------------------------------------

https://github.com/libyal/libfwsi/blob/master/documentation/Windows%20Shell%20Item%20format.asciidoc#33-volume-shell-item
"""


# TODO: rename to volume_shell_item
class MyComputer(LnkTargetBase):
    def __init__(self, *args, **kwargs):
        self.name = "Volume Item"
        super().__init__(*args, **kwargs)

    def as_item(self):
        item = super().as_item()
        item["flags"] = self.flags()
        item["data"] = self.data()
        return item

    # dup: ./shell_fs_folder.py flags()
    # dup: ../target_factory.py item_type()
    def flags(self):
        flags = self.class_type_indicator()

        # FIXME: delete masking
        # FIXME: hex() is only used here
        return hex(flags & 0x0F)

    def data(self):
        if self.class_type_indicator() == 0x2F:
            # FIXME: Some data seems to stay unparsed after \0
            return self.text_processor.read_string(self._raw_target[1:])
        return None
