from LnkParse3.target.lnk_target_base import LnkTargetBase


# https://github.com/libyal/libfwsi/blob/master/documentation/Windows%20Shell%20Item%20format.asciidoc#36-compressed-folder-shell-item
class CompressedFolder(LnkTargetBase):
    # TODO Not implemented
    def __init__(self, *args, **kwargs):
        self.name = "Compressed folder"
        return super().__init__(*args, **kwargs)

    def as_item(self):
        item = super().as_item()
        return item
