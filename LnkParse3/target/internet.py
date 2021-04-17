from LnkParse3.target.lnk_target_base import LnkTargetBase


# https://github.com/libyal/libfwsi/blob/master/documentation/Windows%20Shell%20Item%20format.asciidoc#37-uri-shell-item
# TODO: rename to uri
class Internet(LnkTargetBase):
    # TODO Not implemented
    def __init__(self, *args, **kwargs):
        self.name = "Internet"
        return super().__init__(*args, **kwargs)

    def as_item(self):
        item = super().as_item()
        return item
