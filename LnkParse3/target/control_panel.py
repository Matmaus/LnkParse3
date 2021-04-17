from LnkParse3.target.lnk_target_base import LnkTargetBase
from LnkParse3.decorators import uuid


# https://github.com/libyal/libfwsi/blob/master/documentation/Windows%20Shell%20Item%20format.asciidoc#38-control-panel-shell-item
class ControlPanel(LnkTargetBase):
    # TODO Not implemented
    def __init__(self, *args, **kwargs):
        self.name = "Control panel"
        return super().__init__(*args, **kwargs)

    @uuid
    def control_panel_item_identifier(self):
        start, end = 14, 30
        return self._raw_target[start:end]

    def as_item(self):
        item = super().as_item()
        item["item_identifier"] = self.control_panel_item_identifier()
        return item
