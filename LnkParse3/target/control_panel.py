from LnkParse3.target.lnk_target_base import LnkTargetBase
from LnkParse3.decorators import uuid


# https://github.com/libyal/libfwsi/blob/master/documentation/Windows%20Shell%20Item%20format.asciidoc#38-control-panel-shell-item
class ControlPanel(LnkTargetBase):
    @uuid
    def control_panel_item_identifier(self):
        start, end = 14, 30
        return self._raw_target[start:end]
