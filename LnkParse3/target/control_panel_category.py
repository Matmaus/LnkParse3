import warnings
from struct import unpack

from LnkParse3.target.lnk_target_base import LnkTargetBase


"""
----------------------------------------------------------------------
|              0-7b              |               8-15b               |
----------------------------------------------------------------------
|  ClassTypeIndicator == 0x01   |            Unknown                 |
----------------------------------------------------------------------
|              <u_int32> Signature == 0x39DE2184                     |
|                              4 B                                   |
----------------------------------------------------------------------
|                  <u_int32> CategoryIdentifier                      |
|                              4 B                                   |
----------------------------------------------------------------------
"""


# https://github.com/libyal/libfwsi/blob/main/documentation/Windows%20Shell%20Item%20format.asciidoc#452-control-panel-category-shell-item
class ControlPanelCategory(LnkTargetBase):
    SIGNATURE = 0x39DE2184

    CATEGORIES = {
        0: "All Control Panel Items",
        1: "Appearance and Personalization",
        2: "Hardware and Sound",
        3: "Network and Internet",
        4: "Sounds, Speech, and Audio Devices",
        5: "System and Security",
        6: "Clock, Language, and Region",
        7: "Ease of Access",
        8: "Programs",
        9: "User Accounts",
        10: "Security Center",
        11: "Mobile PC",
    }

    def __init__(self, *args, **kwargs):
        self.name = "Control panel category"
        super().__init__(*args, **kwargs)

    def signature(self):
        start, end = 2, 6
        return unpack("<I", self._raw_target[start:end])[0]

    def category_id(self):
        start, end = 6, 10
        return unpack("<I", self._raw_target[start:end])[0]

    def category(self):
        cat_id = self.category_id()
        if cat_id not in self.CATEGORIES:
            msg = (
                f"Not implemented category_id {cat_id} "
                "in ControlPanelCategory.CATEGORIES. "
                'Use fallback value: "Unknown".'
            )
            warnings.warn(msg)
            return "Unknown"
        return self.CATEGORIES[cat_id]

    def as_item(self):
        item = super().as_item()
        item["category_id"] = self.category_id()
        item["category"] = self.category()
        return item
