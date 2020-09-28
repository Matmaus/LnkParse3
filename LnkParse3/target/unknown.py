from LnkParse3.target.lnk_target_base import LnkTargetBase


class Unknown(LnkTargetBase):
    def __init__(self, *args, **kwargs):
        self.name = "Unknown"
        return super().__init__(*args, **kwargs)

    def as_item(self):
        return None
