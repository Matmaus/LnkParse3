from LnkParse3.target.lnk_target_base import lnk_target_base


class unknown(lnk_target_base):
    def __init__(self, *args, **kwargs):
        self.name = "Unknown"
        return super().__init__(*args, **kwargs)

    def as_item(self):
        return None
