from LnkParse3.target.lnk_target_base import LnkTargetBase


class UsersFilesFolder(LnkTargetBase):
    # TODO Not implemented
    def __init__(self, *args, **kwargs):
        self.name = "Users files folder"
        return super().__init__(*args, **kwargs)

    def as_item(self):
        item = super().as_item()
        return item
