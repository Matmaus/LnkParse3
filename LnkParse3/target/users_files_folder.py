from LnkParse3.target.lnk_target_base import lnk_target_base


class users_files_folder(lnk_target_base):
    def __init__(self, *args, **kwargs):
        self.name = "Users files folder"
        return super().__init__(*args, **kwargs)

    def as_item(self):
        return None
