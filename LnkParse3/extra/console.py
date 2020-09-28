from struct import unpack
from LnkParse3.extra.lnk_extra_base import LnkExtraBase

"""
------------------------------------------------------------------
|     0-7b     |     8-15b     |     16-23b     |     24-31b     |
------------------------------------------------------------------
|              <u_int32> BlockSize == 0x000000CC                 |
------------------------------------------------------------------
|            <u_int32> BlockSignature == 0xA0000002              |
-----------------------------------------------------------------|
| <u_int16> FillAttributes     |<u_int16> PopupFillAttributes    |
------------------------------------------------------------------
| <int16> ScreenBufferSizeX    |     <int16> ScreenBufferSizeY   |
------------------------------------------------------------------
|     <int16> WindowSizeX      |       <int16> WindowSizeY       |
------------------------------------------------------------------
|    <int16> WindowOriginX     |      <int16> WindowOriginY      |
------------------------------------------------------------------
|                           Unused1                              |
------------------------------------------------------------------
|                           Unused2                              |
------------------------------------------------------------------
|                      <u_int32> FontSize                        |
------------------------------------------------------------------
|                     <u_int32> FontFamily                       |
------------------------------------------------------------------
|                     <u_int32> FontWeight                       |
------------------------------------------------------------------
|                    <unicode_str> Face Name                     |
|                            64 B                                |
------------------------------------------------------------------
|                     <u_int32> CursorSize                       |
------------------------------------------------------------------
|                     <u_int32> FullScreen                       |
------------------------------------------------------------------
|                      <u_int32> QuickEdit                       |
------------------------------------------------------------------
|                     <u_int32> InsertMode                       |
------------------------------------------------------------------
|                    <u_int32> AutoPosition                      |
------------------------------------------------------------------
|                 <u_int32> HistoryBufferSize                    |
------------------------------------------------------------------
|               <u_int32> NumberOfHistoryBuffers                 |
------------------------------------------------------------------
|                   <u_int32> HistoryNoDup                       |
------------------------------------------------------------------
|                <vector<u_int32>> ColorTable                    |
|                            64 B                                |
------------------------------------------------------------------
"""


class Console(LnkExtraBase):
    def name(self):
        return "CONSOLE_PROPERTIES_BLOCK"

    def fill_attributes(self):
        start, end = 8, 10
        return unpack("<H", self._raw[start:end])[0]

    def popup_fill_attributes(self):
        start, end = 10, 12
        return unpack("<H", self._raw[start:end])[0]

    def screen_buffer_size_x(self):
        start, end = 12, 14
        return unpack("<h", self._raw[start:end])[0]

    def screen_buffer_size_y(self):
        start, end = 14, 16
        return unpack("<h", self._raw[start:end])[0]

    def window_size_x(self):
        start, end = 16, 18
        return unpack("<h", self._raw[start:end])[0]

    def window_size_y(self):
        start, end = 18, 20
        return unpack("<h", self._raw[start:end])[0]

    def window_origin_x(self):
        start, end = 20, 22
        return unpack("<h", self._raw[start:end])[0]

    def window_origin_y(self):
        start, end = 22, 24
        return unpack("<h", self._raw[start:end])[0]

    def font_size(self):
        start, end = 32, 36
        return unpack("<I", self._raw[start:end])[0]

    def font_family(self):
        start, end = 36, 40
        return unpack("<I", self._raw[start:end])[0]

    def font_weight(self):
        start, end = 40, 44
        return unpack("<I", self._raw[start:end])[0]

    def face_name(self):
        start = 44
        end = start + 64
        binary = self._raw[start:end]
        text = self.text_processor.read_unicode_string(binary)
        return text

    def cursor_size(self):
        start, end = 108, 112
        return unpack("<I", self._raw[start:end])[0]

    def full_screen(self):
        start, end = 112, 116
        return unpack("<I", self._raw[start:end])[0]

    def quick_edit(self):
        start, end = 116, 120
        return unpack("<I", self._raw[start:end])[0]

    def insert_mode(self):
        start, end = 120, 124
        return unpack("<I", self._raw[start:end])[0]

    def auto_position(self):
        start, end = 124, 128
        return unpack("<I", self._raw[start:end])[0]

    def history_buffer_size(self):
        start, end = 128, 132
        return unpack("<I", self._raw[start:end])[0]

    def number_of_history_buffers(self):
        start, end = 132, 136
        return unpack("<I", self._raw[start:end])[0]

    def history_no_dup(self):
        start, end = 136, 140
        return unpack("<I", self._raw[start:end])[0]

    def color_table(self):
        start, end = 140, 144
        return unpack("<I", self._raw[start:end])[0]

    def as_dict(self):
        tmp = super().as_dict()
        tmp["fill_attributes"] = self.fill_attributes()
        tmp["popup_fill_attributes"] = self.popup_fill_attributes()
        tmp["screen_buffer_size_x"] = self.screen_buffer_size_x()
        tmp["screen_buffer_size_y"] = self.screen_buffer_size_y()
        tmp["window_size_x"] = self.window_size_x()
        tmp["window_size_y"] = self.window_size_y()
        tmp["window_origin_x"] = self.window_origin_x()
        tmp["window_origin_y"] = self.window_origin_y()
        tmp["font_size"] = self.font_size()
        tmp["font_family"] = self.font_family()
        tmp["font_weight"] = self.font_weight()
        tmp["face_name"] = self.face_name()
        tmp["cursor_size"] = self.cursor_size()
        tmp["full_screen"] = self.full_screen()
        tmp["quick_edit"] = self.quick_edit()
        tmp["insert_mode"] = self.insert_mode()
        tmp["auto_position"] = self.auto_position()
        tmp["history_buffer_size"] = self.history_buffer_size()
        tmp["number_of_history_buffers"] = self.number_of_history_buffers()
        tmp["history_no_dup"] = self.history_no_dup()
        tmp["color_table"] = self.color_table()
        return tmp
