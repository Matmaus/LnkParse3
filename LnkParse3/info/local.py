from struct import unpack
from LnkParse3.lnk_info import LnkInfo

"""
------------------------------------------------------------------
|     0-7b     |     8-15b     |     16-23b     |     24-31b     |
------------------------------------------------------------------
|                   <u_int32> VolumeIDSize                       |
------------------------------------------------------------------
|                    <u_int32> DriveType                         |
------------------------------------------------------------------
|                 <u_int32> DriveSerialNumber                    |
------------------------------------------------------------------
|                 <u_int32> VolumeLabelOffset                    |
------------------------------------------------------------------
|        <u_int32> VolumeLabelOffsetUnicode (optional)           |
------------------------------------------------------------------
|                       <u_int32> Data                           |
|                            ? B                                 |
------------------------------------------------------------------
"""


class Local(LnkInfo):
    DRIVE_TYPES = [
        "DRIVE_UNKNOWN",
        "DRIVE_NO_ROOT_DIR",
        "DRIVE_REMOVABLE",
        "DRIVE_FIXED",
        "DRIVE_REMOTE",
        "DRIVE_CDROM",
        "DRIVE_RAMDISK",
    ]

    def location(self):
        return "Local"

    def volume_id_size(self):
        start = self.volume_id_offset()
        end = start + 4
        return unpack("<I", self._raw[start:end])[0]

    def r_drive_type(self):
        start = self.volume_id_offset() + 4
        end = start + 4
        return unpack("<I", self._raw[start:end])[0]

    def drive_serial_number(self):
        start = self.volume_id_offset() + 8
        end = start + 4
        number = unpack("<I", self._raw[start:end])[0]
        return hex(number)

    def volume_label_offset(self):
        start = self.volume_id_offset() + 12
        end = start + 4
        return unpack("<I", self._raw[start:end])[0]

    def drive_type(self):
        if self.r_drive_type() < len(self.DRIVE_TYPES):
            return self.DRIVE_TYPES[self.r_drive_type()]
        else:
            return None

    def _has_volume_label_offset_unicode(self):
        return bool(self.volume_label_offset() == 0x00000014)

    def volume_label(self):
        if self._has_volume_label_offset_unicode():
            return None

        start = self.volume_id_offset() + self.volume_label_offset()

        binary = self._raw[start:]
        text = self.text_processor.read_string(binary)
        return text

    def volume_label_unicode_offset(self):
        if not self._has_volume_label_offset_unicode():
            return None

        start = self.volume_id_offset() + 16
        end = start + 4
        return unpack("<I", self._raw[start:end])[0]

    def volume_label_unicode(self):
        if not self.volume_label_unicode_offset():
            return None

        start = self.volume_id_offset() + self.volume_label_unicode_offset()

        binary = self._raw[start:]
        text = self.text_processor.read_unicode_string(binary)
        return text
