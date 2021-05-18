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

    def _has_opt_fields(self):
        """
        Offsets to the optional fields are specified.
        """
        return bool(self.header_size() >= 0x00000024)

    def local_base_path_offset_unicode(self):
        """LocalBasePathOffsetUnicode (4 bytes):
        An optional, 32-bit, unsigned integer that specifies the location of
        the LocalBasePathUnicode field. If the VolumeIDAndLocalBasePath flag
        is set, this value is an offset, in bytes, from the start of the
        LinkInfo structure; otherwise, this value MUST be zero. This field
        can be present only if the value of the LinkInfoHeaderSize field is
        greater than or equal to 0x00000024.
        """
        if not self._has_opt_fields():
            return None

        start, end = 28, 32
        return unpack("<I", self._raw[start:end])[0]

    def common_path_suffix_offset_unicode(self):
        """CommonPathSuffixOffsetUnicode (4 bytes):
        An optional, 32-bit, unsigned integer that specifies the location of
        the CommonPathSuffixUnicode field. This value is an offset, in bytes,
        from the start of the LinkInfo structure. This field can be present
        only if the value of the LinkInfoHeaderSize field is greater than or
        equal to 0x00000024.
        """
        if not self._has_opt_fields():
            return None

        start, end = 32, 36
        return unpack("<I", self._raw[start:end])[0]

    def local_base_path(self):
        """LocalBasePath (variable):
        An optional, NULL-terminated string, defined by the system default
        code page, which is used to construct the full path to the link item
        or link target by appending the string in the CommonPathSuffix field.
        This field is present if the VolumeIDAndLocalBasePath flag is set.
        """
        if self.local_base_path_offset():
            return None

        start = self.local_base_path_offset()

        binary = self._raw[start:]
        text = self.text_processor.read_string(binary)
        return text

    def common_network_relative_link(self):
        """CommonNetworkRelativeLink (variable):
        An optional CommonNetworkRelativeLink structure (section 2.3.2) that
        specifies information about the network location where the link
        target is stored.
        """
        # TODO:
        pass

    def common_path_suffix(self):
        """CommonPathSuffix (variable):
        A NULL-terminated string, defined by the system default code page,
        which is used to construct the full path to the link item or link
        target by being appended to the string in the LocalBasePath field.
        """
        if self.common_path_suffix_offset():
            return None

        start = self.common_path_suffix_offset()

        binary = self._raw[start:]
        text = self.text_processor.read_string(binary)
        return text

    def local_base_path_unicode(self):
        """LocalBasePathUnicode (variable):
        An optional, NULL-terminated, Unicode string that is used to construct
        the full path to the link item or link target by appending the string
        in the CommonPathSuffixUnicode field. This field can be present only
        if the VolumeIDAndLocalBasePath flag is set and the value of the
        LinkInfoHeaderSize field is greater than or equal to 0x00000024.
        """
        if not self.local_base_path_offset_unicode():
            return None

        start = self.local_base_path_offset_unicode()

        binary = self._raw[start:]
        text = self.text_processor.read_unicode_string(binary)
        return text

    def common_path_suffix_unicode(self):
        """CommonPathSuffixUnicode (variable):
        An optional, NULL-terminated, Unicode string that is used to construct
        the full path to the link item or link target by appending the string
        in the CommonPathSuffixUnicode field. This field can be present only
        if the VolumeIDAndLocalBasePath flag is set and the value of the
        LinkInfoHeaderSize field is greater than or equal to 0x00000024.
        """
        if not self.common_path_suffix_offset_unicode():
            return None

        start = self.common_path_suffix_offset_unicode() + 4

        binary = self._raw[start:]
        text = self.text_processor.read_unicode_string(binary)
        return text

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

        start = self.volume_id_offset() + self.volume_labe_unicode_offset()

        binary = self._raw[offset:]
        text = self.text_processor.read_unicode_string(binary)
        return text
