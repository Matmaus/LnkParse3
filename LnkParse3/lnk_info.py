from struct import unpack
from LnkParse3.text_processor import TextProcessor

"""
LINKINFO:
An optional LinkInfo structure (section 2.3), which specifies information
necessary to resolve the link target. The presence of this structure is
specified by the HasLinkInfo bit (LinkFlags section 2.1.1) in the
ShellLinkHeader.

------------------------------------------------------------------
|     0-7b     |     8-15b     |     16-23b     |     24-31b     |
------------------------------------------------------------------
|                   <u_int32> LinkInfoSize                       |
------------------------------------------------------------------
|                <u_int32> LinkInfoHeaderSize                    |
------------------------------------------------------------------
|                   <flags> LinkInfoFlags                        |
------------------------------------------------------------------
|                  <u_int32> VolumeIDOffset                      |
------------------------------------------------------------------
|               <u_int32> LocalBasePathOffset                    |
------------------------------------------------------------------
|           <u_int32> CommonNetworkRelativeLinkOffset            |
------------------------------------------------------------------
|              <u_int32> CommonPathSuffixOffset                  |
------------------------------------------------------------------
|        <u_int32> LocalBasePathOffsetUnicode (optional)         |
------------------------------------------------------------------
|       <u_int32> CommonPathSuffixOffsetUnicode (optional)       |
------------------------------------------------------------------
|                 <VolumeID> VolumeID (optional)                 |
|                            ? B                                 |
------------------------------------------------------------------
|                 <str> LocalBasePath (optional)                 |
|                            ? B                                 |
------------------------------------------------------------------
|<CommonNetworkRelativeLink> CommonNetworkRelativeLink (optional)|
|                            ? B                                 |
------------------------------------------------------------------
|               <str> CommonPathSuffix (optional)                |
|                            ? B                                 |
------------------------------------------------------------------
|        <unicode_str> LocalBasePathUnicode (optional)           |
|                            ? B                                 |
------------------------------------------------------------------
|      <unicode_str> CommonPathSuffixUnicode (optional)          |
|                            ? B                                 |
------------------------------------------------------------------
"""


class LnkInfo:
    def __init__(self, indata=None, cp=None):
        self._raw = indata
        self.text_processor = TextProcessor(cp=cp)

    def size(self):
        """LinkInfoSize (4 bytes):
        A 32-bit, unsigned integer that specifies the size, in bytes, of the
        LinkInfo structure. All offsets specified in this structure MUST be
        less than this value, and all strings contained in this structure MUST
        fit within the extent defined by this size.
        """
        start, end = 0, 4
        return unpack("<I", self._raw[start:end])[0]

    def header_size(self):
        """LinkInfoHeaderSize (4 bytes):
        A 32-bit, unsigned integer that specifies the size, in bytes, of the
        LinkInfo header section, which is composed of the LinkInfoSize,
        LinkInfoHeaderSize, LinkInfoFlags, VolumeIDOffset, LocalBasePathOffset,
        CommonNetworkRelativeLinkOffset, CommonPathSuffixOffset fields, and, if
        included, the LocalBasePathOffsetUnicode and
        CommonPathSuffixOffsetUnicode fields

        * 0x0000001C
            Offsets to the optional fields are not specified.

        * 0x00000024 ≤ value
            Offsets to the optional fields are specified.
        """
        start, end = 4, 8
        return unpack("<I", self._raw[start:end])[0]

    def flags(self):
        """LinkInfoFlags (4 bytes):
        Flags that specify whether the VolumeID, LocalBasePath,
        LocalBasePathUnicode, and CommonNetworkRelativeLink fields are present
        in this structure.
        """
        start, end = 8, 12
        return unpack("<I", self._raw[start:end])[0]

    def volume_id_offset(self):
        """VolumeIDOffset (4 bytes):
        A 32-bit, unsigned integer that specifies the location of the VolumeID
        field. If the VolumeIDAndLocalBasePath flag is set, this value is an
        offset, in bytes, from the start of the LinkInfo structure; otherwise,
        this value MUST be zero.
        """
        start, end = 12, 16
        return unpack("<I", self._raw[start:end])[0]

    def local_base_path_offset(self):
        """LocalBasePathOffset (4 bytes):
        A 32-bit, unsigned integer that specifies the location of the
        LocalBasePath field. If the VolumeIDAndLocalBasePath flag is set, this
        value is an offset, in bytes, from the start of the LinkInfo structure;
        otherwise, this value MUST be zero.
        """
        start, end = 16, 20
        return unpack("<I", self._raw[start:end])[0]

    def common_network_relative_link_offset(self):
        """CommonNetworkRelativeLinkOffset (4 bytes):
        A 32-bit, unsigned integer that specifies the location of the
        CommonNetworkRelativeLink field. If the
        CommonNetworkRelativeLinkAndPathSuffix flag is set, this value is an
        offset, in bytes, from the start of the LinkInfo structure; otherwise,
        this value MUST be zero.
        """
        start, end = 20, 24
        return unpack("<I", self._raw[start:end])[0]

    def common_path_suffix_offset(self):
        """CommonPathSuffixOffset (4 bytes):
        A 32-bit, unsigned integer that specifies the location of the
        CommonPathSuffix field. This value is an offset, in bytes, from the
        start of the LinkInfo structure.
        """
        start, end = 24, 28
        return unpack("<I", self._raw[start:end])[0]

    def _has_opt_fields(self):
        """
        Offsets to the optional fields are specified.
        """
        return bool(self.header_size() >= 0x00000024)

    def common_path_suffix(self):
        """CommonPathSuffix (variable):
        A NULL-terminated string, defined by the system default code page,
        which is used to construct the full path to the link item or link
        target by being appended to the string in the LocalBasePath field.
        """
        if not self.common_path_suffix_offset():
            return None

        start = self.common_path_suffix_offset()

        binary = self._raw[start:]
        text = self.text_processor.read_string(binary)
        return text

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
        if not self.local_base_path_offset():
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
        # import pdb;pdb.set_trace()
        text = self.text_processor.read_unicode_string(binary)
        return text
