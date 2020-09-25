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
