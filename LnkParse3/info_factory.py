import struct
import warnings

from LnkParse3.info.local import Local
from LnkParse3.info.network import Network


class InfoFactory:
    def __init__(self, lnk_info):
        self._lnk_info = lnk_info

    def _volume_id_and_local_base_path(self):
        """
        If set, the VolumeID and LocalBasePath fields are present, and their
        locations are specified by the values of the VolumeIDOffset and
        LocalBasePathOffset fields, respectively. If the value of the
        LinkInfoHeaderSize field is greater than or equal to 0x00000024, the
        LocalBasePathUnicode field is present, and its location is specified by
        the value of the LocalBasePathOffsetUnicode field.
        If not set, the VolumeID, LocalBasePath, and LocalBasePathUnicode
        fields are not present, and the values of the VolumeIDOffset and
        LocalBasePathOffset fields are zero. If the value of the
        LinkInfoHeaderSize field is greater than or equal to 0x00000024, the
        value of the LocalBasePathOffsetUnicode field is zero.
        """
        return bool(self._lnk_info.flags() & 0x0001)

    def _common_network_relative_link_and_path_suffix(self):
        """
        If set, the CommonNetworkRelativeLink field is present, and its
        location is specified by the value of the
        CommonNetworkRelativeLinkOffset field.
        If not set, the CommonNetworkRelativeLink field is not present, and the
        value of the CommonNetworkRelativeLinkOffset field is zero.
        """
        return bool(self._lnk_info.flags() & 0x0002)

    def info_class(self):
        try:
            if self._volume_id_and_local_base_path():
                return Local
            elif self._common_network_relative_link_and_path_suffix():
                return Network
            else:
                return None
        except struct.error as e:
            warnings.warn(f"Error while selecting proper Info class: {e!r}")
            return None
