from struct import unpack
from LnkParse3.lnk_info import LnkInfo

"""
------------------------------------------------------------------
|     0-7b     |     8-15b     |     16-23b     |     24-31b     |
------------------------------------------------------------------
|           <u_int32> CommonNetworkRelativeLinkSize              |
------------------------------------------------------------------
|           <flags> CommonNetworkRelativeLinkFlags               |
------------------------------------------------------------------
|                   <u_int32> NetNameOffset                      |
------------------------------------------------------------------
|                  <u_int32> DeviceNameOffset                    |
------------------------------------------------------------------
|                <u_int32> NetworkProviderType                   |
------------------------------------------------------------------
|          <u_int32> NetNameOffsetUnicode (optional)             |
------------------------------------------------------------------
|         <u_int32> DeviceNameOffsetUnicode (optional)           |
------------------------------------------------------------------
|                       <str> NetName                            |
|                            ? B                                 |
------------------------------------------------------------------
|                     <str> DeviceName                           |
|                            ? B                                 |
------------------------------------------------------------------
|          <unicode_str> NetNameUnicode (optional)               |
|                            ? B                                 |
------------------------------------------------------------------
|         <unicode_str> DeviceNameUnicode (optional)             |
|                            ? B                                 |
------------------------------------------------------------------
"""


class Network(LnkInfo):
    NETWORK_PROVIDER_TYPES = {
        "0x1A000": "WNNC_NET_AVID",
        "0x1B000": "WNNC_NET_DOCUSPACE",
        "0x1C000": "WNNC_NET_MANGOSOFT",
        "0x1D000": "WNNC_NET_SERNET",
        "0X1E000": "WNNC_NET_RIVERFRONT1",
        "0x1F000": "WNNC_NET_RIVERFRONT2",
        "0x20000": "WNNC_NET_DECORB",
        "0x21000": "WNNC_NET_PROTSTOR",
        "0x22000": "WNNC_NET_FJ_REDIR",
        "0x23000": "WNNC_NET_DISTINCT",
        "0x24000": "WNNC_NET_TWINS",
        "0x25000": "WNNC_NET_RDR2SAMPLE",
        "0x26000": "WNNC_NET_CSC",
        "0x27000": "WNNC_NET_3IN1",
        "0x29000": "WNNC_NET_EXTENDNET",
        "0x2A000": "WNNC_NET_STAC",
        "0x2B000": "WNNC_NET_FOXBAT",
        "0x2C000": "WNNC_NET_YAHOO",
        "0x2D000": "WNNC_NET_EXIFS",
        "0x2E000": "WNNC_NET_DAV",
        "0x2F000": "WNNC_NET_KNOWARE",
        "0x30000": "WNNC_NET_OBJECT_DIRE",
        "0x31000": "WNNC_NET_MASFAX",
        "0x32000": "WNNC_NET_HOB_NFS",
        "0x33000": "WNNC_NET_SHIVA",
        "0x34000": "WNNC_NET_IBMAL",
        "0x35000": "WNNC_NET_LOCK",
        "0x36000": "WNNC_NET_TERMSRV",
        "0x37000": "WNNC_NET_SRT",
        "0x38000": "WNNC_NET_QUINCY",
        "0x39000": "WNNC_NET_OPENAFS",
        "0X3A000": "WNNC_NET_AVID1",
        "0x3B000": "WNNC_NET_DFS",
        "0x3C000": "WNNC_NET_KWNP",
        "0x3D000": "WNNC_NET_ZENWORKS",
        "0x3E000": "WNNC_NET_DRIVEONWEB",
        "0x3F000": "WNNC_NET_VMWARE",
        "0x40000": "WNNC_NET_RSFX",
        "0x41000": "WNNC_NET_MFILES",
        "0x42000": "WNNC_NET_MS_NFS",
        "0x43000": "WNNC_NET_GOOGLE",
    }

    def location(self):
        return "Network"

    def common_network_relative_link_size(self):
        start = self.common_network_relative_link_offset()
        end = start + 4
        return unpack("<I", self._raw[start:end])[0]

    def common_network_relative_link_flags(self):
        start = self.common_network_relative_link_offset() + 4
        end = start + 4
        return unpack("<I", self._raw[start:end])[0]

    def net_name_offset(self):
        start = self.common_network_relative_link_offset() + 8
        end = start + 4
        return unpack("<I", self._raw[start:end])[0]

    def device_name_offset(self):
        start = self.common_network_relative_link_offset() + 12
        end = start + 4
        return unpack("<I", self._raw[start:end])[0]

    def r_network_provider_type(self):
        start = self.common_network_relative_link_offset() + 16
        end = start + 4
        provider_type = unpack("<I", self._raw[start:end])[0]
        return hex(provider_type)

    def network_provider_type(self):
        # TODO: explain
        if not self.common_network_relative_link_flags() & 0x0002:
            return None
        if self.r_network_provider_type() not in self.NETWORK_PROVIDER_TYPES:
            return None
        return self.NETWORK_PROVIDER_TYPES[self.r_network_provider_type()]

    def net_name_offset_unicode(self):
        if self.net_name_offset() <= 20:
            return None
        start = self.common_network_relative_link_offset() + 20
        end = start + 4
        return unpack("<I", self._raw[start:end])[0]

    def net_name_unicode(self):
        if self.net_name_offset() <= 20:
            return None

        start = self.common_network_relative_link_offset()
        start += self.net_name_offset_unicode()

        binary = self._raw[start:]
        text = self.text_processor.read_unicode_string(binary)
        return text

    def device_name_offset_unicode(self):
        if self.net_name_offset() <= 20:
            return None
        start = self.common_network_relative_link_offset() + 24
        end = start + 4
        return unpack("<I", self._raw[start:end])[0]

    def device_name_unicode(self):
        if self.net_name_offset() <= 20:
            return None

        start = self.common_network_relative_link_offset()
        start += self.device_name_offset_unicode()

        binary = self._raw[start:]
        text = self.text_processor.read_unicode_string(binary)
        return text

    def net_name(self):
        if self.net_name_offset() > 20:
            return None

        start = self.common_network_relative_link_offset()
        start += self.net_name_offset()

        binary = self._raw[start:]
        text = self.text_processor.read_string(binary)
        return text

    def device_name(self):
        if self.net_name_offset() > 20:
            return None

        start = self.common_network_relative_link_offset()
        start += self.device_name_offset()

        binary = self._raw[start:]
        text = self.text_processor.read_string(binary)
        return text
