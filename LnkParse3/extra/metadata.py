from struct import unpack
from LnkParse3.extra.lnk_extra_base import LnkExtraBase
from LnkParse3.decorators import uuid

"""
------------------------------------------------------------------
|     0-7b     |     8-15b     |     16-23b     |     24-31b     |
------------------------------------------------------------------
|              <u_int32> BlockSize >= 0x0000000C                 |
------------------------------------------------------------------
|            <u_int32> BlockSignature == 0xA0000009              |
------------------------------------------------------------------
|                    <u_int32> StorageSize                       |
------------------------------------------------------------------
|                    Version == 0x53505331                       |
------------------------------------------------------------------
|                      <GUID> FormatID                           |
|                            16 B                                |
------------------------------------------------------------------
|   <vector<MS_OLEPS>> SerializedPropertyValue (see MS-OLEPS)    |
|                             ? B                                |
------------------------------------------------------------------
"""


class Metadata(LnkExtraBase):
    def name(self):
        return "METADATA_PROPERTIES_BLOCK"

    def storage_size(self):
        start, end = 8, 12
        return unpack("<I", self._raw[start:end])[0]

    def version(self):
        start, end = 12, 16
        version = unpack("<I", self._raw[start:end])[0]
        return hex(version)

    @uuid
    def format_id(self):
        start, end = 16, 32
        return self._raw[start:end]

    def as_dict(self):
        tmp = super().as_dict()
        tmp["storage_size"] = self.storage_size()
        tmp["version"] = self.version()
        tmp["format_id"] = self.format_id()
        return tmp

    # TODO:
    def serialized_property_value(self):
        raise NotImplementedError
        """
        if _mpb['format_id'].upper() == 'D5CDD5052E9C101B939708002B2CF9AE':
            # Serialized Property Value (String Name)
            index += 32
            result = []

            while True:
                value = {}
                value['value_size'] = unpack('<I', self.indata[index: index + 4])[0]
                if hex(value['value_size']) == hex(0x0):
                    break
                value['name_size'] = unpack('<I', self.indata[index + 4: index + 8])[0]
                value['name'] = self.read_unicode_string(index + 8)
                value['value'] = ''  # TODO MS-OLEPS

                result.append(value)
                index += 4 + 4 + 2 + value['name_size'] + value['value_size']

            _mpb['serialized_property_value_string'] = result
        else:
            # Serialized Property Value (Integer Name)
            index += 32
            result = []

            while True:
                value = {}
                value['value_size'] = unpack('<I', self.indata[index: index + 4])[0]
                if hex(value['value_size']) == hex(0x0):
                    break
                value['id'] = unpack('<I', self.indata[index + 4: index + 8])[0]
                value['value'] = ''  # TODO MS-OLEPS

                result.append(value)
                index += value['value_size']

            _mpb['serialized_property_value_integer'] = result
        """
