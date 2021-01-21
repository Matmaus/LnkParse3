from struct import unpack
from LnkParse3.extra.lnk_extra_base import LnkExtraBase
from LnkParse3.decorators import must_be
from LnkParse3.decorators import uuid

"""
------------------------------------------------------------------
|     0-7b     |     8-15b     |     16-23b     |     24-31b     |
------------------------------------------------------------------
|              <u_int32> BlockSize == 0x00000060                 |
------------------------------------------------------------------
|            <u_int32> BlockSignature == 0xA0000003              |
------------------------------------------------------------------
|                      <u_int32> Length                          |
------------------------------------------------------------------
|                      <u_int32> Version                         |
------------------------------------------------------------------
|                       <str> MachineID                          |
|                             16 B                               |
------------------------------------------------------------------
|                    <GUID> DroidVolumeId                        |
|                             16 B                               |
------------------------------------------------------------------
|                     <GUID> DroidFileId                         |
|                             16 B                               |
------------------------------------------------------------------
|                  <GUID> DroidBirthVolumeId                     |
|                             16 B                               |
------------------------------------------------------------------
|                   <GUID> DroidBirthFileId                      |
|                             16 B                               |
------------------------------------------------------------------
"""


class DistributedTracker(LnkExtraBase):
    def name(self):
        return "DISTRIBUTED_LINK_TRACKER_BLOCK"

    @must_be(0x00000058)
    def length(self):
        """Length (4 bytes):
        A 32-bit, unsigned integer that specifies the size of the rest of the
        TrackerDataBlock structure, including this Length field. This value
        MUST be 0x00000058.
        """
        start, end = 8, 12
        length = unpack("<I", self._raw[start:end])[0]
        return length

    @must_be(0x00000000)
    def version(self):
        """Version (4 bytes):
        A 32-bit, unsigned integer. This value MUST be 0x00000000.
        """
        start, end = 12, 16
        version = unpack("<I", self._raw[start:end])[0]
        return version

    def machine_id(self):
        """MachineID (16 bytes):
        A NULL-terminated character string, as defined by
        the system default code
        """
        start = 16
        end = start + 16
        binary = self._raw[start:end]
        text = self.text_processor.read_string(binary)
        return text

    @uuid
    def droid_volume_id(self):
        start, end = 32, 48
        binary = self._raw[start:end]
        return binary

    @uuid
    def droid_file_id(self):
        start, end = 48, 64
        binary = self._raw[start:end]
        return binary

    @uuid
    def droid_birth_volume_id(self):
        start, end = 64, 80
        binary = self._raw[start:end]
        return binary

    @uuid
    def droid_birth_file_id(self):
        start, end = 80, 96
        binary = self._raw[start:end]
        return binary

    def as_dict(self):
        tmp = super().as_dict()
        tmp["length"] = self.length()
        tmp["version"] = self.version()
        tmp["machine_identifier"] = self.machine_id()
        tmp["droid_volume_identifier"] = self.droid_volume_id()
        tmp["droid_file_identifier"] = self.droid_file_id()
        tmp["birth_droid_volume_identifier"] = self.droid_birth_volume_id()
        tmp["birth_droid_file_identifier"] = self.droid_birth_file_id()
        return tmp
