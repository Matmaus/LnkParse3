from struct import unpack
from LnkParse3.decorators import must_be
from LnkParse3.decorators import uuid
from LnkParse3.decorators import filetime

"""
SHELL_LINK_HEADER:
A ShellLinkHeader structure (section 2.1), which contains identification
information, timestamps, and flags that specify the presence of optional
structures.

------------------------------------------------------------------
|     0-7b     |     8-15b     |     16-23b     |     24-31b     |
------------------------------------------------------------------
|             <u_int32> HeaderSize == 0x0000004C                 |
------------------------------------------------------------------
|   <CSID> LinkCLSID == 00021401-0000-0000-C000-000000000046     |
|                            16 B                                |
------------------------------------------------------------------
|                     <flags> LinkFlags                          |
------------------------------------------------------------------
|                   <flags> FileAttributes                       |
------------------------------------------------------------------
|                  <FILETIME> CreationTime                       |
|                            16 B                                |
------------------------------------------------------------------
|                   <FILETIME> AccessTime                        |
|                            16 B                                |
------------------------------------------------------------------
|                   <FILETIME> WriteTime                         |
|                            16 B                                |
------------------------------------------------------------------
|                   <u_int32> FileSize                           |
------------------------------------------------------------------
|                   <int32> IconIndex                            |
------------------------------------------------------------------
|                 <u_int32> ShowCommand                          |
------------------------------------------------------------------
|   <HotKeyFlags> HotKey      |            Reserved1             |
------------------------------------------------------------------
|                        Reserved2                               |
------------------------------------------------------------------
|                        Reserved3                               |
------------------------------------------------------------------
"""


class LnkHeader:
    # https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-showwindow
    WINDOW_STYLES = {
        1: "SW_SHOWNORMAL",
        3: "SW_SHOWMAXIMIZED",
        7: "SW_SHOWMINNOACTIVE",
    }

    HOTKEY_VALUES_HIGH = {
        b"\x00": "UNSET",
        b"\x01": "SHIFT",
        b"\x02": "CONTROL",
        b"\x04": "ALT",
    }

    HOTKEY_VALUES_LOW = {
        b"\x00": "UNSET",
        b"\x30": "0",
        b"\x31": "1",
        b"\x32": "2",
        b"\x33": "3",
        b"\x34": "4",
        b"\x35": "5",
        b"\x36": "6",
        b"\x37": "7",
        b"\x38": "8",
        b"\x39": "9",
        b"\x41": "A",
        b"\x42": "B",
        b"\x43": "C",
        b"\x44": "D",
        b"\x45": "E",
        b"\x46": "F",
        b"\x47": "G",
        b"\x48": "H",
        b"\x49": "I",
        b"\x4A": "J",
        b"\x4B": "K",
        b"\x4C": "L",
        b"\x4D": "M",
        b"\x4E": "N",
        b"\x4F": "O",
        b"\x50": "P",
        b"\x51": "Q",
        b"\x52": "R",
        b"\x53": "S",
        b"\x54": "T",
        b"\x55": "U",
        b"\x56": "V",
        b"\x57": "W",
        b"\x58": "X",
        b"\x59": "Y",
        b"\x5A": "Z",
        b"\x70": "F1",
        b"\x71": "F2",
        b"\x72": "F3",
        b"\x73": "F4",
        b"\x74": "F5",
        b"\x75": "F6",
        b"\x76": "F7",
        b"\x77": "F8",
        b"\x78": "F9",
        b"\x79": "F10",
        b"\x7A": "F11",
        b"\x7B": "F12",
        b"\x7C": "F13",
        b"\x7D": "F14",
        b"\x7E": "F15",
        b"\x7F": "F16",
        b"\x80": "F17",
        b"\x81": "F18",
        b"\x82": "F19",
        b"\x83": "F20",
        b"\x84": "F21",
        b"\x85": "F22",
        b"\x86": "F23",
        b"\x87": "F24",
        b"\x90": "NUM_LOCK",
        b"\x91": "SCROLL_LOCK",
    }

    LINK_FLAG_MASK = {  # {{{
        # LinkTargetIDList structure (section 2.2) MUST follow the
        # ShellLinkHeader. If this bit is not set, this structure MUST NOT
        # be present.
        0x00000001: "HasTargetIDList",
        # The shell link is saved with link information. If this bit is set,
        # a LinkInfo structure (section 2.3) MUST be present. If this bit
        # is not set, this structure MUST NOT be present.
        0x00000002: "HasLinkInfo",
        # The shell link is saved with a name string. If this bit is set,
        # a NAME_STRING StringData structure (section 2.4) MUST be present.
        # If this bit is not set, this structure MUST NOT be present.
        0x00000004: "HasName",
        # The shell link is saved with a relative path string. If this bit
        # is set, a RELATIVE_PATH StringData structure (section 2.4) MUST
        # be present. If this bit is not set, this structure MUST NOT be
        # present.
        0x00000008: "HasRelativePath",
        # The shell link is saved with a working directory string. If this
        # bit is set, a WORKING_DIR StringData structure (section 2.4) MUST
        # be present. If this bit is not set, this structure MUST NOT be
        # present.
        0x00000010: "HasWorkingDir",
        # The shell link is saved with command line arguments. If this bit
        # is set, a COMMAND_LINE_ARGUMENTS StringData structure (section
        # 2.4) MUST be present. If this bit is not set, this structure MUST
        # NOT be present.
        0x00000020: "HasArguments",
        # The shell link is saved with an icon location string. If this bit
        # is set, an ICON_LOCATION StringData structure (section 2.4) MUST
        # be present. If this bit is not set, this structure MUST NOT be
        # present.
        0x00000040: "HasIconLocation",
        # The shell link contains Unicode encoded strings. This bit SHOULD
        # be set. If this bit is set, the StringData section contains
        # Unicode-encoded strings; otherwise, it contains strings that are
        # encoded using the system default code page.
        0x00000080: "IsUnicode",
        # The LinkInfo structure (section 2.3) is ignored.
        0x00000100: "ForceNoLinkInfo",
        # The shell link is saved with an EnvironmentVariableDataBlock
        # (section 2.5.4).
        0x00000200: "HasExpString",
        # The target is run in a separate virtual machine when launching
        # a link target that is a 16-bit application.
        0x00000400: "RunInSeparateProcess",
        # TODO: Unused1
        # A bit that is undefined and MUST be ignored.
        0x00000800: "Reserved0",
        # The shell link is saved with a DarwinDataBlock (section 2.5.3).
        0x00001000: "HasDarwinID",
        # The application is run as a different user when the target of the
        # shell link is activated.
        0x00002000: "RunAsUser",
        # The shell link is saved with an IconEnvironmentDataBlock (section
        # 2.5.5).
        0x00004000: "HasExpIcon",
        # The file system location is represented in the shell namespace
        # when the path to an item is parsed into an IDList.
        0x00008000: "NoPidlAlias",
        # TODO: Unused2
        # A bit that is undefined and MUST be ignored.
        0x00010000: "Reserved1",
        # The shell link is saved with a ShimDataBlock (section 2.5.8).
        0x00020000: "RunWithShimLayer",
        # The TrackerDataBlock (section 2.5.10) is ignored.
        0x00040000: "ForceNoLinkTrack",
        # The shell link attempts to collect target properties and store
        # them in the PropertyStoreDataBlock (section 2.5.7) when the link
        # target is set.
        0x00080000: "EnableTargetMetadata",
        # The EnvironmentVariableDataBlock is ignored.
        0x00100000: "DisableLinkPathTracking",
        # The SpecialFolderDataBlock (section 2.5.9) and the
        # KnownFolderDataBlock (section 2.5.6) are ignored when loading the
        # shell link. If this bit is set, these extra data blocks SHOULD
        # NOT be saved when saving the shell link.
        0x00200000: "DisableKnownFolderTracking",
        # If the link has a KnownFolderDataBlock (section 2.5.6), the
        # unaliased form of the known folder IDList SHOULD be used when
        # translating the target IDList at the time that the link is
        # loaded.
        0x00400000: "DisableKnownFolderAlias",
        # Creating a link that references another link is enabled.
        # Otherwise, specifying a link as the target IDList SHOULD NOT be
        # allowed.
        0x00800000: "AllowLinkToLink",
        # When saving a link for which the target IDList is under a known
        # folder, either the unaliased form of that known folder or the
        # target IDList SHOULD be used.
        0x01000000: "UnaliasOnSave",
        # The target IDList SHOULD NOT be stored; instead, the path
        # specified in the 2.1.2 FileAttributesFlags
        # EnvironmentVariableDataBlock (section 2.5.4) SHOULD be used to
        # refer to the target.
        0x02000000: "PreferEnvironmentPath",
        # When the target is a UNC name that refers to a location on
        # a local machine, the local path IDList in the
        # PropertyStoreDataBlock (section 2.5.7) SHOULD be stored, so it
        # can be used when the link is loaded on the local machine.
        0x04000000: "KeepLocalIDListForUNCTarget",
    }  # }}}

    FILE_FLAG_MASK = {  # {{{
        # The file or directory is read-only. For a file, if this bit is set,
        # applications can read the file but cannot write to it or delete it.
        # For a directory, if this bit is set, applications cannot delete the
        # directory.
        0x00000001: "FILE_ATTRIBUTE_READONLY",
        # The file or directory is hidden. If this bit is set, the file or
        # folder is not included in an ordinary directory listing.
        0x00000002: "FILE_ATTRIBUTE_HIDDEN",
        # The file or directory is part of the operating system or is used
        # exclusively by the operating system.
        0x00000004: "FILE_ATTRIBUTE_SYSTEM",
        # TODO: Reserved1
        # A bit that MUST be zero.
        0x00000008: "Reserved, not used by the LNK format",
        # The link target is a directory instead of a file.
        0x00000010: "FILE_ATTRIBUTE_DIRECTORY",
        # The file or directory is an archive file. Applications use this flag
        # to mark files for backup or removal.
        0x00000020: "FILE_ATTRIBUTE_ARCHIVE",
        # A bit that MUST be zero.
        0x00000040: "FILE_ATTRIBUTE_DEVICE",
        # The file or directory has no other flags set. If this bit is 1, all
        # other bits in this structure MUST be clear.
        0x00000080: "FILE_ATTRIBUTE_NORMAL",
        # The file is being used for temporary storage.
        0x00000100: "FILE_ATTRIBUTE_TEMPORARY",
        # The file is a sparse file.
        0x00000200: "FILE_ATTRIBUTE_SPARSE_FILE",
        # The file or directory has an associated reparse point.
        0x00000400: "FILE_ATTRIBUTE_REPARSE_POINT",
        # The file or directory is compressed. For a file, this means that all
        # data in the file is compressed. For a directory, this means that
        # compression is the default for newly created files and
        # subdirectories.
        0x00000800: "FILE_ATTRIBUTE_COMPRESSED",
        # The data of the file is not immediately available.
        0x00001000: "FILE_ATTRIBUTE_OFFLINE",
        # The contents of the file need to be indexed.
        0x00002000: "FILE_ATTRIBUTE_NOT_CONTENT_INDEXED",
        # The file or directory is encrypted. For a file, this means that all
        # data in the file is encrypted. For a directory, this means that
        # encryption is the default for newly created files and subdirectories.
        0x00004000: "FILE_ATTRIBUTE_ENCRYPTED",
        # The directory or user data stream is configured with integrity
        # (only supported on ReFS volumes).
        0x00008000: "FILE_ATTRIBUTE_INTEGRITY_STREAM",
        # Is virtual
        0x00010000: "FILE_ATTRIBUTE_VIRTUAL",
        # The user data stream not to be read by the background data
        # integrity scanner (AKA scrubber).
        0x00020000: "FILE_ATTRIBUTE_NO_SCRUB_DATA",
    }  # }}}

    def __init__(self, fhandle=None, indata=None):
        if fhandle:
            self._raw = fhandle.read()
        elif indata:
            self._raw = indata

        self._lnk_header = {}
        self._stash = {}

        self._raw = self._raw[: self.size()]

    @must_be(int("0x0000004C", 16))
    def size(self):
        """HeaderSize (4 bytes):
        The size, in bytes, of this structure.
        This value MUST be 0x0000004C.
        """
        start, end = 0, 4
        size = unpack("<I", self._raw[start:end])[0]
        return size

    @must_be("00021401-0000-0000-C000-000000000046")
    @uuid
    def link_cls_id(self):
        """LinkCLSID (16 bytes):
        A class identifier (CLSID).
        This value MUST be 00021401-0000-0000-C000-000000000046.
        """
        return self._raw[4:20]

    def guid(self):
        return self.link_cls_id()

    def r_link_flags(self):
        """LinkFlags (4 bytes):
        A LinkFlags structure (section 2.1.1) that specifies information about
        the shell link and the presence of optional portions of the structure.
        """
        start, end = 20, 24
        flags = unpack("<I", self._raw[start:end])[0]
        return flags

    def link_flags(self):
        """
        The LinkFlags structure defines bits that specify which shell link
        structures are present in the file format after the ShellLinkHeader
        structure (section 2.1).
        """
        items = sorted(self.LINK_FLAG_MASK.items())
        flag = self.r_link_flags()
        return [key for mask, key in items if bool(flag & mask)]

    def r_file_flags(self):
        """FileAttributes (4 bytes):
        A FileAttributesFlags structure (section 2.1.2) that specifies
        information about the link target.
        """
        start, end = 24, 28
        flags = unpack("<I", self._raw[start:end])[0]
        return flags

    def file_flags(self):
        """
        The FileAttributesFlags structure defines bits that specify the file
        attributes of the link target, if the target is a file system item.
        File attributes can be used if the link target is not available, or if
        accessing the target would be inefficient. It is possible for the
        target items attributes to be out of sync with this value.
        """
        items = sorted(self.FILE_FLAG_MASK.items())
        flag = self.r_file_flags()
        return [key for mask, key in items if bool(flag & mask)]

    @filetime
    def creation_time(self):
        """CreationTime (8 bytes):
        A FILETIME structure ([MS-DTYP] section 2.3.3) that specifies the
        creation time of the link target in UTC (Coordinated Universal Time).
        If the value is zero, there is no creation time set on the link target.
        """
        start, end = 28, 36
        return self._raw[start:end]

    @filetime
    def access_time(self):
        """AccessTime (8 bytes):
        A FILETIME structure ([MS-DTYP] section 2.3.3) that specifies the
        access time of the link target in UTC (Coordinated Universal Time). If
        the value is zero, there is no access time set on the link target.
        """
        start, end = 36, 44
        return self._raw[start:end]

    @filetime
    def write_time(self):
        """WriteTime (8 bytes):
        A FILETIME structure ([MS-DTYP] section 2.3.3) that specifies the write
        time of the link target in UTC (Coordinated Universal Time). If the
        value is zero, there is no write time set on the link target.
        """
        start, end = 44, 52
        return self._raw[start:end]

    def file_size(self):
        """FileSize (4 bytes):
        A 32-bit unsigned integer that specifies the size, in bytes, of the
        link target. If the link target file is larger than 0xFFFFFFFF, this
        value specifies the least significant 32 bits of the link target file
        size.
        """
        start, end = 52, 56
        size = unpack("<I", self._raw[start:end])[0]
        return size

    def icon_index(self):
        """IconIndex (4 bytes):
        A 32-bit signed integer that specifies the index of an icon within
        a given icon location.
        """
        start, end = 56, 60
        index = unpack("<i", self._raw[start:end])[0]
        return index

    # TODO: rename to show_command
    def window_style(self):
        """ShowCommand (4 bytes):
        A 32-bit unsigned integer that specifies the expected window state of
        an application launched by the link. This value SHOULD be one of the
        following.

        * SW_SHOWNORMAL 0x00000001
            The application is open and its window is open in a normal fashion.

        * SW_SHOWMAXIMIZED 0x00000003
            The application is open, and keyboard focus is given to the
            application, but its window is not shown.

        * SW_SHOWMINNOACTIVE 0x00000007
            The application is open, but its window is not shown. It is not
            given the keyboard focus.

        All other values MUST be treated as SW_SHOWNORMAL.
        """
        start, end = 60, 64
        style = unpack("<i", self._raw[start:end])[0]
        fallback = self.WINDOW_STYLES[1]
        return self.WINDOW_STYLES.get(style, fallback)

    # TODO: See _raw_hot_key
    def hot_key(self):
        start, end = 64, 66
        hot_key = self._raw[start:end]
        b_low, b_high = unpack("<cc", hot_key)

        high = self.HOTKEY_VALUES_HIGH.get(b_high)
        low = self.HOTKEY_VALUES_LOW.get(b_low)

        if high and low:
            return "%s - %s {0x%s}" % (high, low, hot_key.hex())
        else:
            return hot_key.hex()

    def raw_hot_key(self):
        """HotKey (2 bytes):
        A HotKeyFlags structure (section 2.1.3) that specifies the keystrokes
        used to launch the application referenced by the shortcut key. This
        value is assigned to the application after it is launched, so that
        pressing the key activates that application.
        """
        start, end = 64, 66
        raw = unpack("<H", self._raw[start:end])[0]
        return raw

    # TODO: rename to reserved1
    @must_be(0)
    def reserved0(self):
        """Reserved1 (2 bytes):
        A value that MUST be zero.
        """
        start, end = 66, 68
        raw = unpack("<H", self._raw[start:end])[0]
        return raw

    # TODO: rename to reserved2
    @must_be(0)
    def reserved1(self):
        """Reserved2 (4 bytes):
        A value that MUST be zero.
        """
        start, end = 68, 72
        raw = unpack("<I", self._raw[start:end])[0]

        return raw

    # TODO: rename to reserved3
    @must_be(0)
    def reserved2(self):
        """Reserved3 (4 bytes):
        A value that MUST be zero.
        """
        start, end = 72, 76
        raw = unpack("<I", self._raw[start:end])[0]

        return raw
