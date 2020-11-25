#pragma once

#pragma pack(push, 1)

namespace wfx {

// ids for FsGetFile
enum class File : int {
    Ok                  = 0,
    Exists              = 1,
    NotFound            = 2,
    ReadError           = 3,
    WriteError          = 4,
    UserAbort           = 5,
    NotSupported        = 6,
    ExistsResumeAllowed = 7,
};

enum class Exec : int {
    Ok         =  0,
    Error      =  1,
    YourSelf   = -1,
    SymLink    = -2,
};

template <typename T>
inline bool has_flag(T a1, T a2)
{
    return ((int)a1 & (int)a2) != 0;
}

template <typename T>
inline bool has_any_flag(T a1, T a2)
{
    return ((int)a1 & (int)a2) != 0;
}

template <typename T>
inline bool has_all_flags(T a1, T a2)
{
    return ((int)a1 & (int)a2) == (int)a2;
}

enum class CopyFlag : int {
    _Empty               = 0x00,
    Overwrite            = 0x01,
    Resume               = 0x02,
    Move                 = 0x04,
    ExistsSameCase       = 0x08,
    ExistsDifferentCase  = 0x10,
};
typedef CopyFlag  CopyFlags;
inline CopyFlag operator & (const CopyFlag & a1, const CopyFlag & a2) { return (CopyFlag)((int)a1 & (int)a2); }
inline CopyFlag operator | (const CopyFlag & a1, const CopyFlag & a2) { return (CopyFlag)((int)a1 | (int)a2); }

// flags for tRequestProc
enum class RT : int {
    Other            = 0,
    UserName         = 1,
    Password         = 2,
    Account          = 3,
    UserNameFirewall = 4,
    PasswordFirewall = 5,
    TargetDir        = 6,
    URL              = 7,
    MsgOk            = 8,
    MsgYesNo         = 9,
    MsgOkCancel      = 10,
};

// flags for tLogProc
enum class MsgType : int {
    Connect           = 1,
    Disconnect        = 2,
    Details           = 3,
    TransferComplete  = 4,
    ConnectComplete   = 5,
    ImportantError    = 6,
    OperationComplete = 7,
};

// flags for FsStatusInfo
enum class OperStatus : int {
    Start = 0,
    End   = 1,
};

enum class OpStatus : int {
    List           =  1,
    GetSingle      =  2,
    GetMulti       =  3,
    PutSingle      =  4,
    PutMulti       =  5, 
    RenMovSingle   =  6,
    RenMovMulti    =  7,
    Delete         =  8,
    Attrib         =  9,
    MkDir          = 10,
    Exec           = 11,
    CalcSize       = 12,
    Search         = 13,
    SearchText     = 14,
    SyncSearch     = 15,
    SyncGet        = 16,
    SyncPut        = 17,
    SyncDelete     = 18,
    GetMultiThread = 19,
    PutMultiThread = 20,
};

enum class Icon : int {
    UserDefault      = 0,
    Extracted        = 1,
    ExtractedDestroy = 2,
    Delayed          = 3,
};

enum class IconFlag : int {
    Small        = 0x01,
    Background   = 0x02,
};
typedef IconFlag  IconFlags;
inline IconFlag operator & (const IconFlag & a1, const IconFlag & a2) { return (IconFlag)((int)a1 & (int)a2); }
inline IconFlag operator | (const IconFlag & a1, const IconFlag & a2) { return (IconFlag)((int)a1 | (int)a2); }


enum class CryptPass : int {
    Save        = 1,
    Load        = 2,
    LoadNoUI    = 3, // Load password only if master password has already been entered!
    Copy        = 4, // Copy encrypted password to new connection name
    Move        = 5, // Move password when renaming a connection
    Delete      = 6, // Delete password
};

enum class CryptFlag : int {
    MasterPassSet = 0x01,    // The user already has a master password defined
};
typedef CryptFlag  CryptFlags;
inline CryptFlag operator & (const CryptFlag & a1, const CryptFlag & a2) { return (CryptFlag)((int)a1 & (int)a2); }
inline CryptFlag operator | (const CryptFlag & a1, const CryptFlag & a2) { return (CryptFlag)((int)a1 | (int)a2); }


enum class BkGrFlag : int {
    Download    = 0x01,      // Plugin supports downloads in background
    Upload      = 0x02,      // Plugin supports uploads in background
    AskUser     = 0x04,      // Plugin requires separate connection for background transfers -> ask user first
};
typedef BkGrFlag  BkGrFlags;
inline BkGrFlag operator & (const BkGrFlag & a1, const BkGrFlag & a2) { return (BkGrFlag)((int)a1 & (int)a2); }
inline BkGrFlag operator | (const BkGrFlag & a1, const BkGrFlag & a2) { return (BkGrFlag)((int)a1 | (int)a2); }

enum class HashFlag : int {
    _Empty      = 0,
    CRC32       = 0x0001,
    MD5         = 0x0002,
    SHA1        = 0x0004,
    SHA256      = 0x0008,
    SHA512      = 0x0010,
    OTHER       = 0x0200,
};
typedef HashFlag  HashFlags;
inline HashFlag operator & (const HashFlag & a1, const HashFlag & a2) { return (HashFlag)((int)a1 & (int)a2); }
inline HashFlag operator | (const HashFlag & a1, const HashFlag & a2) { return (HashFlag)((int)a1 | (int)a2); }

enum class HashError : int {
    Busy    = -1,        // Checksum calculation still active, try again
    Fail    = -2,        // Failed to get checksum
};

const INT64 TimeUnknown = -2LL;      // Use the following settings for files which don't have a time

const DWORD AttrUnixMode = 0x80000000;   // for Unix systems: set the dwReserved0 parameter to the Unix file mode (permissions).

// Progress task status
enum class TaskStatus : int {
    Continue = 0,
    Aborted  = 1,
};


typedef struct {
    union {
        struct {
            DWORD SizeLow;
            DWORD SizeHigh;
        };
        INT64 Size64;
    };
    union {
        FILETIME LastWriteTime;
        INT64   iLastWriteTime;
    };
    DWORD Attr;
} RemoteFileInfo, *PRemoteFileInfo;

typedef struct {
    int   size;
    DWORD PluginInterfaceVersionLow;
    DWORD PluginInterfaceVersionHi;
    char  DefaultIniName[MAX_PATH];
} PluginDefaultParam;


} /* namespace */

#pragma pack(pop)

