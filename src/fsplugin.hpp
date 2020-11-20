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

enum class CopyFlags : int {
    Overwrite            = 0x01,
    Resume               = 0x02,
    Move                 = 0x04,
    ExistsSameCase       = 0x08,
    ExistsDifferentCase  = 0x10,
};

inline CopyFlags operator + (const CopyFlags & a1, const CopyFlags & a2)
{
    return (CopyFlags)((int)a1 | (int)a2);
}

inline CopyFlags operator | (const CopyFlags & a1, const CopyFlags & a2)
{
    return (CopyFlags)((int)a1 | (int)a2);
}

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

enum class CryptPass : int {
    Save        = 1,
    Load        = 2,
    LoadNoUI    = 3, // Load password only if master password has already been entered!
    Copy        = 4, // Copy encrypted password to new connection name
    Move        = 5, // Move password when renaming a connection
    Delete      = 6, // Delete password
};

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

