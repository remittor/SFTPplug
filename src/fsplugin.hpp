#pragma once

#pragma pack(push, 1)

namespace wfx {

// ids for FsGetFile
enum class FILE : int {
    OK                  = 0,
    EXISTS              = 1,
    NOTFOUND            = 2,
    READERROR           = 3,
    WRITEERROR          = 4,
    USERABORT           = 5,
    NOTSUPPORTED        = 6,
    EXISTSRESUMEALLOWED = 7,
};

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
    MsgOK            = 8,
    MsgYesNo         = 9,
    MsgOKCancel      = 10,
};

// flags for tLogProc
enum class MSGTYPE : int {
    CONNECT           = 1,
    DISCONNECT        = 2,
    DETAILS           = 3,
    TRANSFERCOMPLETE  = 4,
    CONNECTCOMPLETE   = 5,
    IMPORTANTERROR    = 6,
    OPERATIONCOMPLETE = 7,
};

enum class CRYPT : int {
    SAVE_PASSWORD       = 1,
    LOAD_PASSWORD       = 2,
    LOAD_PASSWORD_NO_UI = 3, // Load password only if master password has already been entered!
    COPY_PASSWORD       = 4, // Copy encrypted password to new connection name
    MOVE_PASSWORD       = 5, // Move password when renaming a connection
    DELETE_PASSWORD     = 6, // Delete password
};

// Progress task status
enum class TASK : int {
    CONTINUE = 0,
    ABORTED  = 1,
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

