#pragma once

#include "global.h"

#ifdef SFTP_ALLINONE
#include <libssh2_config.h>
#include <libssh2.h>
#include <libssh2_sftp.h>
#else
#include "libssh2_config.h"
#include "libssh2.h"
#include "libssh2_sftp.h"
#endif

#include "libssh2_error.h"
#include "multiserver.h"
#include "utils.h"

#define SFTP_OK          0
#define SFTP_FAILED      1
#define SFTP_EXISTS      2
#define SFTP_READFAILED  3
#define SFTP_WRITEFAILED 4
#define SFTP_ABORT       5
#define SFTP_PARTIAL     6

namespace sftp {
enum error : int {
    kOk            = 0,
    kFailed        = 1,
    kExists        = 2,
    kReadFailed    = 3,
    kWriteFailed   = 4,
    kAbort         = 5,
    kPartial       = 6,
};
}

extern int PluginNumber;
extern char s_quickconnect[32];

namespace sftp {

enum class Proxy : int
{
    notused = 0,
    default = 1,
    http    = 2,
    socks4  = 3,
    socks5  = 4,
};

enum class PassSaveMode : int
{
    empty   = 0,   /* without password */
    crypt   = 1,   /* use TotalCmd as password agent */
    plain   = 2,   /* plaintext */
};

}

struct scp_opendir_data {
    int TempPathUniqueValue;
    HANDLE tempfile;
};

typedef struct {
    char DisplayName[MAX_PATH];
    char IniFileName[MAX_PATH];
    char server[MAX_PATH];
    char user[MAX_PATH];
    char password[MAX_PATH];
    char connectsendcommand[MAX_PATH];
    WCHAR lastactivepath[1024];
    char savedfingerprint[MAX_PATH];
    char pubkeyfile[MAX_PATH];
    char privkeyfile[MAX_PATH];
    int sendcommandmode;
    
    SOCKET sock;
    LIBSSH2_SESSION *session;
    LIBSSH2_SFTP *sftpsession; 
    
    bool useagent;
    int protocoltype; // 0 = auto,  1 = IPv4,  2 = IPv6
    int servernamelen;
    unsigned short customport;
    int filemod;
    int dirmod;
    bool scponly;
    bool scpfordata;
    bool dialogforconnection;
    bool compressed;
    bool detailedlog;
    bool neednewchannel;   // kill the sftp channel in case of an error
    SYSTICKS findstarttime; // time findfirstfile started, MUST be int
    char utf8names;        // 0=no, 1=yes, -1=auto-detect
    int codepage;          // only used when utf8names=0
    char unixlinebreaks;   // 0=no, 1=yes, -1=auto-detect
    int proxynr;           // 0=no proxy, >0 use entry  [proxy], [proxy2] etc.
    sftp::Proxy proxytype;
    char proxyserver[MAX_PATH];
    char proxyuser[MAX_PATH];
    char proxypassword[MAX_PATH];
    SYSTICKS lastpercenttime;
    int lastpercent;
    sftp::PassSaveMode passSaveMode;
    bool InteractivePasswordSent;
    int trycustomlistcommand;  // set to 2 initially, reduce to 1 or 0 if failing
    int keepAliveIntervalSeconds; // 0 (disabled) by default
    HWND hWndKeepAlive;
    int scpserver64bit;     // 0=no, 1=yes, -1, auto-detect -> Support file upload/download > 2GB only if SCP on server side is 64bit!
                            // There might be 32bit SCP implementations with large file support but we cannot detect it. 
    bool scpserver64bittemporary;  // true=user allowed transfers>2GB
} tConnectSettings, *pConnectSettings;

SERVERID SftpConnectToServer(LPCSTR DisplayName, LPCSTR inifilename, LPCSTR overridepass);
void SftpGetServerBasePathW(LPCWSTR DisplayName, LPWSTR RelativePath, size_t maxlen, LPCSTR inifilename);
bool SftpConfigureServer(LPCSTR DisplayName, LPCSTR inifilename);
int  SftpCloseConnection(SERVERID serverid);
int  SftpFindFirstFileW(SERVERID serverid, LPCWSTR remotedir, LPVOID * davdataptr);
int  SftpFindNextFileW(SERVERID serverid, LPVOID davdataptr, LPWIN32_FIND_DATAW FindData) noexcept;
int  SftpFindClose(SERVERID serverid, LPVOID davdataptr);

int  SftpCreateDirectoryW(SERVERID serverid, LPCWSTR Path);
int  SftpRenameMoveFileW(SERVERID serverid, LPCWSTR OldName, LPCWSTR NewName, bool Move, bool Overwrite, bool isdir);
int  SftpDownloadFileW(SERVERID serverid, LPCWSTR RemoteName, LPCWSTR LocalName, bool alwaysoverwrite, INT64 filesize, LPFILETIME ft, bool Resume);
int  SftpUploadFileW(SERVERID serverid, LPCWSTR LocalName, LPCWSTR RemoteName, bool Resume, bool setattr);
int  SftpDeleteFileW(SERVERID serverid, LPCWSTR RemoteName, bool isdir);
int  SftpSetAttr(SERVERID serverid, LPCSTR RemoteName, int NewAttr);
int  SftpSetDateTimeW(SERVERID serverid, LPCWSTR RemoteName, LPFILETIME LastWriteTime);
void SftpGetLastActivePathW(SERVERID serverid, LPWSTR RelativePath, size_t maxlen);
bool SftpChmodW(SERVERID serverid, LPCWSTR RemoteName, LPCWSTR chmod);
bool SftpLinkFolderTargetW(SERVERID serverid, LPWSTR RemoteName, size_t maxlen);
int  SftpQuoteCommand2(SERVERID serverid, LPCSTR remotedir, LPCSTR cmd, LPSTR reply, size_t replylen);
int  SftpQuoteCommand2W(SERVERID serverid, LPCWSTR remotedir, LPCWSTR cmd, LPSTR reply, size_t replylen);
bool SftpQuoteCommand(SERVERID serverid, LPCSTR remotedir, LPCSTR cmd);
void SftpShowPropertiesW(SERVERID serverid, LPCWSTR remotename);
void SftpSetTransferModeW(LPCWSTR mode);
bool SftpDetermineTransferModeW(LPCWSTR RemoteName);
bool SftpSupportsResume(SERVERID serverid);
int  SftpServerSupportsChecksumsW(SERVERID serverid, LPCWSTR RemoteName);
HANDLE SftpStartFileChecksumW(int ChecksumType, SERVERID serverid, LPCWSTR RemoteName);
int SftpGetFileChecksumResultW(bool WantResult, HANDLE ChecksumHandle, SERVERID serverid, LPSTR checksum, size_t maxlen);
