#pragma once

#include "libssh2_config.h"
#include "libssh2.h"
#include "libssh2_sftp.h"

#define SFTP_OK          0
#define SFTP_FAILED      1
#define SFTP_EXISTS      2
#define SFTP_READFAILED  3
#define SFTP_WRITEFAILED 4
#define SFTP_ABORT       5

extern int PluginNumber;
extern char s_quickconnect[32];

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
    WCHAR lastactivepath[1024];
    char savedfingerprint[MAX_PATH];
    char pubkeyfile[MAX_PATH];
    char privkeyfile[MAX_PATH];
    
    SOCKET sock;
    LIBSSH2_SESSION *session;
    LIBSSH2_SFTP *sftpsession; 
    
    BOOL useagent;
    int protocoltype; // 0 = auto,  1 = IPv4,  2 = IPv6
    int servernamelen;
    unsigned short customport;
    int filemod;
    int dirmod;
    BOOL scpfordata;
    BOOL dialogforconnection;
    BOOL compressed;
    BOOL detailedlog;
    BOOL neednewchannel;   // kill the sftp channel in case of an error
    int findstarttime;     // time findfirstfile started, MUST be int
    char utf8names;        // 0=no, 1=yes, -1=auto-detect
    int codepage;          // only used when utf8names=0
    char unixlinebreaks;   // 0=no, 1=yes, -1=auto-detect
    int proxynr;       // 0=no proxy, >0 use entry  [proxy], [proxy2] etc.
    int proxytype;         // 0=no, 1=default, 2=custom
    char proxyserver[MAX_PATH];
    char proxyuser[MAX_PATH];
    char proxypassword[MAX_PATH];
    DWORD lastpercenttime;
    int lastpercent;
    int passSaveMode;
    BOOL InteractivePasswordSent;
} tConnectSettings, *pConnectSettings;

void* SftpConnectToServer(char* DisplayName, char* inifilename, char* overridepass);
void SftpGetServerBasePathW(WCHAR* DisplayName, WCHAR* RelativePath, int maxlen, char* inifilename);
BOOL SftpConfigureServer(char* DisplayName, char* inifilename);
int  SftpCloseConnection(void* serverid);
int  SftpFindFirstFileW(void* serverid, WCHAR* remotedir, void** davdataptr);
BOOL SftpFindNextFileW(void* serverid, void* davdataptr, WIN32_FIND_DATAW *FindData);
int  SftpFindClose(void* serverid, void* davdataptr);

int  SftpCreateDirectoryW(void* serverid, WCHAR* Path);
int  SftpRenameMoveFileW(void* serverid, WCHAR* OldName, WCHAR* NewName, BOOL Move, BOOL Overwrite, BOOL isdir);
int  SftpDownloadFileW(void* serverid, WCHAR* RemoteName, WCHAR* LocalName, BOOL alwaysoverwrite, __int64 filesize, FILETIME *ft, BOOL Resume);
int  SftpUploadFileW(void* serverid, WCHAR* LocalName, WCHAR* RemoteName, BOOL Resume, BOOL setattr);
int  SftpDeleteFileW(void* serverid, WCHAR* RemoteName, BOOL isdir);
int  SftpSetAttr(void* serverid, char* RemoteName, int NewAttr);
int  SftpSetDateTimeW(void* serverid, WCHAR* RemoteName, FILETIME *LastWriteTime);
void SftpGetLastActivePathW(void* serverid, WCHAR* RelativePath, int maxlen);
BOOL SftpDeleteBeforeUpload(void* serverid);
BOOL SftpChmodW(void* serverid, WCHAR* RemoteName, WCHAR* chmod);
BOOL SftpLinkFolderTargetW(void* serverid, WCHAR* RemoteName, int maxlen);
BOOL SftpQuoteCommand2(void* serverid, char* remotedir, char* cmd, char* reply, int replylen);
BOOL SftpQuoteCommand2W(void* serverid, WCHAR* remotedir, WCHAR* cmd, char* reply, int replylen);
BOOL SftpQuoteCommand(void* serverid, char* remotedir, char* cmd);
void SftpShowPropertiesW(void* serverid, WCHAR* remotename);
void SftpSetTransferModeW(WCHAR* mode);
BOOL SftpDetermineTransferModeW(WCHAR* RemoteName);

