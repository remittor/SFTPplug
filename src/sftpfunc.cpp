#include <windows.h>
#include <stdio.h>
#include <fcntl.h>
#include "sftpfunc.h"
#include "sftpplug.h"
#include "fsplugin.h"
#include "multiserver.h"
#include "res/resource.h"
#include "utils.h"
#include "CVTUTF.H"
#include <afxres.h>
#include "cunicode.h"
#include "ftpdir.h"

#include <map>

#ifdef _WIN64
#define myint INT_PTR
#define myuint UINT_PTR
#else
#define myint int
#define myuint UINT
#endif

BOOL serverfieldchangedbyuser = false;
char Global_TransferMode = 'I';  //I=Binary,  A=Ansi,  X=Auto
WCHAR Global_TextTypes[1024];
char global_detectcrlf = 0;

std::map<HWND, pConnectSettings> ghWndToConnectSettings;

// Will be initialized when loading the SSH DLL
BOOL SSH_ScpNeedBlockingMode = true;  // Need to use blocking mode for SCP?
BOOL SSH_ScpNeedQuote = true;  // Need to use double quotes "" around names with spaces for SCP?
BOOL SSH_ScpCanSendKeepAlive = false;
BOOL SSH_ScpNo2GBLimit = false;

VOID CALLBACK TimerProc(HWND hwnd, UINT uMsg, myuint idEvent, DWORD dwTime);

LIBSSH2_CHANNEL* ConnectChannel(LIBSSH2_SESSION *session);
BOOL SendChannelCommand(LIBSSH2_SESSION *session, LIBSSH2_CHANNEL *channel,char* command);
BOOL GetChannelCommandReply(LIBSSH2_SESSION *session, LIBSSH2_CHANNEL *channel, char* command);
void DisconnectShell(LIBSSH2_CHANNEL *channel);
void StripEscapeSequences(char *msgbuf);
BOOL ReadChannelLine(LIBSSH2_CHANNEL *channel, char *line, int linelen, char* msgbuf, int msgbuflen, char* errbuf, int errbuflen);
int CloseRemote(void* serverid, LIBSSH2_SFTP_HANDLE *remotefilesftp, LIBSSH2_CHANNEL *remotefilescp, BOOL timeout, int percent);

//****************** declarations for ipv6: ****************************/
#define AF_INET6        23

typedef struct addrinfo
{
    int                 ai_flags;       // AI_PASSIVE,  AI_CANONNAME,  AI_NUMERICHOST
    int                 ai_family;      // PF_xxx
    int                 ai_socktype;    // SOCK_xxx
    int                 ai_protocol;    // 0 or IPPROTO_xxx for IPv4 and IPv6
    size_t              ai_addrlen;     // Length of ai_addr
    char *              ai_canonname;   // Canonical name for nodename
    struct sockaddr *   ai_addr;        // Binary address
    struct addrinfo *   ai_next;        // Next structure in linked list
}
ADDRINFOA,  *PADDRINFOA;

typedef struct {
    short   sin6_family;        /* AF_INET6 */
    u_short sin6_port;          /* Transport level port number */
    u_long  sin6_flowinfo;      /* IPv6 flow information */
    u_char sin6_addr[16];       /* IPv6 address */
    u_long sin6_scope_id;       /* set of interfaces for a scope */
} sockaddr_in6, *psockaddr_in6;

typedef ADDRINFOA       ADDRINFO,  FAR * LPADDRINFO;

typedef  int (__stdcall* tgetaddrinfo)(IN const char FAR * nodename,
                                    IN const char FAR * servname,
                                    IN const struct addrinfo FAR * hints,
                                    OUT struct addrinfo FAR * FAR * res);
typedef int (__stdcall* tfreeaddrinfo)(IN  LPADDRINFO      pAddrInfo);
typedef int (__stdcall* tWSAAddressToStringA)(
    IN     LPSOCKADDR          lpsaAddress,
    IN     DWORD               dwAddressLength,
    IN     void*               lpProtocolInfo,
    IN OUT LPSTR               lpszAddressString,
    IN OUT LPDWORD             lpdwAddressStringLength);

tgetaddrinfo getaddrinfo = NULL;
tfreeaddrinfo freeaddrinfo = NULL;
tWSAAddressToStringA WSAAddressToString = NULL;

typedef struct {
    LIBSSH2_CHANNEL *channel;
    char msgbuf[2048];   // previously received data
    char errbuf[2048];
} SCP_DATA;

BOOL EscapePressed()
{
    // Abort with ESCAPE pressed in same program only!
    if (GetAsyncKeyState(VK_ESCAPE) < 0) {
        DWORD procid1;
        HWND hwnd = GetActiveWindow();
        if (hwnd) {
            GetWindowThreadProcessId(hwnd, &procid1);
            if (procid1 == GetCurrentProcessId())
                return true;
        }
    }
    return false;
}

void strlcpyansitoutf8(LPSTR utf8str, LPCSTR ansistr, size_t maxlen)
{
    WCHAR utf16buf[1024];
    MultiByteToWideChar(CP_ACP, 0, ansistr, -1, utf16buf, _countof(utf16buf));
    ConvUTF16toUTF8(utf16buf, 0, utf8str, maxlen);
}

void wcslcpytoutf8(LPSTR utf8str, LPCWSTR utf16str, size_t maxlen)
{
    ConvUTF16toUTF8(utf16str, 0, utf8str, maxlen);
}

void CopyStringW2A(pConnectSettings ConnectSettings, LPCWSTR instr, LPSTR outstr, size_t outmax) noexcept
{
    if (ConnectSettings->utf8names) {
        ConvUTF16toUTF8(instr, 0, outstr, outmax);
    } else {
        walcopyCP(ConnectSettings->codepage, outstr, instr, outmax - 1);
    }
}

void CopyStringA2W(pConnectSettings ConnectSettings, LPCSTR instr, LPWSTR outstr, size_t outmax, bool useCVT = true) noexcept
{
    if (ConnectSettings->utf8names) {
        if (useCVT)
            ConvUTF8toUTF16(instr, 0, outstr, outmax);
        else
            awlcopyCP(CP_UTF8, outstr, instr, outmax - 1);
    } else {
        awlcopyCP(ConnectSettings->codepage, outstr, instr, outmax - 1);
    }
}

//#define FUNCDEF(f, p) (*f) p // define the functions as pointers
//#define FUNCDEF(f, p) WINAPI f p

HINSTANCE sshlib = NULL;
BOOL loadOK, loadAgent;

FARPROC GetProcAddress2(HMODULE hModule, LPCSTR lpProcName)
{
    FARPROC retval = GetProcAddress(hModule, lpProcName);
    if (!retval)
        loadOK = false;
    return retval;
}

FARPROC GetProcAddressAgent(HMODULE hModule, LPCSTR lpProcName)
{
    FARPROC retval=GetProcAddress(hModule, lpProcName);
    if (!retval)
        loadAgent=false;
    return retval;
}


#undef FUNCDEF
#define FUNCDEF(r, f, p) typedef r (*t##f) p;
#undef FUNCDEF2
#define FUNCDEF2(r, f, p) typedef r (*t##f) p;
#include "sshdynfunctions.h"

#undef FUNCDEF
#define FUNCDEF(r, f, p) t##f f=NULL;
#undef FUNCDEF2
#define FUNCDEF2(r, f, p) t##f f=NULL;
#include "sshdynfunctions.h"

// we need version 1.7.0 or later for SCP 64 bit SCP filetransfer
#define LIBSSH2_VERSION_NUM_64BIT_FILETRANSFER_SCP 0x010206
// we need version 1.2.5 or later for SCP keep alive option
#define LIBSSH2_VERSION_NUM_CAN_SEND_KEEP_ALIVE_SCP 0x010205
// we need version 1.2.1 or later for SCP mode working in async mode
#define LIBSSH2_VERSION_NUM_ASYNC_SCP 0x010201
// we need version 1.2.1 or later for SCP mode working without quotes "" for files with spaces in name
#define LIBSSH2_VERSION_NUM_QUOTE_SCP 0x010100

BOOL LoadSSHLib()
{
    if (!sshlib) {
        LogProc(PluginNumber, MSGTYPE_DETAILS, "Loading SSH Library");
        int olderrormode = SetErrorMode(0x8001);
        char dllname[MAX_PATH];
        dllname[0] = 0;

        // first, try in the DLL directory (changed from previous versions)
        GetModuleFileName(hinst, dllname, sizeof(dllname)-10);
        char* p = strrchr(dllname, '\\');
        if (p)
            p++;
        else
            p = dllname;
        // Load libeay32.dll first,  otherwise it will not be found!
#ifdef _WIN64
        p[0] = 0;
        strlcat(dllname, "64\\zlibwapi.dll", sizeof(dllname)-1);
        sshlib = (HINSTANCE)LoadLibrary(dllname);
        p[0] = 0;
        strlcat(dllname, "64\\zlib1.dll", sizeof(dllname)-1);
        sshlib = (HINSTANCE)LoadLibrary(dllname);
        p[0] = 0;
        strlcat(dllname, "64\\libeay32.dll", sizeof(dllname)-1);
        sshlib = (HINSTANCE)LoadLibrary(dllname);
        p[0] = 0;
        strlcat(dllname, "64\\libssh2.dll", sizeof(dllname)-1);
        sshlib = (HINSTANCE)LoadLibrary(dllname);
        if (!sshlib) {
            p[0] = 0;
            strlcat(dllname, "x64\\zlibwapi.dll", sizeof(dllname)-1);
            sshlib = (HINSTANCE)LoadLibrary(dllname);
            p[0] = 0;
            strlcat(dllname, "x64\\zlib1.dll", sizeof(dllname)-1);
            sshlib = (HINSTANCE)LoadLibrary(dllname);
            p[0] = 0;
            strlcat(dllname, "x64\\libeay32.dll", sizeof(dllname)-1);
            sshlib = (HINSTANCE)LoadLibrary(dllname);
            p[0] = 0;
            strlcat(dllname, "x64\\libssh2.dll", sizeof(dllname)-1);
            sshlib = (HINSTANCE)LoadLibrary(dllname);
        }
#else 
        sshlib = NULL;
#endif
        if (!sshlib) {
            p[0] = 0;
            strlcat(dllname, "zlibwapi.dll", sizeof(dllname)-1);
            sshlib = (HINSTANCE)LoadLibrary(dllname);
            p[0] = 0;
            strlcat(dllname, "zlib1.dll", sizeof(dllname)-1);
            sshlib = (HINSTANCE)LoadLibrary(dllname);
            p[0] = 0;
            strlcat(dllname, "libeay32.dll", sizeof(dllname)-1);
            sshlib = (HINSTANCE)LoadLibrary(dllname);
            p[0] = 0;
            strlcat(dllname, "libssh2.dll", sizeof(dllname)-1);
            sshlib = (HINSTANCE)LoadLibrary(dllname);
        }
        if (!sshlib) {
            GetModuleFileName(NULL, dllname, sizeof(dllname)-10);
            p = strrchr(dllname, '\\');
            if (p)
                p++;
            else
                p = dllname;
            // Load libeay32.dll first,  otherwise it will not be found!
            p[0] = 0;
#ifdef _WIN64
            strlcat(dllname, "64\\zlibwapi.dll", sizeof(dllname)-1);
            sshlib = (HINSTANCE)LoadLibrary(dllname);
            p[0] = 0;
            strlcat(dllname, "64\\zlib1.dll", sizeof(dllname)-1);
            sshlib = (HINSTANCE)LoadLibrary(dllname);
            p[0] = 0;
            strlcat(dllname, "64\\libeay32.dll", sizeof(dllname)-1);
            sshlib = (HINSTANCE)LoadLibrary(dllname);
            p[0] = 0;
            strlcat(dllname, "64\\libssh2.dll", sizeof(dllname)-1);
            sshlib = (HINSTANCE)LoadLibrary(dllname);
            if (!sshlib) {
                p[0] = 0;
                strlcat(dllname, "x64\\zlibwapi.dll", sizeof(dllname)-1);
                sshlib = (HINSTANCE)LoadLibrary(dllname);
                p[0] = 0;
                strlcat(dllname, "x64\\zlib1.dll", sizeof(dllname)-1);
                sshlib = (HINSTANCE)LoadLibrary(dllname);
                p[0] = 0;
                strlcat(dllname, "x64\\libeay32.dll", sizeof(dllname)-1);
                sshlib = (HINSTANCE)LoadLibrary(dllname);
                p[0] = 0;
                strlcat(dllname, "x64\\libssh2.dll", sizeof(dllname)-1);
                sshlib = (HINSTANCE)LoadLibrary(dllname);
            }
#endif
            if (!sshlib) {
                p[0] = 0;
                strlcat(dllname, "zlibwapi.dll", sizeof(dllname)-1);
                sshlib = (HINSTANCE)LoadLibrary(dllname);
                p[0] = 0;
                strlcat(dllname, "zlib1.dll", sizeof(dllname)-1);
                sshlib = (HINSTANCE)LoadLibrary(dllname);
                p[0] = 0;
                strlcat(dllname, "libeay32.dll", sizeof(dllname)-1);
                sshlib = (HINSTANCE)LoadLibrary(dllname);
                p[0] = 0;
                strlcat(dllname, "libssh2.dll", sizeof(dllname)-1);
                sshlib = (HINSTANCE)LoadLibrary(dllname);
            }
        }
        if (!sshlib) {
            // try also in Total Commander dir and the path!
            // we don't need to load libeay32.dll then,  because
            // libssh2.dll would find it in the path anyway!
            sshlib = (HINSTANCE)LoadLibrary("libssh2.dll");
        }
        if (!sshlib) {
            OSVERSIONINFO vx;
            vx.dwOSVersionInfoSize = sizeof(vx);
            GetVersionEx(&vx);
            if (vx.dwPlatformId == VER_PLATFORM_WIN32_NT && vx.dwMajorVersion < 6) {  // XP or older?
                GetModuleFileName(hinst, dllname, sizeof(dllname)-10);
                char* p = strrchr(dllname,'\\');
                if (p)
                    p++;
                else
                    p = dllname;
#ifdef _WIN64
                p[0] = 0;
                strlcat(dllname, "64\\libssh2.dll", sizeof(dllname)-1);
                sshlib = (HINSTANCE)LoadLibraryEx(dllname, NULL, LOAD_LIBRARY_AS_DATAFILE);
                if (!sshlib) {
                    p[0] = 0;
                    strlcat(dllname, "x64\\libssh2.dll", sizeof(dllname)-1);
                    sshlib = (HINSTANCE)LoadLibraryEx(dllname, NULL, LOAD_LIBRARY_AS_DATAFILE);
                }
#endif
                if (!sshlib) {
                    p[0] = 0;
                    strlcat(dllname, "libssh2.dll", sizeof(dllname)-1);
                    sshlib = (HINSTANCE)LoadLibraryEx(dllname, NULL, LOAD_LIBRARY_AS_DATAFILE);
                }
                if (sshlib) {
                    HICON icon = LoadIcon(sshlib, MAKEINTRESOURCE(12345));
                    FreeLibrary(sshlib);
                    sshlib = NULL;
                    if (icon) {
                        MessageBox(GetActiveWindow(), "This plugin requires Windows Vista, 7 or newer. Please get the separate plugin for Windows XP or older from www.ghisler.com!", "Error", MB_ICONSTOP);
                        return false;
                    }
                }
            }
#ifdef _WIN64
            int res = MessageBox(GetActiveWindow(), "Please put the openssl dlls either\n- in the same directory as the plugin, or\n- in the Total Commander dir, or\n- in subdir \"64\" of the plugin or TC directory, or\n- somewhere in your PATH!\n\nDownload now?", "Error", MB_YESNO | MB_ICONSTOP);
#else
            int res = MessageBox(GetActiveWindow(), "Please put the openssl dlls either\n- in the same directory as the plugin, or\n- in the Total Commander dir, or\n- somewhere in your PATH!\n\nDownload now?", "Error", MB_YESNO | MB_ICONQUESTION);
#endif
            if (res == IDYES)
                ShellExecute(GetActiveWindow(), NULL, "https://www.ghisler.com/openssl", NULL, NULL, SW_SHOW);
            return false;
        }
        SetErrorMode(olderrormode);
        loadOK = true;
        loadAgent = true;
        
        // the following will load all the functions!
        #undef FUNCDEF
        #undef FUNCDEF2
        #define FUNCDEF(r, f, p) f=(t##f)GetProcAddress2(sshlib,  #f)
        #define FUNCDEF2(r, f, p) f=(t##f)GetProcAddressAgent(sshlib,  #f)
        #include "sshdynfunctions.h"

        SSH_ScpNo2GBLimit = (libssh2_version != NULL && libssh2_version(LIBSSH2_VERSION_NUM_64BIT_FILETRANSFER_SCP) != NULL);
        SSH_ScpCanSendKeepAlive = (libssh2_version != NULL && libssh2_version(LIBSSH2_VERSION_NUM_CAN_SEND_KEEP_ALIVE_SCP) != NULL);
        SSH_ScpNeedBlockingMode = (libssh2_version == NULL || !libssh2_version(LIBSSH2_VERSION_NUM_ASYNC_SCP));
        SSH_ScpNeedQuote = (libssh2_version == NULL || !libssh2_version(LIBSSH2_VERSION_NUM_QUOTE_SCP));
    }
    // initialize the Winsock calls too
    if (loadOK) {
        char ws2libname[MAX_PATH];
        WSADATA wsadata;
        WSAStartup(MAKEWORD( 2,  2 ), &wsadata);

        // also load the getaddrinfo function
        if (GetSystemDirectoryA(ws2libname, MAX_PATH)) {
            strlcat(ws2libname,  "\\ws2_32", sizeof(ws2libname)-1);
            HINSTANCE ws2lib = LoadLibraryA(ws2libname);
            if (ws2lib) {
                getaddrinfo = (tgetaddrinfo)GetProcAddress(ws2lib, "getaddrinfo");
                freeaddrinfo = (tfreeaddrinfo)GetProcAddress(ws2lib, "freeaddrinfo");
                WSAAddressToString=(tWSAAddressToStringA)GetProcAddress(ws2lib, "WSAAddressToStringA");
                if (!getaddrinfo) {
                    FreeLibrary(ws2lib);
                    GetSystemDirectoryA(ws2libname,  MAX_PATH);
                    strlcat(ws2libname, "\\wship6", sizeof(ws2libname)-1);
                    ws2lib = LoadLibraryA(ws2libname);
                    if (ws2lib) {
                        getaddrinfo = (tgetaddrinfo)GetProcAddress(ws2lib, "getaddrinfo");
                        freeaddrinfo = (tfreeaddrinfo)GetProcAddress(ws2lib, "freeaddrinfo");
                        if (!getaddrinfo) {
                            FreeLibrary(ws2lib);
                        }
                    }
                }
            }
        }
    }

    return loadOK;
}

static void kbd_callback(const char *name,  int name_len,
             const char *instruction,  int instruction_len,  int num_prompts,
             const LIBSSH2_USERAUTH_KBDINT_PROMPT *prompts,
             LIBSSH2_USERAUTH_KBDINT_RESPONSE *responses,
             void **abstract)
{
    char buf[1024];
    char retbuf[256];
    for (int i = 0; i < num_prompts; i++) {
        // Special case: Pass the stored password as the first response to the interactive prompts
        // Note: We may get multiple calls to kbd_callback - this is tracked with "InteractivePasswordSent"
        strlcpy(retbuf, prompts[i].text, min(prompts[i].length, sizeof(retbuf)-1));
        ShowStatus(retbuf);
        pConnectSettings ConnectSettings = (pConnectSettings)*abstract;
        BOOL autoSendPassword = (ConnectSettings && ConnectSettings->password[0] && !ConnectSettings->InteractivePasswordSent);
        if (autoSendPassword) {
            strlwr(retbuf);
            // it must contain "pass"
            if (strstr(retbuf, "pass") == NULL)
                autoSendPassword = false;
            // it must NOT contain "OATH" or "one time" or "one_time"
            else if (strstr(retbuf, "OATH") || strstr(retbuf, "one time") || strstr(retbuf, "one-time"))
                autoSendPassword = false;
        }
        if (autoSendPassword) {
            ConnectSettings->InteractivePasswordSent = true;
            char* p = strstr(ConnectSettings->password, "\",\"");
            int len = strlen(ConnectSettings->password);
            if (p && ConnectSettings->password[0] == '"' && ConnectSettings->password[len-1] == '"') {
                // two passwords -> use second one!
                ConnectSettings->password[len-1] = 0;
                if (p[3] == 0)
                    autoSendPassword = false;
                else
                    responses[i].text = _strdup(p + 3);
                ConnectSettings->password[len-1] = '"';
            } else
                responses[i].text = _strdup(ConnectSettings->password);
            if (autoSendPassword) {
                responses[i].length = (unsigned int)strlen(responses[0].text);
                ShowStatus("sending stored password");
            }
        }
        if (!autoSendPassword) {
            char title[128];
            buf[0] = 0;
            title[0] = 0;
            if (instruction && instruction_len) {
                strlcpy(buf, instruction, min(instruction_len, sizeof(buf)-1));
                strlcat(buf, "\n", sizeof(buf)-1);
            }
            if (prompts[i].length && prompts[i].text) {
                strlcpy(retbuf, prompts[i].text, min(prompts[i].length, sizeof(retbuf)-1));
                strlcat(buf, retbuf, sizeof(buf)-1);
            }
            if (buf[0] == 0)
                strlcat(buf, "Password:", sizeof(buf)-1);

            if (name && name_len)
                strlcpy(title, name, min(name_len, sizeof(title)-1));
            else
                strlcpy(title, "SFTP password for", sizeof(title)-1);
            if (ConnectSettings) {
                strlcat(title, " ", sizeof(title)-1);
                strlcat(title, ConnectSettings->user, sizeof(title)-1);
                strlcat(title, "@", sizeof(title)-1);
                strlcat(title, ConnectSettings->server, sizeof(title)-1);
            }
            retbuf[0] = 0;

            ShowStatus("requesting password from user...");
            if (RequestProc(PluginNumber, RT_Password, title, buf, retbuf, sizeof(retbuf)-1)) {
                responses[i].text = _strdup(retbuf);
                responses[i].length = (unsigned int)strlen(retbuf);
                // Remember password for background transfers
                if (ConnectSettings && ConnectSettings->password[0] == 0)
                    strlcpy(ConnectSettings->password, retbuf, sizeof(ConnectSettings->password)-1);
                ShowStatus("sending password entered by user");
            } else {
                responses[i].text = NULL;
                responses[i].length = 0;
            }
        }
    }
} /* kbd_callback */ 

void *myalloc(size_t count, void **abstract)
{
    return malloc(count);
}

void *myrealloc(void *ptr, size_t count, void **abstract)
{
    // avoid possible memory leak if realloc fails
    void* ptrSav = ptr;

    ptr = realloc(ptr, count);

    if (ptr == NULL && ptrSav != NULL)
        free(ptrSav);

    return ptr;
}

void myfree(void *ptr, void **abstract)
{
    free(ptr);
}

BOOL ismimechar(char ch)
{
    return ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
             ch == '/' || ch == '+' || ch == '=' || ch == '\r' || ch == '\n');
}

BOOL ProgressLoop(char* progresstext, int start, int end, int* loopval, DWORD* lasttime)
{
    DWORD time = GetCurrentTime();
    if (time - *lasttime > 100 || *loopval < start) {
        *lasttime = time;
        (*loopval)++;
        if (*loopval < start || *loopval > end)
            *loopval = start;
        return ProgressProc(PluginNumber, progresstext, "-", *loopval);
    }
    return false;
}

void ShowError(char* error)
{
    ShowStatus(error);  // log it
    RequestProc(PluginNumber, RT_MsgOK, "SFTP Error", error, NULL, 0);
}

void SftpLogLastError(char* errtext, int errnr)
{
    char errbuf[128];
    if (errnr == 0 || errnr == LIBSSH2_ERROR_EAGAIN)   //no error -> do not log
        return;
    strlcpy(errbuf, errtext, 128 - 10);
    errnr = -errnr;
    if (errnr >= 0 && errnr <= 47) {
        strlcat(errbuf, ERRORNAMES[errnr], sizeof(errbuf)-8);
        strlcat(errbuf, " (", sizeof(errbuf)-6);
        _itoa(errnr, errbuf + strlen(errbuf), 10);
        strlcat(errbuf, ")", sizeof(errbuf)-1);
    } else
        _itoa(errnr, errbuf + strlen(errbuf), 10);
    LogProc(PluginNumber, MSGTYPE_IMPORTANTERROR, errbuf);
}

void ShowErrorId(int errorid)
{
    char errorstr[256];
    LoadStr(errorstr, errorid);
    ShowStatus(errorstr);  // log it
    RequestProc(PluginNumber, RT_MsgOK, "SFTP Error", errorstr, NULL, 0);
}

void SetBlockingSocket(SOCKET s, BOOL blocking)
{
    u_long arg = blocking ? 0 : 1;
    ioctlsocket(s, FIONBIO, &arg);
}

BOOL IsSocketError(SOCKET s)
{
    fd_set fds;
    timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 50000;
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    return 1 == select(0, NULL, NULL, &fds, &timeout);
}

BOOL IsSocketWritable(SOCKET s)
{
    fd_set fds;
    timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 50000;
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    return 1 == select(0, NULL, &fds, NULL, &timeout);
}

BOOL IsSocketReadable(SOCKET s)
{
    fd_set fds;
    timeval timeout;
    timeout.tv_sec = 1;    // This is absolutely necessary, otherwise wingate local will not work!
    timeout.tv_usec = 0;
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    int err = select(0, &fds, NULL, NULL, &timeout);
    return (err == 1);
}

int mysend(SOCKET s, const char *buf, int len, int flags, char* progressmessage, int progressstart, int* ploop, DWORD* plasttime)
{
    int err;
    int ret = SOCKET_ERROR;
    while (true) {
        ret = send(s, buf, len, flags);
        if (ret != len)
            MessageBeep(0);
        if (ret >= 0)
            return ret;
        err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            if (ProgressLoop(progressmessage, progressstart, progressstart+10, ploop, plasttime))
                break;
        }
    }
    return ret;
}

int myrecv(SOCKET s, char *buf, int len, int flags, char* progressmessage, int progressstart, int* ploop, DWORD* plasttime)
{
    int err;
    int totallen = len;
    int ret = SOCKET_ERROR;
    while (true) {
        if (!IsSocketReadable(s))
            err = WSAEWOULDBLOCK;
        else {
            ret = recv(s, buf, len, flags);
            if (ret == len)
                return totallen;
            else if (ret <= 0)
                err = WSAGetLastError();
            else {  // partial data received!
                buf += ret;
                len -= ret;
                err = 0;
            }
        }
        if (err == WSAEWOULDBLOCK) {
            if (ProgressLoop(progressmessage, progressstart, progressstart+10, ploop, plasttime))
                break;
            Sleep(50);
        } else if (err!=0)
            break;
    }
    return ret;
}

pConnectSettings gConnectResults;
char* gDisplayName;
char* gIniFileName;
int g_focusset = 0;

void EncryptString(LPCTSTR pszPlain,  LPTSTR pszEncrypted,  UINT cchEncrypted);

void newpassfunc(LIBSSH2_SESSION *session, char **newpw, int *newpw_len, void **abstract)
{
    pConnectSettings PassConnectSettings = (pConnectSettings)*abstract;
    char title[128], buf1[128];
    char newpass[128];
    LoadStr(title, IDS_PASS_TITLE);
    LoadStr(buf1, IDS_PASS_CHANGE_REQUEST);
    newpass[0] = 0;
    if (RequestProc(PluginNumber, RT_Password, title, buf1, newpass, sizeof(newpass)-1)) {
        int bufsize = (int)strlen(newpass) + 1;
        *newpw = (char*)malloc(bufsize);
        strlcpy(*newpw, newpass, bufsize);
        *newpw_len = bufsize;
        if (PassConnectSettings) {
            strlcpy(PassConnectSettings->password, newpass, sizeof(PassConnectSettings->password)-1);
            switch (PassConnectSettings->passSaveMode) {
            case 1:
                CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_SAVE_PASSWORD, PassConnectSettings->DisplayName, newpass, 0);
                break;
            case 2:
                if (newpass[0] == 0) {
                    WritePrivateProfileString(PassConnectSettings->DisplayName, "password", NULL, gIniFileName);
                } else {
                    char szEncryptedPassword[256];
                    EncryptString(newpass,  szEncryptedPassword,  countof(szEncryptedPassword));
                    WritePrivateProfileString(PassConnectSettings->DisplayName, "password", szEncryptedPassword, gIniFileName);
                }
                break;
            }
        }
    }
}

int SftpConnect(pConnectSettings ConnectSettings)
{
    if (!LoadSSHLib())
        return SFTP_FAILED;
    if (!loadAgent && ConnectSettings->useagent) {
        char buf[128], buf1[128];
        LoadStr(buf1, IDS_SSH2_TOO_OLD);
#ifdef sprintf_s
        sprintf_s(buf, 128, buf1, LIBSSH2_VERSION);
#else
        sprintf(buf, buf1, LIBSSH2_VERSION);
#endif
        MessageBox(GetActiveWindow(), buf, "Error", MB_ICONSTOP);
        return SFTP_FAILED;
    }
    char buf[1024];
    DWORD len;
    char connecttoserver[250];
    unsigned long hostaddr;
    unsigned short connecttoport;
    char* p;
    struct sockaddr_in sin;
    struct addrinfo hints, *res, *ai;
    bool connected = FALSE;
    int nsocks; int auth, loop;
    DWORD lasttime = GetCurrentTime();

    if (!ConnectSettings->session) {
        if (ProgressProc(PluginNumber, "Connecting...", "-", 0))
            return -1;

        switch (ConnectSettings->proxytype) {
        case 0:
            strlcpy(connecttoserver, ConnectSettings->server, sizeof(connecttoserver)-1);
            connecttoport = ConnectSettings->customport;
            break;
        case 2: // HTTP connect
            if (!ParseAddress(ConnectSettings->proxyserver,  &connecttoserver[0],  &connecttoport,  8080)) {
                MessageBox(GetActiveWindow(), "Invalid proxy server address.", "SFTP Error", MB_ICONSTOP);
                return -1;
            }
            break;
        case 3: // SOCKS4a
        case 4: // SOCKS5
            if(!ParseAddress(ConnectSettings->proxyserver,  &connecttoserver[0],  &connecttoport,  1080)) {
                MessageBox(GetActiveWindow(), "Invalid proxy server address.", "SFTP Error", MB_ICONSTOP);
                return -1;
            }
            break;
        default:
            MessageBox(GetActiveWindow(), "Function not supported yet!", "SFTP Error", MB_ICONSTOP);
            return -1;
        }
        ShowStatus(" ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  == ");
        LoadStr(buf, IDS_CONNECT_TO);
        strlcat(buf, ConnectSettings->server, sizeof(buf)-1);
        ShowStatus(buf);

        if (!getaddrinfo) {
            hostaddr = inet_addr(connecttoserver);
            if (hostaddr == INADDR_NONE) {
                hostent* hostinfo;
                hostinfo = (struct hostent *) gethostbyname(connecttoserver);
                if (hostinfo)
                    memcpy(&hostaddr, hostinfo->h_addr_list[0], 4);
            }
            ConnectSettings->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

            sin.sin_family = AF_INET;
            sin.sin_port = htons(connecttoport); //htons(22);
            sin.sin_addr.s_addr = hostaddr; 

            if (ConnectSettings->proxytype) {
                LoadStr(buf, IDS_VIA_PROXY);
                strlcat(buf, connecttoserver, sizeof(buf)-1);
                ShowStatus(buf);
            }
            SetBlockingSocket(ConnectSettings->sock, false);
            connected = connect(ConnectSettings->sock, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in)) == 0;
            if (!connected && WSAGetLastError() == WSAEWOULDBLOCK) {
                while (true) {
                    if (IsSocketWritable(ConnectSettings->sock)) {
                        connected = true;
                        break;
                    }
                    if (IsSocketError(ConnectSettings->sock))
                        break;
                    if (ProgressLoop(buf, 0, 20, &loop, &lasttime))
                        break;
                }
            }
        } else {
            // IPv6 code added by forum-user "Sob"
            memset(&hints, 0, sizeof(hints));
            switch (ConnectSettings->protocoltype) {
            case 1:
                hints.ai_family = AF_INET;
                break;
            case 2:
                hints.ai_family = AF_INET6;
                break;
            default:
                hints.ai_family = AF_UNSPEC;
                break;
            }
            hints.ai_socktype = SOCK_STREAM;
#ifdef sprintf_s
            sprintf_s(buf, sizeof(buf), "%d", connecttoport);
#else
            sprintf(buf, "%d", connecttoport);
#endif
            if (getaddrinfo(connecttoserver, buf, &hints, &res) != 0) {
                ShowErrorId(IDS_ERR_GETADDRINFO);
                return -1;
            }
            for (nsocks = 0, ai = res; ai; ai = ai->ai_next, nsocks++) {
                if(nsocks > 0) closesocket(ConnectSettings->sock);
                ConnectSettings->sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
                if (WSAAddressToString) {
                    len = (DWORD)sizeof(buf) - (DWORD)strlen(buf);
                    strlcpy(buf, "IP address: ", sizeof(buf)-1);
                    WSAAddressToString(ai->ai_addr, ai->ai_addrlen, NULL, buf + (DWORD)strlen(buf), (LPDWORD)&len);
                    ShowStatus(buf);
                }
                SetBlockingSocket(ConnectSettings->sock, false);
                connected = connect(ConnectSettings->sock, ai->ai_addr, (int)ai->ai_addrlen) == 0;
                if (!connected && WSAGetLastError() == WSAEWOULDBLOCK) {
                    while (true) {
                        if (IsSocketWritable(ConnectSettings->sock)) {
                            connected = true;
                            break;
                        }
                        if (IsSocketError(ConnectSettings->sock))
                            break;
                        if (ProgressLoop(buf, 0, 20, &loop, &lasttime))
                            break;
                    }
                }
                if (connected)
                    break;
            }
            if (freeaddrinfo)
                freeaddrinfo(res);
        }

        if (!connected) {
            if (ConnectSettings->proxytype)
                ShowErrorId(IDS_ERR_PROXYCONNECT);
            else
                ShowErrorId(IDS_ERR_SERVERCONNECT);
            return -1;
        }

        // **********************************************************
        //  Proxy?
        bool lastcrlfcrlf;
        char progressbuf[250];
        LoadStr(progressbuf, IDS_PROXY_CONNECT);
        int nrbytes, err;
        switch (ConnectSettings->proxytype) {
        case 2: // HTTP CONNECT
            if (ProgressProc(PluginNumber, progressbuf, "-", 20)) {
                closesocket(ConnectSettings->sock);
                ConnectSettings->sock = 0;
                return -1;
            }
            // Send "CONNECT hostname:port HTTP/1.1"<CRLF>"Host: hostname:port"<2xCRLF> to the proxy
            if (IsNumericIPv6(ConnectSettings->server))
#ifdef sprintf_s
                sprintf_s(buf, sizeof(buf), "CONNECT [%s]:%d HTTP/1.1\r\nHost: [%s]:%d\r\n", ConnectSettings->server, ConnectSettings->customport, ConnectSettings->server, ConnectSettings->customport);
#else
                sprintf(buf,"CONNECT [%s]:%d HTTP/1.1\r\nHost: [%s]:%d\r\n",ConnectSettings->server,ConnectSettings->customport,ConnectSettings->server,ConnectSettings->customport);
#endif
            else
#ifdef sprintf_s
                sprintf_s(buf, sizeof(buf), "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n", ConnectSettings->server, ConnectSettings->customport, ConnectSettings->server, ConnectSettings->customport);
#else
                sprintf(buf,"CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n",ConnectSettings->server,ConnectSettings->customport,ConnectSettings->server,ConnectSettings->customport);
#endif
            if (ConnectSettings->proxyuser[0]) {
                char buf1[250], buf2[500], title[250];
                char passphrase[256];
                strlcpy(passphrase, ConnectSettings->proxypassword, sizeof(passphrase)-1);
            
                LoadStr(buf1, IDS_PROXY_PASSWORD_FOR);
                strlcpy(title, buf1, sizeof(title)-1);
                strlcat(title, ConnectSettings->proxyuser, sizeof(title)-1);
                strlcat(title, "@", sizeof(title)-1);
                strlcat(title, ConnectSettings->proxyserver, sizeof(title)-1);
                LoadStr(buf1, IDS_PROXY_PASSWORD);
                if (passphrase[0] == 0)
                    RequestProc(PluginNumber, RT_Password, title, buf1, passphrase, sizeof(passphrase)-1);

                strlcpy(buf1, ConnectSettings->proxyuser, sizeof(buf1)-1);
                strlcat(buf1, ":", sizeof(buf1)-1);
                strlcat(buf1, passphrase, sizeof(buf1)-1);
                strlcat(buf, "Proxy-Authorization: Basic ", sizeof(buf2)-1);
                MimeEncode(buf1, buf2, sizeof(buf2)-1);
                strlcat(buf, buf2, sizeof(buf)-1);
                strlcat(buf, "\r\n", sizeof(buf)-1);
            }
            strlcat(buf, "\r\n", sizeof(buf)-1);
            mysend(ConnectSettings->sock, buf, (int)strlen(buf), 0, progressbuf, 20, &loop, &lasttime);
            // Response;
            // HTTP/1.0 200 Connection established
            // Proxy-agent: WinProxy/1.5.3<2xCRLF>
            lastcrlfcrlf = false;
            nrbytes = myrecv(ConnectSettings->sock, buf, 12, 0, progressbuf, 20, &loop, &lasttime);
            if (nrbytes == 12 && buf[9] == '2') {    // proxy signals success!!
                // read data until we get 2xCRLF
                bool lastcrlf = false;
                bool lastcr = false;
                while (1) {
                    nrbytes = myrecv(ConnectSettings->sock, buf, 1, 0, progressbuf, 20, &loop, &lasttime);
                    if (nrbytes <= 0)
                        break;
                    if (buf[0] == '\r')
                        lastcr = true;
                    else if (buf[0] == '\n') {
                        if (lastcr) {
                            if (lastcrlf) {
                                lastcrlfcrlf = true;
                                break;
                            } else
                                lastcrlf = true;
                        } else
                            lastcrlf = false;
                    } else {
                        lastcr = false;
                        lastcrlf = false;
                    }
                }
            }
            if (!lastcrlfcrlf) {
                ShowErrorId(IDS_VIA_PROXY_CONNECT);
                closesocket(ConnectSettings->sock);
                ConnectSettings->sock = 0;
                return -1;
            }
            break;
        case 3: // SOCKS4/4A
            if (ProgressProc(PluginNumber, progressbuf, "-", 20)) {
                closesocket(ConnectSettings->sock);
                ConnectSettings->sock = 0;
                return -1;
            }
            ZeroMemory(buf, sizeof(buf));
            buf[0] = 4; //version
            buf[1] = 1; //TCP connect
            *((unsigned short *)&buf[2]) = htons(ConnectSettings->customport);

            // numerical IPv4 given?
            hostaddr = inet_addr(ConnectSettings->server);
            if (hostaddr == INADDR_NONE)
                *((unsigned long *)&buf[4]) = htonl(0x00000001);
            else
                *((unsigned long *)&buf[4]) = hostaddr;  // it's already in network order!
            nrbytes = 8;
            strlcpy(&buf[nrbytes], ConnectSettings->proxyuser, sizeof(buf)-nrbytes-1);
            nrbytes += (int)strlen(ConnectSettings->proxyuser) + 1;
            if (hostaddr == INADDR_NONE) {  // SOCKS4A
                strlcpy(&buf[nrbytes], ConnectSettings->server, sizeof(buf)-nrbytes-1);
                nrbytes += (int)strlen(ConnectSettings->server) + 1;
            }
            //
            mysend(ConnectSettings->sock, buf, nrbytes, 0, progressbuf, 20, &loop, &lasttime);
            nrbytes=myrecv(ConnectSettings->sock, buf, 8, 0, progressbuf, 20, &loop, &lasttime);
            if (nrbytes != 8 || buf[0] != 0 || buf[1] != 0x5a) {
                ShowErrorId(IDS_VIA_PROXY_CONNECT);
                closesocket(ConnectSettings->sock);
                ConnectSettings->sock = 0;
                return -1;
            }
            break;
        case 4:  // SOCKS5
            if (ProgressProc(PluginNumber, progressbuf, "-", 20)) {
                closesocket(ConnectSettings->sock);
                ConnectSettings->sock = 0;
                return -1;
            }
            ZeroMemory(buf, sizeof(buf));
            buf[0] = 5; // version
            buf[2] = 0; // no auth
            nrbytes = 3;
            if (ConnectSettings->proxyuser[0]) {
                buf[3] = 2; // user/pass auth
                nrbytes++;
            }
            buf[1] = nrbytes - 2; // nr. of methods
            //
            mysend(ConnectSettings->sock, buf, nrbytes, 0, progressbuf, 20, &loop, &lasttime);
            nrbytes = myrecv(ConnectSettings->sock, buf, 2, 0, progressbuf, 20, &loop, &lasttime);
            if (!ConnectSettings->proxyuser[0] && buf[1] != 0) {
                *((unsigned char *)&buf[1]) = 0xff;
            }
            if (nrbytes != 2 || buf[0] != 5 || buf[1] == 0xff) {
                ShowErrorId(IDS_VIA_PROXY_CONNECT);
                closesocket(ConnectSettings->sock);
                ConnectSettings->sock = 0;
                return -1;
            }
            //
            if (buf[1] == 2) { // user/pass auth
                int len;
                ZeroMemory(buf, sizeof(buf));
                buf[0] = 1; // version
                len = (int)strlen(ConnectSettings->proxyuser);
                buf[1] = len;
                strlcpy(&buf[2], ConnectSettings->proxyuser, sizeof(buf)-3);
                nrbytes = len + 2;
                len = (int)strlen(ConnectSettings->proxypassword);
                buf[nrbytes] = len;
                strlcpy(&buf[nrbytes+1],  ConnectSettings->proxypassword,  sizeof(buf)-nrbytes-1);
                nrbytes += len + 1;
                //
                mysend(ConnectSettings->sock, buf, nrbytes, 0, progressbuf, 20, &loop, &lasttime);
                nrbytes = myrecv(ConnectSettings->sock, buf, 2, 0, progressbuf, 20, &loop, &lasttime);
                if (nrbytes != 2 || buf[1] != 0) {
                    LoadStr(buf, IDS_SOCKS5PROXYERR);
                    ShowError(buf);
                    closesocket(ConnectSettings->sock);
                    ConnectSettings->sock = 0;
                    return -1;
                }
            }
            //
            ZeroMemory(buf,  sizeof(buf));
            buf[0] = 5; // version
            buf[1] = 1; // TCP connect
            buf[2] = 0; // reserved

            hostaddr = inet_addr(ConnectSettings->server);
            if (hostaddr != INADDR_NONE) {
                buf[3] = 1; // addrtype (IPv4)
                *((unsigned long *)&buf[4]) = hostaddr;  // it's already in network order!
                nrbytes = 4 + 4;
            } else {
                BOOL numipv6 = false;  // is it an IPv6 numeric address?
                if (getaddrinfo && IsNumericIPv6(ConnectSettings->server)) {
                    memset(&hints, 0, sizeof(hints));
                    hints.ai_family = AF_INET6;
                    hints.ai_socktype = SOCK_STREAM;
#ifdef sprintf_s
                    sprintf_s(buf, sizeof(buf), "%d", connecttoport);
#else
                    sprintf(buf, "%d", connecttoport);
#endif
                    if (getaddrinfo(ConnectSettings->server, buf, &hints, &res) == 0 && res->ai_addrlen>=sizeof(sockaddr_in6)) {
                        numipv6 = true;
                        buf[3] = 4; // IPv6
                        memcpy(&buf[4], ((psockaddr_in6)(res->ai_addr))->sin6_addr, 16);
                        nrbytes = 4 + 16;
                    }
                }
                if (!numipv6) {
                    buf[3] = 3; // addrtype (domainname)
                    buf[4] = (char)strlen(ConnectSettings->server);
                    strlcpy(&buf[5], ConnectSettings->server, sizeof(buf)-6);
                    nrbytes = (unsigned char)buf[4] + 5;
                }
            }
            *((unsigned short *)&buf[nrbytes]) = htons(ConnectSettings->customport);
            nrbytes += 2;
            //
            mysend(ConnectSettings->sock, buf, nrbytes, 0, progressbuf, 20, &loop, &lasttime);
            nrbytes = myrecv(ConnectSettings->sock, buf, 4, 0, progressbuf, 20, &loop, &lasttime);
            if (nrbytes != 4 || buf[0] != 5 || buf[1] != 0) {
                //ShowErrorId(IDS_VIA_PROXY_CONNECT);
                switch(buf[1]) {
                case 1: LoadStr(buf, IDS_GENERALSOCKSFAILURE); break;
                case 2: LoadStr(buf, IDS_CONNNOTALLOWED); break;
                case 3: LoadStr(buf, IDS_NETUNREACHABLE); break;
                case 4: LoadStr(buf, IDS_HOSTUNREACHABLE); break;
                case 5: LoadStr(buf, IDS_CONNREFUSED); break;
                case 6: LoadStr(buf, IDS_TTLEXPIRED); break;
                case 7: LoadStr(buf, IDS_CMDNOTSUPPORTED); break;
                case 8: LoadStr(buf, IDS_ADDRTYPENOTSUPPORTED); break;
                default:
                    {
                        char buf2[MAX_PATH];
                        LoadStr(buf2, IDS_UNKNOWNSOCKERR);
#ifdef sprintf_s
                        sprintf_s(buf, sizeof(buf), buf2, buf[1]);
#else
                        sprintf(buf, buf2, buf[1]);
#endif
                    }
                }
                ShowError(buf);
                closesocket(ConnectSettings->sock);
                ConnectSettings->sock = 0;
                return -1;
            }
            int needread = 0;
            switch(buf[3]) {
            case 1: needread = 6; break;           // IPv4+port
            case 3:
                nrbytes = myrecv(ConnectSettings->sock, buf, 1, 0, progressbuf, 20, &loop, &lasttime);
                if (nrbytes == 1)
                    needread = buf[0]+2;
                break;    // Domain Name+port
            case 4: needread = 18; break;          // IPv6+port
            }
            nrbytes = myrecv(ConnectSettings->sock, buf, needread, 0, progressbuf, 20, &loop, &lasttime);
            if(nrbytes != needread) {
                ShowErrorId(IDS_VIA_PROXY_CONNECT);
                closesocket(ConnectSettings->sock);
                ConnectSettings->sock = 0;
                return -1;
            }
            break;
        }
        LoadStr(buf, IDS_INITSSH2);
        if (ProgressProc(PluginNumber, buf, "-", 30)) {
            closesocket(ConnectSettings->sock);
            ConnectSettings->sock = 0;
            return -1;
        }

        ConnectSettings->session = libssh2_session_init_ex(myalloc, myfree, myrealloc, ConnectSettings);
        if (!ConnectSettings->session) {
            SftpLogLastError("libssh2_session_init_ex: ", libssh2_session_last_errno(ConnectSettings->session));
            ShowErrorId(IDS_ERR_INIT_SSH2);
            closesocket(ConnectSettings->sock);
            ConnectSettings->sock = 0;
            return -1;
        }
        /* Since we have set non-blocking,  tell libssh2 we are non-blocking */
        libssh2_session_set_blocking(ConnectSettings->session, 0);

        // Set ZLIB compression on/off
        // Always allow "none" for the case that the server doesn't support compression
        loop = 30;
        LoadStr(buf, IDS_SET_COMPRESSION);
        while ((err = libssh2_session_method_pref(ConnectSettings->session, LIBSSH2_METHOD_COMP_CS, ConnectSettings->compressed ? "zlib, none" : "none")) ==  LIBSSH2_ERROR_EAGAIN) {
            if (ProgressLoop(buf, 30, 40, &loop, &lasttime))
                break;
            IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
        }
        SftpLogLastError("libssh2_session_method_pref: ", err);
        while ((err = libssh2_session_method_pref(ConnectSettings->session, LIBSSH2_METHOD_COMP_SC, ConnectSettings->compressed ? "zlib, none" : "none")) ==  LIBSSH2_ERROR_EAGAIN) {
            if (ProgressLoop(buf, 30, 40, &loop, &lasttime))
                break;
            IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
        }
        SftpLogLastError("libssh2_session_method_pref2: ", err);
        /* ... start it up. This will trade welcome banners,  exchange keys, 
         * and setup crypto,  compression,  and MAC layers
         */
        LoadStr(buf, IDS_SESSION_STARTUP);
        while ((auth = libssh2_session_startup(ConnectSettings->session, (int)ConnectSettings->sock))  ==  LIBSSH2_ERROR_EAGAIN) {
            if (ProgressLoop(buf, 40, 60, &loop, &lasttime))
                break;
            IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
        } 

        if (auth) {
            LoadStr(buf, IDS_ERR_SSH_SESSION);
            char* errmsg;
            int errmsg_len;
            libssh2_session_last_error(ConnectSettings->session, &errmsg, &errmsg_len, false);
            strlcat(buf, errmsg, sizeof(buf)-1);
            ShowError(buf);

            libssh2_session_free(ConnectSettings->session); 
            ConnectSettings->session = NULL;
            Sleep(1000);
            closesocket(ConnectSettings->sock); 
            ConnectSettings->sock = 0;
            return -1;
        } else
            SftpLogLastError("libssh2_session_startup: ", libssh2_session_last_errno(ConnectSettings->session));

        LoadStr(buf, IDS_SSH_LOGIN);
        if (ProgressProc(PluginNumber, buf, "-", 60)) {
            libssh2_session_free(ConnectSettings->session); 
            ConnectSettings->session = NULL;
            Sleep(1000);
            closesocket(ConnectSettings->sock);
            ConnectSettings->sock = 0;
            return -1;
        }

        const char *fingerprint = libssh2_hostkey_hash(ConnectSettings->session, LIBSSH2_HOSTKEY_HASH_MD5);
        
        if (fingerprint == NULL) {
            SftpLogLastError("Fingerprint error: ", libssh2_session_last_errno(ConnectSettings->session));
            libssh2_session_free(ConnectSettings->session); 
            ConnectSettings->session = NULL;
            Sleep(1000);
            closesocket(ConnectSettings->sock); 
            ConnectSettings->sock = 0;
            return -1;
        }
        LoadStr(buf, IDS_SERVER_FINGERPRINT);
        ShowStatus(buf);
        buf[0] = 0;
        for (int i = 0; i < 16; i++) {
            char buf1[20];
#ifdef sprintf_s
            sprintf_s(buf1, sizeof(buf1), "%02X",  (unsigned char)fingerprint[i]);
#else
            sprintf(buf1, "%02X", (unsigned char)fingerprint[i]);
#endif
            strlcat(buf, buf1, sizeof(buf)-1);
            if (i < 15)
                strlcat(buf, " ", sizeof(buf)-1);
        }
        ShowStatus(buf);

        // Verify server
        if (ConnectSettings->savedfingerprint[0] == 0 || strcmp(ConnectSettings->savedfingerprint, buf) != 0) {  // a new server,  or changed fingerprint
            char buf1[4*MAX_PATH];
            char buf2[MAX_PATH];
            if (ConnectSettings->savedfingerprint[0] == 0)
                LoadStr(buf1, IDS_CONNECTION_FIRSTTIME);
            else
                LoadStr(buf1, IDS_FINGERPRINT_CHANGED);

            LoadStr(buf2, IDS_FINGERPRINT);
            strlcat(buf1, buf2, sizeof(buf1)-1);
            strlcat(buf1, buf, sizeof(buf1)-1);
            LoadStr(buf2, IDS_CONNECTING);
            if (!RequestProc(PluginNumber, RT_MsgYesNo, buf2, buf1, NULL, 0)) {
                libssh2_session_free(ConnectSettings->session); 
                ConnectSettings->session = NULL;
                Sleep(1000);
                closesocket(ConnectSettings->sock); 
                ConnectSettings->sock = 0;
                return -1;
            }
            // Store it,  also for quick connections!
            WritePrivateProfileString(ConnectSettings->DisplayName, "fingerprint", buf, ConnectSettings->IniFileName);
            strlcpy(ConnectSettings->savedfingerprint, buf, sizeof(ConnectSettings->savedfingerprint)-1);
        }

        // Ask for user name if none was entered
        if (ConnectSettings->user[0] == 0) {
            char title[250];
            LoadStr(title, IDS_USERNAME_FOR);
            strlcat(title, ConnectSettings->server, sizeof(title)-1);
            if (!RequestProc(PluginNumber, RT_UserName, title, NULL, ConnectSettings->user, sizeof(ConnectSettings->user)-1)) {
                libssh2_session_free(ConnectSettings->session); 
                ConnectSettings->session = NULL;
                Sleep(1000);
                closesocket(ConnectSettings->sock); 
                ConnectSettings->sock = 0;
                return -1;
            }
        }

        char* userauthlist;
        do {
            userauthlist = libssh2_userauth_list(ConnectSettings->session, 
                            ConnectSettings->user, (unsigned int)strlen(ConnectSettings->user));
            LoadStr(buf, IDS_USER_AUTH_LIST);
            if (ProgressLoop(buf, 60, 70, &loop, &lasttime))
                break;
        } while (userauthlist == NULL && libssh2_session_last_errno(ConnectSettings->session) == LIBSSH2_ERROR_EAGAIN);
        int auth_pw=0;
        if (userauthlist) {
            LoadStr(buf, IDS_SUPPORTED_AUTH_METHODS);
            strlcat(buf, userauthlist, sizeof(buf)-1); 
            ShowStatus(buf);
#ifdef _strlwr_s
            _strlwr_s(userauthlist, strlen(userauthlist) + 1);
#else
            _strlwr(userauthlist);
#endif
            if (strstr(userauthlist, "password") != NULL) {
                auth_pw |= 1;
            }
            if (strstr(userauthlist,  "keyboard-interactive") != NULL) {
                auth_pw |= 2;
            }
            if (strstr(userauthlist,  "publickey") != NULL) {
                auth_pw |= 4;
            } 
        } else {
            SftpLogLastError("libssh2_userauth_list: ", libssh2_session_last_errno(ConnectSettings->session));
            auth_pw = 5;   // assume password+pubkey allowed
        }

        auth = 0;
        if (libssh2_userauth_authenticated(ConnectSettings->session)) {
            ShowStatus("User authenticated without password.");
        } else if (auth_pw & 4 && ConnectSettings->useagent && loadAgent) {
            struct libssh2_agent_publickey *identity, *prev_identity = NULL; 
            LIBSSH2_AGENT *agent = libssh2_agent_init(ConnectSettings->session);

            BOOL connected = true;
            if (!agent || libssh2_agent_connect(agent) != 0) {
                // Try to launch Pageant!
                char linkname[MAX_PATH], dirname[MAX_PATH];
                connected = false;
                dirname[0] = 0;
                GetModuleFileName(hinst, dirname, sizeof(dirname)-10);
                char* p = strrchr(dirname, '\\');
                if (p)
                    p++;
                else
                    p = dirname;
                p[0] = 0;
                strlcpy(linkname, dirname, MAX_PATH-1);
                strlcat(linkname, "pageant.lnk", MAX_PATH-1);
                if (GetFileAttributes(linkname) != 0xFFFFFFFF) {
                    HWND active = GetForegroundWindow();
                    ShellExecute(active, NULL, linkname, NULL, dirname, SW_SHOW);
                    Sleep(2000);
                    DWORD starttime = GetCurrentTime();
                    while (active != GetForegroundWindow() && labs(GetCurrentTime() - starttime) < 20000) {
                        Sleep(200);
                        if (ProgressLoop(buf, 65, 70, &loop, &lasttime))
                            break;
                    }
                    agent = libssh2_agent_init(ConnectSettings->session);
                    if (agent && libssh2_agent_connect(agent) == 0)
                        connected = true;
                }
                if (!connected) {
                    LoadStr(buf, IDS_AGENT_CONNECTERROR);
                    ShowError(buf); 
                    auth = -1;
                }
            }
            if (connected) {
                if (libssh2_agent_list_identities(agent)) {
                    LoadStr(buf, IDS_AGENT_REQUESTIDENTITIES);
                    ShowError(buf); 
                    auth = -1;
                } else {
                    while (1) {
                        auth = libssh2_agent_get_identity(agent, &identity, prev_identity);
                        if (auth == 1) {
                            LoadStr(buf, IDS_AGENT_AUTHFAILED);
                            ShowError(buf); 
                            break;
                        }
                        if (auth < 0) {
                            LoadStr(buf, IDS_AGENT_NOIDENTITY);
                            ShowError(buf); 
                            break;
                        }
                        char buf1[128];
                        LoadStr(buf1, IDS_AGENT_TRYING1);
                        strlcpy(buf, buf1, sizeof(buf)-1);
                        strlcat(buf, ConnectSettings->user, sizeof(buf)-1);
                        LoadStr(buf1, IDS_AGENT_TRYING2);
                        strlcat(buf, buf1, sizeof(buf)-1);
                        strlcat(buf, identity->comment, sizeof(buf)-1);
                        LoadStr(buf1, IDS_AGENT_TRYING3);
                        strlcat(buf, buf1, sizeof(buf)-1);
                        ShowStatus(buf);
                        while ((auth = libssh2_agent_userauth(agent,  ConnectSettings->user,  identity)) == LIBSSH2_ERROR_EAGAIN);
                        if (auth == LIBSSH2_ERROR_REQUIRE_KEYBOARD) {
                            auth_pw = 2;
                            break;
                        } else if (auth == LIBSSH2_ERROR_REQUIRE_PASSWORD) {
                            auth_pw = 1;
                            break;
                        } else if (auth) {
                            LoadStr(buf, IDS_AGENT_AUTHFAILED);
                            ShowStatus(buf);
                        } else {
                            LoadStr(buf, IDS_AGENT_AUTHSUCCEEDED);
                            ShowStatus(buf);
                            break;
                        }
                        prev_identity = identity;
                    }
                }
            }
            libssh2_agent_disconnect(agent);
            libssh2_agent_free(agent);
        } else if (auth_pw & 4 && ConnectSettings->pubkeyfile[0] && ConnectSettings->privkeyfile[0]) {
            BOOL pubkeybad = false;
            char filebuf[1024];
            char passphrase[256];
            char pubkeyfile[MAX_PATH], privkeyfile[MAX_PATH];
            char* pubkeyfileptr = pubkeyfile;
            strlcpy(pubkeyfile, ConnectSettings->pubkeyfile, sizeof(pubkeyfile)-1);
            ReplaceSubString(pubkeyfile, "%USER%", ConnectSettings->user, sizeof(pubkeyfile)-1);
            ReplaceEnvVars(pubkeyfile, sizeof(pubkeyfile)-1);
            strlcpy(privkeyfile, ConnectSettings->privkeyfile, sizeof(privkeyfile)-1);
            ReplaceSubString(privkeyfile, "%USER%", ConnectSettings->user, sizeof(privkeyfile)-1);
            ReplaceEnvVars(privkeyfile, sizeof(privkeyfile)-1);

            passphrase[0] = 0;
            // verify that we have a valid public key file
            HANDLE hf = CreateFile(pubkeyfile, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 
                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
            if (hf == INVALID_HANDLE_VALUE) {
                LoadStr(buf, IDS_ERR_LOAD_PUBKEY);
                strlcat(buf, pubkeyfile, sizeof(buf)-1);
                ShowError(buf);
                auth = LIBSSH2_ERROR_FILE;
                pubkeybad = true;
            } else {
                DWORD dataread = 0;
                if (ReadFile(hf, &filebuf, 35, &dataread, NULL)) {
                    if (_strnicmp(filebuf, "ssh-", 4) != 0 && 
                        _strnicmp(filebuf, "ecdsa-", 6) != 0 &&
                        _strnicmp(filebuf, "-----BEGIN OPENSSH PRIVATE KEY-----", 35) != 0)
                    {
                        LoadStr(buf, IDS_ERR_PUBKEY_WRONG_FORMAT);
                        ShowError(buf);
                        auth = LIBSSH2_ERROR_FILE;
                        pubkeybad = true;
                    }
                }
                CloseHandle(hf);
            }
            if (!pubkeybad) {
                // do not ask for the pass phrase if the key isn't encrypted!
                HANDLE hf = CreateFile(privkeyfile, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
                if (hf == INVALID_HANDLE_VALUE) {
                    LoadStr(buf, IDS_ERR_LOAD_PRIVKEY);
                    strlcat(buf, privkeyfile, sizeof(buf)-1);
                    ShowError(buf);
                    auth = LIBSSH2_ERROR_FILE;
                } else {
                    DWORD dataread = 0;
                    BOOL isencrypted = true; 
                    if (ReadFile(hf, &filebuf, sizeof(filebuf)-32, &dataread, NULL)) {
                        filebuf[dataread] = 0;
                        p = strchr(filebuf, '\n');
                        if (!p)
                            p = strchr(filebuf, '\r');
                        if (p) {
                            p++;
                            while (p[0] == '\r' || p[0] == '\n')
                                p++;
                            isencrypted = false;
                            // if there is something else than just MIME-encoded data, 
                            // then the key is encrypted -> we need a pass phrase
                            for (int i=0; i < 32; i++)
                                if (!ismimechar(p[i]))
                                    isencrypted = true;
                            // new format -----BEGIN OPENSSH PRIVATE KEY-----
                            // check whether the encoded string contains bcrypt
                            if (!isencrypted) {
                                char* p2 = filebuf;
                                while (p2[0] == '\r' || p2[0] == '\n')
                                    p2++;
                                if (strncmp(p2, "-----BEGIN OPENSSH PRIVATE KEY-----", 35) == 0) {
                                    char outbuf[64];
                                    int l = MimeDecode(p, min(64, strlen(p)), outbuf, sizeof(outbuf));
                                    for (int i = 0; i < l - 6; i++) {
                                        if (outbuf[i] == 'b' && strncmp(outbuf + i,"bcrypt", 6) == 0) {
                                            isencrypted = true;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    CloseHandle(hf);
                    if (isencrypted) {
                        char title[250];
                        LoadStr(buf, IDS_PASSPHRASE);
                        strlcpy(title, buf, sizeof(title)-1);
                        strlcat(title, ConnectSettings->user, sizeof(title)-1);
                        strlcat(title, "@", sizeof(title)-1);
                        strlcat(title, ConnectSettings->server, sizeof(title)-1);
                        LoadStr(buf, IDS_KEYPASSPHRASE);
                        if (ConnectSettings->password[0] != 0) {
                            char* p = strstr(ConnectSettings->password, "\",\"");
                            int len = strlen(ConnectSettings->password);
                            if (p && ConnectSettings->password[0] == '"' && ConnectSettings->password[len-1] == '"') {
                                // two passwords -> use second one!
                                p[0] = 0;
                                strlcpy(passphrase, ConnectSettings->password + 1, sizeof(passphrase)-1);
                                p[0] = '"';
                            } else
                            strlcpy(passphrase, ConnectSettings->password, sizeof(passphrase)-1);
                        } else
                            RequestProc(PluginNumber, RT_Password, title, buf, passphrase, sizeof(passphrase)-1);
                    }

                    LoadStr(buf, IDS_AUTH_PUBKEY_FOR);
                    strlcpy(buf, "Auth via public key for user: ", sizeof(buf)-1);
                    strlcat(buf, ConnectSettings->user, sizeof(buf)-1);
                    ShowStatus(buf);

                    if (strcmp(pubkeyfile, privkeyfile) == 0)
                        pubkeyfileptr = NULL;

                    LoadStr(buf, IDS_AUTH_PUBKEY);
                    while ((auth = libssh2_userauth_publickey_fromfile(ConnectSettings->session,
                                        ConnectSettings->user,
                                        pubkeyfileptr,
                                        privkeyfile,
                                        passphrase)) == LIBSSH2_ERROR_EAGAIN) {
                        if (ProgressLoop(buf, 60, 70, &loop, &lasttime))
                            break;
                        IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
                    }
                    if (auth == LIBSSH2_ERROR_REQUIRE_KEYBOARD)
                        auth_pw = 2;
                    else if (auth == LIBSSH2_ERROR_REQUIRE_PASSWORD)
                        auth_pw = 1;
                    else if (auth) {
                        SftpLogLastError("libssh2_userauth_publickey_fromfile: ", auth);
                        ShowErrorId(IDS_ERR_AUTH_PUBKEY);
                    }
                    else if (!ConnectSettings->password[0])
                        strlcpy(ConnectSettings->password, passphrase, sizeof(ConnectSettings->password)-1);
                }
            }
        } else
            auth_pw = auth_pw & 3;
        if ((auth_pw & 4) == 0) {
            if (auth_pw & 2) {   // keyboard-interactive
                LoadStr(buf, IDS_AUTH_KEYBDINT_FOR);
                strlcat(buf, ConnectSettings->user, sizeof(buf)-1);
                ShowStatus(buf);

                LoadStr(buf, IDS_AUTH_KEYBDINT);
                ConnectSettings->InteractivePasswordSent = false;
                while ((auth = libssh2_userauth_keyboard_interactive(ConnectSettings->session,ConnectSettings->user, &kbd_callback))==
                    LIBSSH2_ERROR_EAGAIN) {
                    if (ProgressLoop(buf, 70, 80, &loop, &lasttime))
                        break;
                    IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
                }
                if (auth) {
                    SftpLogLastError("libssh2_userauth_keyboard_interactive: ", auth);
                    if ((auth_pw & 1) == 0)  // only show error if password auth isn't supported - otherwise try that
                        ShowErrorId(IDS_ERR_AUTH_KEYBDINT);
                }
            } else
                auth = LIBSSH2_ERROR_INVAL;
            if (auth != 0 && (auth_pw & 1) != 0) {
                char passphrase[256];

                char* p = strstr(ConnectSettings->password, "\",\"");
                int len = strlen(ConnectSettings->password);
                if (p && ConnectSettings->password[0] == '"' && ConnectSettings->password[len-1] == '"') {
                    // two passwords -> use second one!
                    ConnectSettings->password[len-1] = 0;
                    strlcpy(passphrase, p + 3, sizeof(passphrase)-1);
                    ConnectSettings->password[len-1] = '"';
                } else
                    strlcpy(passphrase, ConnectSettings->password, sizeof(passphrase)-1);
                if (passphrase[0] == 0) {
                    char title[250];
                    strlcpy(title, "SFTP password for ", sizeof(title)-1);
                    strlcat(title, ConnectSettings->user, sizeof(title)-1);
                    strlcat(title, "@", sizeof(title)-1);
                    strlcat(title, ConnectSettings->server, sizeof(title)-1);
                    RequestProc(PluginNumber, RT_Password, title, NULL, passphrase, sizeof(passphrase)-1);
                }
 
                LoadStr(buf, IDS_AUTH_PASSWORD_FOR);
                strlcat(buf, ConnectSettings->user, sizeof(buf)-1);
                ShowStatus(buf);

                LoadStr(buf, IDS_AUTH_PASSWORD);
                /* We could authenticate via password */
                while(1) {
                    auth = libssh2_userauth_password_ex(ConnectSettings->session, ConnectSettings->user, strlen(ConnectSettings->user), passphrase, strlen(passphrase), &newpassfunc);
                    if (auth != LIBSSH2_ERROR_EAGAIN && auth != LIBSSH2_ERROR_PASSWORD_EXPIRED)
                        break;
                    if (ProgressLoop(buf, 70, 80, &loop, &lasttime))
                        break;
                    IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
                }
                void* abst = ConnectSettings;
                if (auth) {
                    SftpLogLastError("libssh2_userauth_password_ex: ", auth);
                    ShowErrorId(IDS_ERR_AUTH_PASSWORD);
                }
                else if (!ConnectSettings->password[0])
                    strlcpy(ConnectSettings->password, passphrase, sizeof(ConnectSettings->password)-1);
            }
        } 
        
        if (auth){
            libssh2_session_disconnect(ConnectSettings->session, "Shutdown");
            libssh2_session_free(ConnectSettings->session); 
            ConnectSettings->session = NULL;
            Sleep(1000);
            closesocket(ConnectSettings->sock); 
            ConnectSettings->sock = 0;
            return SFTP_FAILED;
        }
        /*char* banner=_ssh_get_issue_banner(ConnectSettings->session);
        if(banner){
            ShowStatus(banner);
            free(banner);
        }*/

        // try to auto-detect UTF-8 settings
        if (ConnectSettings->utf8names == -1) {
            ConnectSettings->utf8names = 0;
            ConnectSettings->codepage = 0;

            char cmdname[MAX_PATH];
            char reply[8192];
            strlcpy(cmdname, "echo $LC_ALL $LC_CTYPE $LANG", sizeof(cmdname)-1);
            reply[0] = 0;
            if (SftpQuoteCommand2(ConnectSettings, NULL, cmdname, reply, sizeof(reply)-1) == 0) {
#ifdef _strupr_s
                _strupr_s(reply, sizeof(reply));
#else
                _strupr(reply);
#endif
                if (strstr(reply, "UTF-8"))
                    ConnectSettings->utf8names = 1;
                else {
                    strlcpy(cmdname, "locale", sizeof(cmdname)-1);
                    if (SftpQuoteCommand2(ConnectSettings, NULL, cmdname, reply, sizeof(reply)-1) == 0) {
#ifdef _strupr_s
                        _strupr_s(reply, sizeof(reply));
#else
                        _strupr(reply);
#endif
                        if (strstr(reply, "UTF-8"))
                            ConnectSettings->utf8names = 1;
                    }
                }
            }
            // store the result!
            if (strcmp(ConnectSettings->DisplayName, s_quickconnect) != 0)
                WritePrivateProfileString(ConnectSettings->DisplayName, "utf8", ConnectSettings->utf8names ? "1" : "0", ConnectSettings->IniFileName);
        }
        if (ConnectSettings->unixlinebreaks == -1) {
            ConnectSettings->unixlinebreaks = 0;
            char cmdname[MAX_PATH];
            char reply[8192];
            strlcpy(cmdname, "echo $OSTYPE", sizeof(cmdname)-1);
            reply[0] = 0;
            if (SftpQuoteCommand2(ConnectSettings, NULL, cmdname, reply, sizeof(reply)-1) == 0) {
#ifdef _strupr_s
                _strupr_s(reply, sizeof(reply));
#else
                _strupr(reply);
#endif
                if (strstr(reply, "LINUX") || strstr(reply, "UNIX") || strstr(reply, "AIX"))
                    ConnectSettings->unixlinebreaks = 1;
                else {   // look whether the returned data ends with LF or CRLF!
                    global_detectcrlf = -1;
                    strlcpy(cmdname, "ls -l", sizeof(cmdname)-1); // try to get some multi-line reply
                    if (SftpQuoteCommand2(ConnectSettings, NULL, cmdname, reply, sizeof(reply)-1) == 0) {
                        if (global_detectcrlf == 0)
                            ConnectSettings->unixlinebreaks = 1;
                    }
                }
            }
            // store the result!
            if (strcmp(ConnectSettings->DisplayName, s_quickconnect) != 0)
                WritePrivateProfileString(ConnectSettings->DisplayName, "unixlinebreaks", ConnectSettings->unixlinebreaks ? "1" : "0", ConnectSettings->IniFileName);
        }
        ConnectSettings->sftpsession = NULL;

        // Send user-defined command line
        if (ConnectSettings->connectsendcommand[0]) {
            ShowStatus("Sending user-defined command:");
            ShowStatus(ConnectSettings->connectsendcommand);
            strlcpy(buf, ConnectSettings->connectsendcommand, sizeof(buf)-1);
            LIBSSH2_CHANNEL *channel;
            channel = ConnectChannel(ConnectSettings->session);
            SftpLogLastError("ConnectChannel: ", libssh2_session_last_errno(ConnectSettings->session));
            if (ConnectSettings->sendcommandmode <= 1) {
                if (SendChannelCommand(ConnectSettings->session, channel, ConnectSettings->connectsendcommand)) {
                    while (!libssh2_channel_eof(channel)) {
                        if (ProgressLoop(buf, 80, 90, &loop, &lasttime))
                            break;
                        char databuf[1024], *p, *p2;
                        databuf[0] = 0;
                        if (0 < libssh2_channel_read_stderr(channel, databuf, sizeof(databuf)-1)) {
                            p = databuf;
                            while (p[0] > 0 && p[0] <= ' ')
                                p++;
                            if (p[0]) {
                                p2 = p + strlen(p) - 1;
                                while (p2[0] <= ' ' && p2 >= p) {
                                    p2[0] = 0;
                                    p2--;
                                }
                            }
                            if (p[0])
                                ShowStatus(databuf);
                        }
                        databuf[0] = 0;
                        if (!libssh2_channel_eof(channel) &&
                            0 < libssh2_channel_read(channel, databuf, sizeof(databuf)-1)) {
                            p = databuf;
                            while (p[0] > 0 && p[0] <= ' ')
                                p++;
                            if (p[0]) {
                                p2 = p + strlen(p) - 1;
                                while (p2[0] <= ' ' && p2 >= p) {
                                    p2[0] = 0;
                                    p2--;
                                }
                            }
                            if (p[0])
                                ShowStatus(databuf);
                        }
                    }
                }
                if (ConnectSettings->sendcommandmode == 0)
                    DisconnectShell(channel);
            } else {
                int rc = -1;
                do {
                    rc = libssh2_channel_exec(channel, ConnectSettings->connectsendcommand);
                    if (rc <0 ) {
                        if (rc == -1)
                            rc = libssh2_session_last_errno(ConnectSettings->session);
                        if (rc != LIBSSH2_ERROR_EAGAIN)
                            break;
                    }
                    if (EscapePressed())
                        break;
                } while (rc < 0);
            }
            Sleep(1000);
        }

        if (ConnectSettings->scpfordata && ConnectSettings->scpserver64bit == -1) {
            ConnectSettings->scpserver64bit = 0;
            char cmdname[MAX_PATH];
            char reply[8192];
            strlcpy(cmdname, "file `which scp`", sizeof(cmdname)-1);
            reply[0] = 0;
            if (SftpQuoteCommand2(ConnectSettings, NULL, cmdname, reply, sizeof(reply)-1) == 0) {
#ifdef _strupr_s
                _strupr_s(reply, sizeof(reply));
#else
                _strupr(reply);
#endif
                // /usr/bin/scp: ELF 32-bit LSB executable, ARM ...
                // /usr/bin/scp: ELF 64-bit LSB shared object, x86-64 ...
                if (strstr(reply, "64-BIT")) {
                    ShowStatus("64-bit scp detected!");
                    ConnectSettings->scpserver64bit = 1;
                }
            }
            // store the result!
            if (strcmp(ConnectSettings->DisplayName, s_quickconnect) != 0)
                WritePrivateProfileString(ConnectSettings->DisplayName, "largefilesupport", ConnectSettings->scpserver64bit ? "1" : "0", ConnectSettings->IniFileName);
        }

        if (!ConnectSettings->scponly) {
            LoadStr(buf, IDS_SESSION_STARTUP);
            strlcat(buf, " (SFTP)", sizeof(buf)-1);
            ShowStatus(buf);
            do {
                ConnectSettings->sftpsession = NULL;
                if (ProgressLoop(buf, 80, 90, &loop, &lasttime))
                    break;
                ConnectSettings->sftpsession=libssh2_sftp_init(ConnectSettings->session);
                if ((!ConnectSettings->sftpsession) && (libssh2_session_last_errno(ConnectSettings->session) != LIBSSH2_ERROR_EAGAIN)) {
                    break;
                }
                IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
            } while (!ConnectSettings->sftpsession);

            if (!ConnectSettings->sftpsession){
                LoadStr(buf, IDS_ERR_INIT_SFTP);
                char* errmsg;
                int errmsg_len, rc;
                libssh2_session_last_error(ConnectSettings->session, &errmsg, &errmsg_len, false);
                strlcat(buf, errmsg, sizeof(buf)-1);
                ShowError(buf);
                LoadStr(buf, IDS_DISCONNECTING);
                do {
                    rc = libssh2_session_disconnect(ConnectSettings->session, "Shutdown");
                    if (ProgressLoop(buf, 80, 90, &loop, &lasttime))
                        break;
                    IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
                } while (rc == LIBSSH2_ERROR_EAGAIN);
                libssh2_session_free(ConnectSettings->session);
                ConnectSettings->session = NULL;
                Sleep(1000);
                closesocket(ConnectSettings->sock);
                ConnectSettings->sock = 0;
                return SFTP_FAILED;
            }

            // Seems that we need to set it again,  so the sftpsession is informed too!
            // Otherwise disconnect hangs with CoreFTP mini-sftp-server in libssh2_sftp_shutdown
            libssh2_session_set_blocking(ConnectSettings->session, 0);
        }

        LoadStr(buf, IDS_GET_DIRECTORY);
        if (ProgressProc(PluginNumber, buf, "-", 90)) {
            LoadStr(buf, IDS_DISCONNECTING);
            int rc;
            if (ConnectSettings->sftpsession) {
                do {
                    rc = libssh2_sftp_shutdown(ConnectSettings->sftpsession);
                    if (ProgressLoop(buf, 80, 100, &loop, &lasttime))
                        break;
                    IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
                } while (rc == LIBSSH2_ERROR_EAGAIN);
                ConnectSettings->sftpsession = NULL;
            }
            do {
                rc = libssh2_session_disconnect(ConnectSettings->session,  "Shutdown");
                if (ProgressLoop(buf, 80, 100, &loop, &lasttime))
                    break;
                IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
            } while (rc == LIBSSH2_ERROR_EAGAIN);
            libssh2_session_free(ConnectSettings->session); 
            ConnectSettings->session = NULL;
            Sleep(1000);
            closesocket(ConnectSettings->sock);
            ConnectSettings->sock = 0;
            return SFTP_FAILED;
        }
    }
    if (ConnectSettings->scponly) {
        if (!ConnectSettings->session)
            return SFTP_FAILED;
        else
            return SFTP_OK;
    } else if (!ConnectSettings->sftpsession) {
        return SFTP_FAILED;
    } else
        return SFTP_OK;
}

LPCTSTR g_pszKey = TEXT("unpzScGeCInX7XcRM2z+svTK+gegRLhz9KXVbYKJl5boSvVCcfym");

void EncryptString(LPCTSTR pszPlain, LPTSTR pszEncrypted, UINT cchEncrypted)
{
    int iPlainLength = lstrlen(pszPlain);
    int iKeyLength = lstrlen(g_pszKey);
    int iPos = lstrlen(pszPlain) % iKeyLength;

    pszEncrypted[0] = '\0';
    
    for (int iChar = 0; iChar < iPlainLength; iChar++) {
#ifdef sprintf_s
        sprintf_s(pszEncrypted, cchEncrypted, ("%s%03d"), pszEncrypted, (unsigned char)pszPlain[iChar] ^ (unsigned char)g_pszKey[(iChar + iPos) % iKeyLength]);
#else
        sprintf(pszEncrypted, ("%s%03d"), pszEncrypted, (unsigned char)pszPlain[iChar] ^ (unsigned char)g_pszKey[(iChar + iPos) % iKeyLength]);
#endif
    }
}

void DecryptString(LPCTSTR pszEncrypted, LPTSTR pszPlain, UINT cchPlain)
{
    if (strcmp(pszEncrypted, "!") == 0) {   // signal password-protected password
        if (CryptProc)
            strlcpy(pszPlain, "\001", cchPlain-1);
        else
            pszPlain[0] = 0;
        return;
    }
    int iKeyLength = lstrlen(g_pszKey);
    int iEncryptedLength = lstrlen(pszEncrypted);
    int iPos = (iEncryptedLength/3) % iKeyLength;
    int iChar;

    pszPlain[0] = ('\0');

    for (iChar = 0; iChar < iEncryptedLength / 3 && iChar < (int)(cchPlain - 1); iChar++) {
        int iDigit = pszEncrypted[iChar * 3];
        if (iDigit < '0' || iDigit > '9') {
            pszPlain[0] = ('\0');
            return;
        }

        int iNumber = (iDigit - '0') * 100;
        iDigit = pszEncrypted[iChar * 3 + 1];
        if (iDigit < '0' || iDigit > '9') {
            pszPlain[0] = ('\0');
            return;
        }
        
        iNumber += (iDigit - '0') * 10;
        iDigit = pszEncrypted[iChar * 3 + 2];
        if (iDigit < '0' || iDigit > '9') {
            pszPlain[0] = ('\0');
            return;
        }
        
        iNumber += iDigit - '0';
        pszPlain[iChar] = (iNumber ^ g_pszKey[(iChar + iPos) % iKeyLength]);
    }

    pszPlain[iChar] = ('\0');
}

void SftpGetServerBasePathW(WCHAR* DisplayName, WCHAR* RelativePath, int maxlen, char* inifilename)
{
    char DisplayNameA[MAX_PATH], server[MAX_PATH];
    walcopy(DisplayNameA, DisplayName, sizeof(DisplayNameA)-1);
    GetPrivateProfileString(DisplayNameA, "server", "", server, sizeof(server)-1, inifilename);
    ReplaceBackslashBySlash(server);
    // Remove trailing sftp://
    if (_strnicmp(server, "sftp://", 7) == 0)
        memmove(server, server+7, strlen(server)-6);
    ReplaceBackslashBySlash(server);
    char* p = strchr(server, '/');
    if (p)
        awlcopy(RelativePath, p, maxlen);
    else
        wcslcpy(RelativePath, L"/", maxlen);
}

BOOL LoadProxySettingsFromNr(int proxynr, pConnectSettings ConnectResults)
{
    if (proxynr > 0) {
        TCHAR proxyentry[64];
        if (proxynr > 1)
#ifdef sprintf_s
            sprintf_s(proxyentry, sizeof(proxyentry), "proxy%d", proxynr);
#else
            sprintf(proxyentry, "proxy%d", proxynr);
#endif
        else
            strlcpy(proxyentry, "proxy", sizeof(proxyentry)-1);
        int type = GetPrivateProfileInt(proxyentry, "proxytype", -1, gIniFileName);
        if (type == -1)
            ConnectResults->proxytype = 0;
        else
            ConnectResults->proxytype = type;
        GetPrivateProfileString(proxyentry, "proxyserver", "", ConnectResults->proxyserver, sizeof(ConnectResults->proxyuser)-1, gIniFileName);
        GetPrivateProfileString(proxyentry, "proxyuser", "", ConnectResults->proxyuser, sizeof(ConnectResults->proxyuser)-1, gIniFileName);
        char szPassword[MAX_PATH];
        if (GetPrivateProfileString(proxyentry, "proxypassword", "", szPassword, countof(szPassword), gIniFileName)) {
            DecryptString(szPassword,  ConnectResults->proxypassword, countof(ConnectResults->proxypassword));
        } else
            ConnectResults->proxypassword[0] = 0;
        return (type != -1 || proxynr == 1);   //nr 1 is always valid
    } else {
        ConnectResults->proxytype = 0;
        ConnectResults->proxyserver[0] = 0;
        ConnectResults->proxyuser[0] = 0;
        ConnectResults->proxypassword[0] = 0;
        return false;
    }
}

BOOL LoadServerSettings(char* DisplayName, pConnectSettings ConnectResults)
{
    char szPassword[MAX_PATH], modbuf[6];
    strlcpy(ConnectResults->DisplayName, DisplayName, sizeof(ConnectResults->DisplayName)-1);
    strlcpy(ConnectResults->IniFileName, gIniFileName, sizeof(ConnectResults->IniFileName)-1);
    GetPrivateProfileString(DisplayName, "server", "", ConnectResults->server, sizeof(ConnectResults->server)-1, gIniFileName);
    ConnectResults->protocoltype=GetPrivateProfileInt(DisplayName, "protocol", 0, gIniFileName);
    GetPrivateProfileString(DisplayName, "user", "", ConnectResults->user, sizeof(ConnectResults->user)-1, gIniFileName);
    GetPrivateProfileString(DisplayName, "fingerprint", "", ConnectResults->savedfingerprint, sizeof(ConnectResults->savedfingerprint)-1, gIniFileName);
    GetPrivateProfileString(DisplayName, "pubkeyfile", "", ConnectResults->pubkeyfile, sizeof(ConnectResults->pubkeyfile)-1, gIniFileName);
    GetPrivateProfileString(DisplayName, "privkeyfile", "", ConnectResults->privkeyfile, sizeof(ConnectResults->privkeyfile)-1, gIniFileName);
    ConnectResults->useagent = GetPrivateProfileInt(gDisplayName, "useagent", 0, gIniFileName) != 0;

    GetPrivateProfileString(DisplayName, "filemod", "644", modbuf, sizeof(modbuf)-1, gIniFileName);
    ConnectResults->filemod = strtol(modbuf, NULL, 8);
    GetPrivateProfileString(DisplayName, "dirmod", "755", modbuf, sizeof(modbuf)-1, gIniFileName);
    ConnectResults->dirmod = strtol(modbuf, NULL, 8);

    ConnectResults->compressed = GetPrivateProfileInt(gDisplayName, "compression", 0, gIniFileName) != 0;
    ConnectResults->scpfordata = GetPrivateProfileInt(gDisplayName, "scpfordata", 0, gIniFileName) != 0;
    ConnectResults->scponly = GetPrivateProfileInt(gDisplayName, "scponly", 0, gIniFileName) != 0;
    if (ConnectResults->scponly)
        ConnectResults->scpfordata = true;
    ConnectResults->trycustomlistcommand = 2;
    ConnectResults->keepAliveIntervalSeconds = GetPrivateProfileInt(gDisplayName, "keepaliveseconds", 0, gIniFileName);
    ConnectResults->hWndKeepAlive = NULL;

    ConnectResults->detailedlog = GetPrivateProfileInt(gDisplayName, "detailedlog", 0, gIniFileName) != 0;
    ConnectResults->utf8names = GetPrivateProfileInt(gDisplayName, "utf8", -1, gIniFileName); // -1 means auto-detect
    ConnectResults->codepage = GetPrivateProfileInt(gDisplayName, "codepage", 0, gIniFileName); // -1 means local ANSI
    ConnectResults->unixlinebreaks = GetPrivateProfileInt(gDisplayName, "unixlinebreaks", -1, gIniFileName); // -1 means auto-detect
    ConnectResults->scpserver64bit = GetPrivateProfileInt(gDisplayName, "largefilesupport", -1, gIniFileName); // -1 means auto-detect
    ConnectResults->password[0] = 0;
    // we don't need a password when using Pageant!
    if (GetPrivateProfileString(gDisplayName, "password", "",  szPassword,  countof(szPassword),  gIniFileName)) {
        if (!ConnectResults->useagent)
            DecryptString(szPassword, ConnectResults->password, countof(ConnectResults->password));
        else if (strcmp(szPassword, "!") == 0)
            strlcpy(ConnectResults->password, "\001", sizeof(ConnectResults->password)-1);
    }
    ConnectResults->proxynr = GetPrivateProfileInt(gDisplayName, "proxynr", 1, gIniFileName);

    LoadProxySettingsFromNr(ConnectResults->proxynr, ConnectResults);
    ConnectResults->neednewchannel = false;
    GetPrivateProfileString(DisplayName, "sendcommand", "", ConnectResults->connectsendcommand, sizeof(ConnectResults->connectsendcommand)-1, gIniFileName);
    ConnectResults->sendcommandmode = GetPrivateProfileInt(gDisplayName, "sendcommandmode", 0, gIniFileName);
    return ConnectResults->server[0] != 0;
}

int codepagelist[] = {-1, -2, 0, 1, 2, 1250, 1251, 1252, 1253, 1254, 1255, 1256, 1257, 1258,
                      936, 950, 932, 949, 874, 437, 850, 20866, -3, -4};

void EnableControlsPageant(HWND hWnd, BOOL enable)
{
    //EnableWindow(GetDlgItem(hWnd, IDC_PASSWORD), enable);  <- new! We can have both pubkey+keyboard interactive logins!
    //EnableWindow(GetDlgItem(hWnd, IDC_EDITPASS), enable);
    //EnableWindow(GetDlgItem(hWnd, IDC_CRYPTPASS), enable);
    EnableWindow(GetDlgItem(hWnd, IDC_CERTFRAME), enable);
    EnableWindow(GetDlgItem(hWnd, IDC_STATICPUB), enable);
    EnableWindow(GetDlgItem(hWnd, IDC_STATICPEM), enable);
    EnableWindow(GetDlgItem(hWnd, IDC_PUBKEY), enable);
    EnableWindow(GetDlgItem(hWnd, IDC_PRIVKEY), enable);
    EnableWindow(GetDlgItem(hWnd, IDC_LOADPUBKEY), enable);
    EnableWindow(GetDlgItem(hWnd, IDC_LOADPRIVKEY), enable);
}

int gProxyNr = 0;

myint __stdcall ProxyDlgProc(HWND hWnd, unsigned int Message, WPARAM wParam, LPARAM lParam)
{
    RECT rt1, rt2;
    int w, h, DlgWidth, DlgHeight, NewPosX, NewPosY;
    tConnectSettings ConnectData;

    switch (Message) {
    case WM_INITDIALOG: {
        LoadProxySettingsFromNr(gProxyNr, &ConnectData);

        switch (ConnectData.proxytype) {
        case 2:  g_focusset = IDC_OTHERPROXY; break;
        case 3:  g_focusset = IDC_SOCKS4APROXY; break;
        case 4:  g_focusset = IDC_SOCKS5PROXY; break;
        default: g_focusset = IDC_NOPROXY;
        }
        CheckRadioButton(hWnd, IDC_NOPROXY, IDC_SOCKS5PROXY, g_focusset);

        EnableWindow(GetDlgItem(hWnd, IDC_PROXYSERVER), ConnectData.proxytype != 0);
        EnableWindow(GetDlgItem(hWnd, IDC_PROXYUSERNAME), ConnectData.proxytype != 0);
        EnableWindow(GetDlgItem(hWnd, IDC_PROXYPASSWORD), ConnectData.proxytype != 0);
        SetDlgItemText(hWnd, IDC_PROXYSERVER, ConnectData.proxyserver);
        SetDlgItemText(hWnd, IDC_PROXYUSERNAME, ConnectData.proxyuser);

        if (strcmp(ConnectData.proxypassword, "\001") == 0 && CryptProc) {
            char proxyentry[64];
            if (gProxyNr > 1)
#ifdef sprintf_s
                sprintf_s(proxyentry, sizeof(proxyentry), "proxy%d", gProxyNr);
#else
                sprintf(proxyentry, "proxy%d", gProxyNr);
#endif
            else
                strlcpy(proxyentry, "proxy", sizeof(proxyentry)-1);

            strlcat(proxyentry, "$$pass", sizeof(proxyentry)-1);

            if (CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_LOAD_PASSWORD_NO_UI, proxyentry, ConnectData.proxypassword, countof(ConnectData.proxypassword)-1) == FS_FILE_OK) {
                SetDlgItemText(hWnd, IDC_PROXYPASSWORD, ConnectData.proxypassword);
                CheckDlgButton(hWnd, IDC_CRYPTPASS, BST_CHECKED);
            } else {
                ShowWindow(GetDlgItem(hWnd, IDC_PROXYPASSWORD), SW_HIDE);
                ShowWindow(GetDlgItem(hWnd, IDC_CRYPTPASS), SW_HIDE);
                ShowWindow(GetDlgItem(hWnd, IDC_EDITPASS), SW_SHOW);
            }
        } else {
            SetDlgItemText(hWnd, IDC_PROXYPASSWORD, ConnectData.proxypassword);
            if (!CryptProc)
                EnableWindow(GetDlgItem(hWnd, IDC_CRYPTPASS), false);
            else if (ConnectData.proxypassword[0] == 0 && CryptCheckPass)
                CheckDlgButton(hWnd, IDC_CRYPTPASS, BST_CHECKED);
        }
        
        // trying to center the About dialog
        if (GetWindowRect(hWnd, &rt1) && GetWindowRect(GetParent(hWnd), &rt2)) {
            w = rt2.right  - rt2.left;
            h = rt2.bottom - rt2.top;
            DlgWidth   = rt1.right - rt1.left;
            DlgHeight  = rt1.bottom - rt1.top;
            NewPosX    = rt2.left + (w - DlgWidth)/2;
            NewPosY    = rt2.top + (h - DlgHeight)/2;
            SetWindowPos(hWnd, 0, NewPosX, NewPosY, 0, 0, SWP_NOZORDER | SWP_NOSIZE);
        }
        return 1;
    }
    case WM_SHOWWINDOW: {
        if (g_focusset)
            SetFocus(GetDlgItem(hWnd, g_focusset));
        break;
    }
    case WM_COMMAND: {
        switch (LOWORD(wParam)) {
        case IDOK: {
            if (IsDlgButtonChecked(hWnd, IDC_NOPROXY))
                ConnectData.proxytype = 0;
            else if (IsDlgButtonChecked(hWnd, IDC_OTHERPROXY))
                ConnectData.proxytype = 2;
            else if (IsDlgButtonChecked(hWnd, IDC_SOCKS4APROXY))
                ConnectData.proxytype = 3;
            else if (IsDlgButtonChecked(hWnd, IDC_SOCKS5PROXY))
                ConnectData.proxytype = 4;
            else
                ConnectData.proxytype = 0;

            GetDlgItemText(hWnd, IDC_PROXYSERVER, ConnectData.proxyserver, sizeof(ConnectData.proxyserver)-1);
            GetDlgItemText(hWnd, IDC_PROXYUSERNAME, ConnectData.proxyuser, sizeof(ConnectData.proxyuser)-1);
            GetDlgItemText(hWnd, IDC_PROXYPASSWORD, ConnectData.proxypassword, sizeof(ConnectData.proxypassword)-1);

            char proxyentry[64];
            if (gProxyNr > 1)
#ifdef sprintf_s
                sprintf_s(proxyentry, sizeof(proxyentry), "proxy%d", gProxyNr);
#else
                sprintf(proxyentry, "proxy%d", gProxyNr);
#endif
            else
                strlcpy(proxyentry, "proxy", sizeof(proxyentry)-1);

            WritePrivateProfileString(proxyentry, "proxyserver", ConnectData.proxyserver, gIniFileName);
            WritePrivateProfileString(proxyentry, "proxyuser", ConnectData.proxyuser, gIniFileName);
            char buf[64];
            _itoa_s(ConnectData.proxytype, buf, sizeof(buf), 10);
            WritePrivateProfileString(proxyentry, "proxytype", ConnectData.proxytype!=0 ? buf : NULL, gIniFileName);

            char szEncryptedPassword[256];
            if (!IsWindowVisible(GetDlgItem(hWnd, IDC_EDITPASS))) {  //button not visible
                if (ConnectData.proxypassword[0] == 0) {
                    WritePrivateProfileString(proxyentry, "proxypassword", NULL, gIniFileName);
                } else if (CryptProc && IsDlgButtonChecked(hWnd, IDC_CRYPTPASS)) {
                    char proxyentry2[64];
                    strlcpy(proxyentry2, proxyentry, sizeof(proxyentry2)-1);
                    strlcat(proxyentry2, "$$pass", sizeof(proxyentry2)-1);
                    BOOL ok = CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_SAVE_PASSWORD, proxyentry2, ConnectData.proxypassword, 0) == FS_FILE_OK;
                    WritePrivateProfileString(proxyentry, "proxypassword", ok? "!" : NULL, gIniFileName);
                    CryptCheckPass = true;
                } else {
                    EncryptString(ConnectData.proxypassword, szEncryptedPassword, countof(szEncryptedPassword));
                    WritePrivateProfileString(proxyentry, "proxypassword", szEncryptedPassword, gIniFileName);
                }
            }
            
            EndDialog(hWnd, IDOK);
            return 1;
        }
        case IDCANCEL:
        {
            EndDialog(hWnd, IDCANCEL);
            return 1;
        }
        case IDC_OTHERPROXY:
        case IDC_SOCKS4APROXY:
        case IDC_SOCKS5PROXY:
            EnableWindow(GetDlgItem(hWnd, IDC_PROXYSERVER), true);
            EnableWindow(GetDlgItem(hWnd, IDC_PROXYUSERNAME), true);
            EnableWindow(GetDlgItem(hWnd, IDC_PROXYPASSWORD), true);
            SetFocus(GetDlgItem(hWnd, IDC_PROXYSERVER));
            break;
        case IDC_NOPROXY:
            EnableWindow(GetDlgItem(hWnd, IDC_PROXYSERVER), false);
            EnableWindow(GetDlgItem(hWnd, IDC_PROXYUSERNAME), false);
            EnableWindow(GetDlgItem(hWnd, IDC_PROXYPASSWORD), false);
            break;
        case IDC_PROXYHELP:
        {
            TCHAR szCaption[100];
            LoadString(hinst,  IDS_HELP_CAPTION,  szCaption,  countof(szCaption));
            TCHAR szBuffer[1024];
            LoadString(hinst,  IDS_HELP_PROXY,  szBuffer,  countof(szBuffer));
            MessageBox(hWnd, szBuffer, szCaption, MB_OK | MB_ICONINFORMATION);
            break;
        }
        case IDC_EDITPASS:
        {   
            BOOL doshow = true;
            int err;
            TCHAR proxyentry[64];
            if (gProxyNr > 1)
#ifdef sprintf_s
                sprintf_s(proxyentry, sizeof(proxyentry), "proxy%d", gProxyNr);
#else
                sprintf(proxyentry, "proxy%d", gProxyNr);
#endif
            else
                strlcpy(proxyentry, "proxy", sizeof(proxyentry)-1);

            strlcat(proxyentry, "$$pass", sizeof(proxyentry)-1);

            err = CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_LOAD_PASSWORD, proxyentry, ConnectData.proxypassword, countof(ConnectData.proxypassword)-1);
            if (err == FS_FILE_OK) {
                SetDlgItemText(hWnd, IDC_PROXYPASSWORD, ConnectData.proxypassword);
            } else if (err = FS_FILE_READERROR) {         // no password stored!
                SetDlgItemText(hWnd, IDC_PROXYPASSWORD, "");
            } else {
                doshow = false;
            }
            if (doshow) {
                ShowWindow(GetDlgItem(hWnd, IDC_PROXYPASSWORD), SW_SHOW);
                ShowWindow(GetDlgItem(hWnd, IDC_CRYPTPASS), SW_SHOW);
                ShowWindow(GetDlgItem(hWnd, IDC_EDITPASS), SW_HIDE);
                if (gConnectResults->password[0] != 0)
                    CheckDlgButton(hWnd, IDC_CRYPTPASS, BST_CHECKED);
            }
        }
        } /* switch */
    }
    } /* switch */
    return 0;
}

void fillProxyCombobox(HWND hWnd, int defproxynr)
{
    SendDlgItemMessage(hWnd, IDC_PROXYCOMBO, CB_RESETCONTENT, 0, 0);
    TCHAR noproxy[100], addproxy[100], httpproxy[100], buf[256];
    LoadString(hinst, IDS_NO_PROXY,   noproxy,   countof(noproxy));
    LoadString(hinst, IDS_HTTP_PROXY, httpproxy, countof(httpproxy));
    LoadString(hinst, IDS_ADD_PROXY,  addproxy,  countof(addproxy));
    
    SendDlgItemMessage(hWnd, IDC_PROXYCOMBO, CB_ADDSTRING, 0, (LPARAM)&noproxy);
    
    tConnectSettings connectData;
    int proxynr = 1;
    while (true) {
        if (LoadProxySettingsFromNr(proxynr, &connectData)) {
#ifdef sprintf_s
            sprintf_s(buf, sizeof(buf), TEXT("%d: "), proxynr);
#else
            sprintf(buf, TEXT("%d: "), proxynr);
#endif
            switch (connectData.proxytype) {
            case 0:
                strlcat(buf, noproxy, sizeof(buf)-1);
                break;
            case 2:
                strlcat(buf, httpproxy, sizeof(buf)-1);
                break;
            case 3:
                strlcat(buf, "SOCKS4a: ", sizeof(buf)-1);
                break;
            case 4:
                strlcat(buf, "SOCKS5: ", sizeof(buf)-1);
                break;
            }
            if (connectData.proxytype > 0)
                strlcat(buf, connectData.proxyserver, sizeof(buf)-1);
            SendDlgItemMessage(hWnd, IDC_PROXYCOMBO, CB_ADDSTRING, 0, (LPARAM)&buf);
        } else
            break;
        proxynr++;
    }
    SendDlgItemMessage(hWnd, IDC_PROXYCOMBO, CB_ADDSTRING, 0, (LPARAM)&addproxy);
    if (defproxynr >= 0 && defproxynr <= proxynr)
        SendDlgItemMessage(hWnd, IDC_PROXYCOMBO, CB_SETCURSEL, defproxynr, 0);
}

BOOL DeleteLastProxy(int proxynrtodelete, char* ServerToSkip, char *AppendToList, int maxlen)
{
    if (proxynrtodelete <= 1)
        return false;

    BOOL CanDelete = true;
    BOOL AlreadyAdded = false;
    char name[wdirtypemax];
    SERVERHANDLE hdl = FindFirstServer(name, sizeof(name)-1);
    while (hdl) {
        if (_stricmp(name, ServerToSkip) != 0) {
            int proxynr = GetPrivateProfileInt(name, "proxynr", 1, gIniFileName);
            if (proxynr == proxynrtodelete) {
                CanDelete = false;
                if (AlreadyAdded)
                    strlcat(AppendToList, ", ", maxlen);
                strlcat(AppendToList, name, maxlen);
                AlreadyAdded = true;
            }
        }
        hdl = FindNextServer(hdl, name, sizeof(name)-1);
    }
    if (CanDelete) {
        char proxyentry[64];
#ifdef sprintf_s
        sprintf_s(proxyentry, sizeof(proxyentry), "proxy%d", proxynrtodelete);
#else
        sprintf(proxyentry, "proxy%d", proxynrtodelete);
#endif
        WritePrivateProfileString(proxyentry, NULL, NULL, gIniFileName);
    }
    return CanDelete;
}

// SR: 09.07.2005
myint __stdcall ConnectDlgProc(HWND hWnd, unsigned int Message, WPARAM wParam, LPARAM lParam)
{
    RECT rt1, rt2;
    int i, w, h, DlgWidth, DlgHeight, NewPosX, NewPosY, cp, cbline;
    char modbuf[32], strbuf[MAX_PATH];

    switch (Message) {
    case WM_INITDIALOG: {
        SendDlgItemMessage(hWnd, IDC_DEFAULTCOMBO, CB_SETCURSEL, 0, 0);
        serverfieldchangedbyuser = false;

        LoadStr(strbuf, IDS_AUTO);
        SendDlgItemMessage(hWnd, IDC_UTF8, CB_ADDSTRING, 0, (LPARAM)&strbuf);
        for (i = IDS_UTF8; i <= IDS_OTHER; i++) {
            LoadStr(strbuf, i);
            SendDlgItemMessage(hWnd, IDC_UTF8, CB_ADDSTRING, 0, (LPARAM)&strbuf);
        }

        LoadStr(strbuf, IDS_AUTO);
        SendDlgItemMessage(hWnd, IDC_SYSTEM, CB_ADDSTRING, 0, (LPARAM)&strbuf);
        strlcpy(strbuf, "Windows (CR/LF)", sizeof(strbuf)-1);
        SendDlgItemMessage(hWnd, IDC_SYSTEM, CB_ADDSTRING, 0, (LPARAM)&strbuf);
        strlcpy(strbuf, "Unix (LF)", sizeof(strbuf)-1);
        SendDlgItemMessage(hWnd, IDC_SYSTEM, CB_ADDSTRING, 0, (LPARAM)&strbuf);

        if (strcmp(gDisplayName, s_quickconnect) != 0) {
            SetDlgItemText(hWnd, IDC_CONNECTTO, gConnectResults->server);
            if (gConnectResults->server[0])
                serverfieldchangedbyuser = true;

            switch (gConnectResults->protocoltype) {
            case 1:  CheckRadioButton(hWnd, IDC_PROTOAUTO, IDC_PROTOV6, IDC_PROTOV4); break;
            case 2:  CheckRadioButton(hWnd, IDC_PROTOAUTO, IDC_PROTOV6, IDC_PROTOV6); break;
            default: CheckRadioButton(hWnd, IDC_PROTOAUTO, IDC_PROTOV6, IDC_PROTOAUTO); break;
            }

            SetDlgItemText(hWnd, IDC_USERNAME, gConnectResults->user);

            if (gConnectResults->useagent) {
                CheckDlgButton(hWnd, IDC_USEAGENT, BST_CHECKED);
                EnableControlsPageant(hWnd, false);
            }
            if (gConnectResults->detailedlog)
                CheckDlgButton(hWnd, IDC_DETAILED_LOG, BST_CHECKED);
            if (gConnectResults->compressed)
                CheckDlgButton(hWnd, IDC_COMPRESS, BST_CHECKED);
            if (gConnectResults->scpfordata)
                CheckDlgButton(hWnd, IDC_SCP_DATA, BST_CHECKED);
            if (gConnectResults->scponly)
                CheckDlgButton(hWnd, IDC_SCP_ALL,BST_CHECKED);
            if (gConnectResults->keepAliveIntervalSeconds > 0) {
                CheckDlgButton(hWnd, IDC_KEEP_ALIVE,BST_CHECKED);
                _itoa_s(gConnectResults->keepAliveIntervalSeconds, modbuf, sizeof(modbuf), 10);
                SetDlgItemText(hWnd, IDC_KEEP_ALIVE_SECONDS, modbuf);
            }
            else
                ::EnableWindow(GetDlgItem(hWnd, IDC_KEEP_ALIVE_SECONDS), FALSE);

            switch (gConnectResults->utf8names) {
            case -1: cbline = 0; break;  // auto-detect
            case  1: cbline = 1; break;
            default:
                cbline = 0;
                cp = gConnectResults->codepage;
                for (i = 0; i < countof(codepagelist); i++)
                    if (cp == codepagelist[i]) {
                        cbline = i;
                        break;
                    }
                if (cp > 0 && cbline == 0) {
                    _itoa_s(cp, strbuf, sizeof(strbuf), 10);
                    SendDlgItemMessage(hWnd, IDC_UTF8, CB_ADDSTRING, 0, (LPARAM)&strbuf);
                    cbline = countof(codepagelist) - 1;
                }
            }
            SendDlgItemMessage(hWnd, IDC_UTF8, CB_SETCURSEL, cbline, 0);

            SendDlgItemMessage(hWnd, IDC_SYSTEM, CB_SETCURSEL, max(0, min(2, gConnectResults->unixlinebreaks+1)), 0);

            if (strcmp(gConnectResults->password, "\001") == 0 && CryptProc) {
                if (CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_LOAD_PASSWORD_NO_UI, gDisplayName, gConnectResults->password, countof(gConnectResults->password)-1) == FS_FILE_OK) {
                    SetDlgItemText(hWnd, IDC_PASSWORD, gConnectResults->password);
                    CheckDlgButton(hWnd, IDC_CRYPTPASS, BST_CHECKED);
                } else {
                    ShowWindow(GetDlgItem(hWnd, IDC_PASSWORD), SW_HIDE);
                    ShowWindow(GetDlgItem(hWnd, IDC_CRYPTPASS), SW_HIDE);
                    ShowWindow(GetDlgItem(hWnd, IDC_EDITPASS), SW_SHOW);
                }
            } else {
                SetDlgItemText(hWnd, IDC_PASSWORD, gConnectResults->password);
                if (!CryptProc)
                    EnableWindow(GetDlgItem(hWnd, IDC_CRYPTPASS), false);
                else if (gConnectResults->password[0] == 0 && CryptCheckPass)
                    CheckDlgButton(hWnd, IDC_CRYPTPASS, BST_CHECKED);
            }

            SetDlgItemText(hWnd, IDC_PUBKEY, gConnectResults->pubkeyfile);
            SetDlgItemText(hWnd, IDC_PRIVKEY, gConnectResults->privkeyfile);

            _itoa_s(gConnectResults->filemod, modbuf, sizeof(modbuf), 8);
            SetDlgItemText(hWnd, IDC_FILEMOD, modbuf);
            _itoa_s(gConnectResults->dirmod, modbuf, sizeof(modbuf), 8);
            SetDlgItemText(hWnd, IDC_DIRMOD, modbuf);

            fillProxyCombobox(hWnd, gConnectResults->proxynr);
        } else {
            CheckRadioButton(hWnd, IDC_PROTOAUTO, IDC_PROTOV6, IDC_PROTOAUTO);
            SetDlgItemText(hWnd, IDC_FILEMOD, "644");
            SetDlgItemText(hWnd, IDC_DIRMOD, "755");
            SendDlgItemMessage(hWnd, IDC_UTF8, CB_SETCURSEL, 0, 0);
            SendDlgItemMessage(hWnd, IDC_SYSTEM, CB_SETCURSEL, 0, 0);
        }

        if (strcmp(gDisplayName, s_quickconnect) != 0) {
            if (gConnectResults->server[0] == 0)
                g_focusset=IDC_CONNECTTO;
            else if (gConnectResults->user[0] == 0)
                g_focusset=IDC_USERNAME;
            else
                g_focusset=IDC_PASSWORD;
        } else
            g_focusset=IDC_CONNECTTO;

        // trying to center the About dialog
        if (GetWindowRect(hWnd, &rt1) && GetWindowRect(GetParent(hWnd), &rt2)) {
            w = rt2.right  - rt2.left;
            h = rt2.bottom - rt2.top;
            DlgWidth   = rt1.right - rt1.left;
            DlgHeight  = rt1.bottom - rt1.top ;
            NewPosX    = rt2.left + (w - DlgWidth)/2;
            NewPosY    = rt2.top + (h - DlgHeight)/2;
            SetWindowPos(hWnd, 0, NewPosX, NewPosY, 0, 0, SWP_NOZORDER | SWP_NOSIZE);
        }

        // SR: 11.07.2005
        serverfieldchangedbyuser = false;

        return 1;
        break;
    }
    case WM_SHOWWINDOW: {
        if (g_focusset)
            SetFocus(GetDlgItem(hWnd, g_focusset));
        break;
    }
    case WM_COMMAND: {
        switch(LOWORD(wParam)) {
        case IDOK: {
            GetDlgItemText(hWnd, IDC_CONNECTTO, gConnectResults->server, sizeof(gConnectResults->server)-1);
            GetDlgItemText(hWnd, IDC_USERNAME, gConnectResults->user, sizeof(gConnectResults->user)-1);
            GetDlgItemText(hWnd, IDC_PASSWORD, gConnectResults->password, sizeof(gConnectResults->password)-1);
            if (IsDlgButtonChecked(hWnd, IDC_PROTOV4))
                gConnectResults->protocoltype = 1;
            else if (IsDlgButtonChecked(hWnd, IDC_PROTOV6))
                gConnectResults->protocoltype = 2;
            else
                gConnectResults->protocoltype = 0;

            GetDlgItemText(hWnd, IDC_PUBKEY, gConnectResults->pubkeyfile, sizeof(gConnectResults->pubkeyfile)-1);
            GetDlgItemText(hWnd, IDC_PRIVKEY, gConnectResults->privkeyfile, sizeof(gConnectResults->privkeyfile)-1);
            gConnectResults->useagent=IsDlgButtonChecked(hWnd, IDC_USEAGENT);

            gConnectResults->detailedlog = IsDlgButtonChecked(hWnd, IDC_DETAILED_LOG);
            gConnectResults->compressed = IsDlgButtonChecked(hWnd, IDC_COMPRESS);
            gConnectResults->scpfordata = IsDlgButtonChecked(hWnd, IDC_SCP_DATA);
            gConnectResults->scponly = IsDlgButtonChecked(hWnd, IDC_SCP_ALL);

            if (!IsDlgButtonChecked(hWnd, IDC_KEEP_ALIVE))
                gConnectResults->keepAliveIntervalSeconds = 0;
            else {
                GetDlgItemText(hWnd, IDC_KEEP_ALIVE_SECONDS, modbuf, sizeof(modbuf)-1);
                gConnectResults->keepAliveIntervalSeconds = atoi(modbuf);
            }

            cp = 0;
            cbline = (char)SendDlgItemMessage(hWnd, IDC_UTF8, CB_GETCURSEL, 0, 0);
            switch (cbline) {
            case 0: gConnectResults->utf8names = -1; break;  // auto-detect
            case 1: gConnectResults->utf8names = 1; break;
            default:
                gConnectResults->utf8names = 0;
                if (cbline >= 0 && cbline < countof(codepagelist)) {
                    cp = codepagelist[cbline];
                    if (cp == -3) {
                        if (RequestProc(PluginNumber, RT_Other, "Code page", "Code page (e.g. 28591):", strbuf, sizeof(strbuf)-1)) {
                            cp = atoi(strbuf);
                        }
                    } else if (cp == -4) {
                        cp = gConnectResults->codepage;  // unchanged!
                    }
                }
            }
            gConnectResults->codepage = cp;

            gConnectResults->unixlinebreaks = (char)SendDlgItemMessage(hWnd, IDC_SYSTEM, CB_GETCURSEL, 0, 0) - 1;

            GetDlgItemText(hWnd, IDC_FILEMOD, modbuf, sizeof(modbuf)-1);
            if (modbuf[0] == 0)
                gConnectResults->filemod = 0644;
            else
                gConnectResults->filemod = strtol(modbuf, NULL, 8);
            GetDlgItemText(hWnd, IDC_DIRMOD, modbuf, sizeof(modbuf)-1);
            if (modbuf[0] == 0)
                gConnectResults->dirmod = 0755;
            else
                gConnectResults->dirmod = strtol(modbuf, NULL, 8);

            gConnectResults->proxynr = (int)SendDlgItemMessage(hWnd, IDC_PROXYCOMBO, CB_GETCURSEL, 0, 0);
            int max = (int)SendDlgItemMessage(hWnd, IDC_PROXYCOMBO, CB_GETCOUNT, 0, 0) - 1;
            if (gConnectResults->proxynr >= max)  // "add" item!
                gConnectResults->proxynr = 0;

            if (strcmp(gDisplayName, s_quickconnect) != 0) {
                char buf[16];
                WritePrivateProfileString(gDisplayName, "server", gConnectResults->server, gIniFileName);
                WritePrivateProfileString(gDisplayName, "user", gConnectResults->user, gIniFileName);
                _itoa_s(gConnectResults->protocoltype, buf, sizeof(buf), 10);
                WritePrivateProfileString(gDisplayName, "protocol", gConnectResults->protocoltype == 0 ? NULL : buf, gIniFileName);
                WritePrivateProfileString(gDisplayName, "detailedlog", gConnectResults->detailedlog ? "1" : NULL, gIniFileName);
                WritePrivateProfileString(gDisplayName, "utf8", gConnectResults->utf8names == -1 ? NULL : gConnectResults->utf8names == 1 ? "1" : "0", gIniFileName);
                _itoa_s(gConnectResults->codepage, buf, sizeof(buf), 10);
                WritePrivateProfileString(gDisplayName, "codepage", buf, gIniFileName);
                WritePrivateProfileString(gDisplayName, "unixlinebreaks", gConnectResults->unixlinebreaks == -1 ? NULL : gConnectResults->unixlinebreaks == 1 ? "1" : "0", gIniFileName);
                WritePrivateProfileString(gDisplayName, "largefilesupport", gConnectResults->scpserver64bit == -1 ? NULL : gConnectResults->scpserver64bit == 1 ? "1" : "0", gIniFileName);
                WritePrivateProfileString(gDisplayName, "compression", gConnectResults->compressed ? "1" : NULL, gIniFileName);
                WritePrivateProfileString(gDisplayName, "scpfordata", gConnectResults->scpfordata ? "1" : NULL, gIniFileName);
                _itoa_s(gConnectResults->keepAliveIntervalSeconds, buf, sizeof(buf), 10);
                WritePrivateProfileString(gDisplayName, "keepaliveseconds", gConnectResults->keepAliveIntervalSeconds == 0 ? NULL : buf, gIniFileName);
                WritePrivateProfileString(gDisplayName, "scponly", gConnectResults->scponly ? "1" : NULL, gIniFileName);
                WritePrivateProfileString(gDisplayName, "pubkeyfile", gConnectResults->pubkeyfile[0] ? gConnectResults->pubkeyfile : NULL, gIniFileName);
                WritePrivateProfileString(gDisplayName, "privkeyfile", gConnectResults->privkeyfile[0] ? gConnectResults->privkeyfile : NULL, gIniFileName);
                WritePrivateProfileString(gDisplayName, "useagent", gConnectResults->useagent ? "1" : NULL, gIniFileName);

                _itoa_s(gConnectResults->filemod, modbuf, sizeof(modbuf), 8);
                WritePrivateProfileString(gDisplayName, "filemod", gConnectResults->filemod == 0644 ? NULL : modbuf, gIniFileName);
                _itoa_s(gConnectResults->dirmod, modbuf, sizeof(modbuf), 8);
                WritePrivateProfileString(gDisplayName, "dirmod", gConnectResults->dirmod == 0755 ? NULL : modbuf, gIniFileName);

                _itoa_s(gConnectResults->proxynr, buf, sizeof(buf), 10);
                WritePrivateProfileString(gDisplayName, TEXT("proxynr"), buf, gIniFileName);

                // SR: 09.07.2005
                if (!gConnectResults->dialogforconnection) {
                    TCHAR szEncryptedPassword[MAX_PATH];
                    {
                        if (!IsWindowVisible(GetDlgItem(hWnd, IDC_EDITPASS))) {
                            if (gConnectResults->password[0] == 0) {
                                WritePrivateProfileString(gDisplayName, "password", NULL, gIniFileName);
                            } else if (CryptProc && IsDlgButtonChecked(hWnd, IDC_CRYPTPASS)) {
                                BOOL ok = CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_SAVE_PASSWORD, gDisplayName, gConnectResults->password, 0) == FS_FILE_OK;
                                WritePrivateProfileString(gDisplayName, "password", ok? "!" : NULL, gIniFileName);
                                CryptCheckPass=true;
                            } else {
                                EncryptString(gConnectResults->password, szEncryptedPassword, countof(szEncryptedPassword));
                                WritePrivateProfileString(gDisplayName, "password", szEncryptedPassword, gIniFileName);
                            }
                        }
                    }
                }
            }
            gConnectResults->customport = 0;  // will be set later
            EndDialog(hWnd, IDOK);
            return 1;
        }
        case IDCANCEL:
        {
            // free serial number structures associated with each client certificate combo item
            int iCount = (int)SendDlgItemMessage(hWnd, IDC_CBO_CC, CB_GETCOUNT, (WPARAM)0, (LPARAM)0);

            EndDialog(hWnd, IDCANCEL);
            return 1;
        }
        case IDC_EDITPASS:
        {   
            BOOL doshow = true;
            int err;
            err = CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_LOAD_PASSWORD, gDisplayName, gConnectResults->password, countof(gConnectResults->password)-1);
            if (err == FS_FILE_OK) {
                SetDlgItemText(hWnd, IDC_PASSWORD, gConnectResults->password);
            } else if (err = FS_FILE_READERROR) {         // no password stored!
                SetDlgItemText(hWnd, IDC_PASSWORD, "");
            } else {
                doshow = false;
            }
            if (doshow) {
                ShowWindow(GetDlgItem(hWnd, IDC_PASSWORD), SW_SHOW);
                ShowWindow(GetDlgItem(hWnd, IDC_CRYPTPASS), SW_SHOW);
                ShowWindow(GetDlgItem(hWnd, IDC_EDITPASS), SW_HIDE);
                if (gConnectResults->password[0] != 0)
                    CheckDlgButton(hWnd, IDC_CRYPTPASS, BST_CHECKED);
            }
        }
        case IDC_CONNECTTO:
            if (HIWORD(wParam) == EN_CHANGE) {
                serverfieldchangedbyuser = true;
            }
            break;
        case IDC_CERTHELP:
        {
            TCHAR szCaption[100];
            LoadString(hinst,  IDS_HELP_CAPTION, szCaption, countof(szCaption));
            TCHAR szBuffer[1024];
            LoadString(hinst,  IDS_HELP_CERT, szBuffer, countof(szBuffer));
            MessageBox(hWnd, szBuffer, szCaption, MB_OK | MB_ICONINFORMATION);
            break;
        }
        case IDC_PASSWORDHELP:
        {
            TCHAR szCaption[100];
            LoadString(hinst, IDS_HELP_CAPTION, szCaption, countof(szCaption));
            TCHAR szBuffer[1024];
            LoadString(hinst, IDS_HELP_PASSWORD, szBuffer, countof(szBuffer));
            MessageBox(hWnd, szBuffer, szCaption, MB_OK | MB_ICONINFORMATION);
            break;
        }
        case IDC_UTF8HELP: 
        {
            TCHAR szCaption[100];
            LoadString(hinst, IDS_HELP_CAPTION, szCaption, countof(szCaption));
            TCHAR szBuffer[1024];
            LoadString(hinst, IDS_HELP_UTF8, szBuffer, countof(szBuffer));
            MessageBox(hWnd, szBuffer, szCaption, MB_OK | MB_ICONINFORMATION);
            break;
        }
        case IDC_LOADPUBKEY:
        case IDC_LOADPRIVKEY:
            {
            OPENFILENAME ofn ; // structure used by the common file dialog
            char szFileName[MAX_PATH];
            ZeroMemory(&ofn, sizeof(OPENFILENAME));
            ofn.lStructSize = sizeof(OPENFILENAME);
            ofn.hwndOwner = hWnd;
            ofn.nFilterIndex = 1;
            ofn.lpstrFile = szFileName ;
            ofn.nMaxFile = sizeof(szFileName);
            if (LOWORD(wParam) == IDC_LOADPUBKEY) {
                lstrcpy(szFileName, TEXT("*.pub"));
                ofn.lpstrFilter = TEXT("Public key files (*.pub)\0*.pub\0All Files\0*.*\0");
                ofn.lpstrTitle = TEXT("Select public key file");
            } else {
                lstrcpy(szFileName, TEXT("*.pem"));
                ofn.lpstrFilter = TEXT("Private key files (*.pem)\0*.pem\0All Files\0*.*\0");
                ofn.lpstrTitle = TEXT("Select private key file");
            }
            ofn.Flags = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY ;

            // GetOpenFileName will bring up the common file dialog in open mode
            if (GetOpenFileName(&ofn)) { // user specified a file
                SetDlgItemText(hWnd, LOWORD(wParam) == IDC_LOADPUBKEY ? IDC_PUBKEY : IDC_PRIVKEY, szFileName);
            }
            break;
            }
        case IDC_USEAGENT:
        {
            EnableControlsPageant(hWnd, !IsDlgButtonChecked(hWnd, IDC_USEAGENT));
            break;
        }
        case IDC_PROXYCOMBO:
            {
                int proxynr1 = (int)SendDlgItemMessage(hWnd, IDC_PROXYCOMBO, CB_GETCURSEL, 0, 0);
                if (HIWORD(wParam) == CBN_SELCHANGE)
                    if (proxynr1 == (int)SendDlgItemMessage(hWnd, IDC_PROXYCOMBO, CB_GETCOUNT, 0, 0) - 1)
                        PostMessage(hWnd, WM_COMMAND, IDC_PROXYBUTTON, 0);
            }
            break;
        case IDC_PROXYBUTTON:
        {
            int proxynr = (int)SendDlgItemMessage(hWnd, IDC_PROXYCOMBO, CB_GETCURSEL, 0, 0);
            if (proxynr > 0) {
                gProxyNr = proxynr;
                if (IDOK == DialogBox(hinst, MAKEINTRESOURCE(IDD_PROXY), GetActiveWindow(), ProxyDlgProc))
                    fillProxyCombobox(hWnd, proxynr);
            }
            break;
        }
        case IDC_KEEP_ALIVE:
            ::EnableWindow(GetDlgItem(hWnd,IDC_KEEP_ALIVE_SECONDS), IsDlgButtonChecked(hWnd, IDC_KEEP_ALIVE));
            if (IsDlgButtonChecked(hWnd, IDC_KEEP_ALIVE))
                ::SetFocus(GetDlgItem(hWnd, IDC_KEEP_ALIVE_SECONDS));
            break;
        case IDC_DELETELAST:
            int proxynr = (int)SendDlgItemMessage(hWnd, IDC_PROXYCOMBO, CB_GETCOUNT, 0, 0) - 2;
            if (proxynr >= 2) {    // proxy nr 1 cannot be deleted!
                TCHAR errorstr[1024];
                LoadString(hinst, IDS_ERROR_INUSE, errorstr, sizeof(errorstr));
                strlcat(errorstr, "\n", sizeof(errorstr)-1);
                if (DeleteLastProxy(proxynr, gConnectResults->DisplayName, errorstr, sizeof(errorstr)-1)) {
                    int proxynr = (int)SendDlgItemMessage(hWnd, IDC_PROXYCOMBO, CB_GETCURSEL, 0, 0);
                    fillProxyCombobox(hWnd, proxynr);
                } else {
                    MessageBox(hWnd, errorstr, "SFTP", MB_ICONSTOP);   
                }
            } else
                MessageBeep(MB_ICONSTOP);
            break;
        }
    }
    }
    return 0;
}

BOOL ShowConnectDialog(pConnectSettings ConnectSettings, char* DisplayName, char* inifilename)
{
    gConnectResults = ConnectSettings;
    gDisplayName = DisplayName;
    gIniFileName = inifilename;
    LoadServerSettings(DisplayName, ConnectSettings);

    if (ConnectSettings->dialogforconnection && ConnectSettings->server[0]) {
        if ((ConnectSettings->user[0] == 0 ||
             ConnectSettings->password[0]) &&        // password saved
            (ConnectSettings->proxyuser[0] == 0 ||   // no proxy auth required
             ConnectSettings->proxypassword[0]))     // or proxy pass saved
            return true;
        else {
            char title[256];
            // A proxy user name was given,  but no proxy password -> ask for proxy password
            if (ConnectSettings->proxyuser[0] != 0 &&       // no proxy auth required
                ConnectSettings->proxypassword[0] == 0) {
                LoadString(hinst, IDS_PROXY_PASS_TITLE, title, countof(title));
                strlcat(title, ConnectSettings->proxyuser, sizeof(title)-1);
                if (!RequestProc(PluginNumber, RT_PasswordFirewall, title, title, ConnectSettings->proxypassword, countof(ConnectSettings->proxypassword)-1))
                    return false;
            }
            return true;
        }
    } else
        return (IDOK == DialogBox(hinst, MAKEINTRESOURCE(IDD_WEBDAV), GetActiveWindow(), ConnectDlgProc));
}

#ifndef HWND_MESSAGE
#define HWND_MESSAGE ((HWND)(-3))
#endif

void* SftpConnectToServer(char* DisplayName, char* inifilename, char* overridepass)
{
    tConnectSettings ConnectSettings;
    memset(&ConnectSettings, 0, sizeof(tConnectSettings));
    ConnectSettings.dialogforconnection = true;
    
    // Get connection settings here
    if (ShowConnectDialog(&ConnectSettings, DisplayName, inifilename)) {
        if (overridepass)
            strlcpy(gConnectResults->password, overridepass, sizeof(gConnectResults->password)-1);
        if (CryptProc && strcmp(gConnectResults->password, "\001") == 0) {
            ConnectSettings.passSaveMode = 1;
            if (CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_LOAD_PASSWORD, gDisplayName, gConnectResults->password, countof(gConnectResults->password)-1)!=FS_FILE_OK) {
                MessageBox(GetActiveWindow(), "Failed to load password!", "Error", MB_ICONSTOP);
                return NULL;
            }
        } else if (ConnectSettings.useagent || gConnectResults->password[0] == 0)
            ConnectSettings.passSaveMode = 0;
        else
            ConnectSettings.passSaveMode = 2;
        if (CryptProc && strcmp(gConnectResults->proxypassword, "\001") == 0) {
            TCHAR proxyentry[64];
            if (gConnectResults->proxynr > 1)
#ifdef sprintf_s
                sprintf_s(proxyentry, sizeof(proxyentry), "proxy%d", gConnectResults->proxynr);
#else
                sprintf(proxyentry, "proxy%d", gConnectResults->proxynr);
#endif
            else
                strlcpy(proxyentry, "proxy", sizeof(proxyentry)-1);

            strlcat(proxyentry, "$$pass", sizeof(proxyentry)-1);
            if (CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_LOAD_PASSWORD, proxyentry, gConnectResults->proxypassword, countof(gConnectResults->proxypassword)-1) != FS_FILE_OK) {
                MessageBox(GetActiveWindow(), "Failed to load proxy password!", "Error", MB_ICONSTOP);
                return NULL;
            }
        }
        // Clear proxy user and pass if proxy type is set to 0!
        if (ConnectSettings.proxytype == 0) {
            ConnectSettings.proxyuser[0] = 0;
            ConnectSettings.proxypassword[0] = 0;
        }
        // split server name into server/path
        ReplaceBackslashBySlash(ConnectSettings.server);
        // Remove trailing sftp://
        if (_strnicmp(ConnectSettings.server, "sftp://", 7) == 0)
            memmove(ConnectSettings.server, ConnectSettings.server + 7, strlen(ConnectSettings.server) - 6);
        char* p = strchr(ConnectSettings.server, '/');
        ConnectSettings.lastactivepath[0] = 0;
        if (p) {
            awlcopy(ConnectSettings.lastactivepath, p, countof(ConnectSettings.lastactivepath)-1);
            p[0] = 0;
            // remove trailing backslash,  also in case of root!
        }
        // look for address and port
        p = strchr(ConnectSettings.server, ':');
        if (!ParseAddress(ConnectSettings.server, &ConnectSettings.server[0], &ConnectSettings.customport, 22)) {
            MessageBox(GetActiveWindow(), "Invalid server address.", "SFTP Error", MB_ICONSTOP);
            return NULL;
        }

        if (ProgressProc(PluginNumber, DisplayName, "temp", 0))
            return NULL;

        if (SftpConnect(&ConnectSettings) != SFTP_OK)
            return NULL;
        {
            // This will show ftp toolbar
            char connbuf[MAX_PATH];
            strlcpy(connbuf, "CONNECT \\", sizeof(connbuf)-1);
            strlcat(connbuf, DisplayName, sizeof(connbuf)-1);
            LogProc(PluginNumber, MSGTYPE_CONNECT, connbuf);

            pConnectSettings psettings = (pConnectSettings)malloc(sizeof(ConnectSettings));

            if (psettings)
                memcpy(psettings, &ConnectSettings, sizeof(ConnectSettings));

            if (psettings && psettings->keepAliveIntervalSeconds > 0) {
                if (!(psettings->scpfordata && SSH_ScpNeedBlockingMode) && SSH_ScpCanSendKeepAlive && psettings->hWndKeepAlive == NULL) {
                    // only needed in non-blocking mode
                    psettings->hWndKeepAlive = ::CreateWindow("Static", "SFTPPlug keep alive window", WS_CHILD, 0, 0, 0, 0, HWND_MESSAGE, NULL, NULL, NULL);

                    if (psettings->hWndKeepAlive != NULL) {
                        ghWndToConnectSettings[psettings->hWndKeepAlive] = psettings;
                        ::SetTimer(psettings->hWndKeepAlive, 1000, psettings->keepAliveIntervalSeconds * 1000, TimerProc);
                    }
                }
                else if (!SSH_ScpCanSendKeepAlive) {
                    strlcpy(connbuf, "KEEP-ALIVE not supported by libssh2. Version >= 1.2.5 required!", sizeof(connbuf)-1);
                    LogProc(PluginNumber, MSGTYPE_CONNECT, connbuf);
                }

                libssh2_keepalive_config(psettings->session, 0, psettings->keepAliveIntervalSeconds);
            }

            return psettings;
        }
    }
    return NULL;
}

BOOL SftpConfigureServer(char* DisplayName, char* inifilename)
{
    tConnectSettings ConnectSettings;

    memset(&ConnectSettings, 0, sizeof(tConnectSettings));
    ConnectSettings.dialogforconnection = false;
    return ShowConnectDialog(&ConnectSettings, DisplayName, inifilename);
}

int SftpCloseConnection(void* serverid)
{
    int rc;
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (ConnectSettings) {
        int starttime = (int)GetTickCount();
        BOOL doabort = false;
        if (ConnectSettings->sftpsession) {
            do {
                rc = libssh2_sftp_shutdown(ConnectSettings->sftpsession);
                if (EscapePressed())
                    doabort = true;
                if (doabort && (int)GetTickCount() - starttime > 2000)
                    break;
                if ((int)GetTickCount() - starttime > 5000)
                    break;
                if (rc == LIBSSH2_ERROR_EAGAIN)
                    IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
            } while (rc == LIBSSH2_ERROR_EAGAIN);
            ConnectSettings->sftpsession = NULL;
        }
        if (ConnectSettings->session) {
            do {
                rc = libssh2_session_disconnect(ConnectSettings->session, "Disconnect");
                if (EscapePressed())
                    doabort = true;
                if (doabort && (int)GetTickCount() - starttime > 2000)
                    break;
                if ((int)GetTickCount() - starttime > 5000)
                    break;
                if (rc == LIBSSH2_ERROR_EAGAIN)
                    IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
            } while (rc == LIBSSH2_ERROR_EAGAIN);
            libssh2_session_free(ConnectSettings->session);
            ConnectSettings->session = NULL;
        }
        if (ConnectSettings->sock != INVALID_SOCKET) {
            Sleep(1000);
            closesocket(ConnectSettings->sock); 
            ConnectSettings->sock = INVALID_SOCKET;
        }
        if (ConnectSettings->hWndKeepAlive != NULL) {
            ::DestroyWindow(ConnectSettings->hWndKeepAlive);
            ghWndToConnectSettings[ConnectSettings->hWndKeepAlive] = NULL;
            ConnectSettings->hWndKeepAlive = NULL;
        }
    }
    return SFTP_FAILED;
}

BOOL ReconnectSFTPChannelIfNeeded(pConnectSettings ConnectSettings)
{
    if (ConnectSettings->scponly)
        return true;   // not needed
    if (ConnectSettings->neednewchannel || ConnectSettings->sftpsession == NULL) {
        ConnectSettings->neednewchannel = false;
        DWORD starttime = (int)GetTickCount();
        int rc;
        int loop = 0;
        if (ConnectSettings->sftpsession) {
            do {
                rc=libssh2_sftp_shutdown(ConnectSettings->sftpsession);
            } while (rc == LIBSSH2_ERROR_EAGAIN && (int)GetTickCount() - (int)starttime < 2000);
        }

        if (ConnectSettings->session)
            do {
                ConnectSettings->sftpsession = NULL;
                if (ProgressLoop("Reconnect SFTP channel", 0, 100, &loop, &starttime))
                    break;
                ConnectSettings->sftpsession = libssh2_sftp_init(ConnectSettings->session);
                if ((!ConnectSettings->sftpsession) && (libssh2_session_last_errno(ConnectSettings->session) !=
                    LIBSSH2_ERROR_EAGAIN)) {
                    break;
                }
            } while (!ConnectSettings->sftpsession);

        // try to reconnect the entire connection!
        if (!ConnectSettings->sftpsession) {
            ShowStatus("Connection lost,  trying to reconnect!");
            SftpCloseConnection(ConnectSettings);
            Sleep(1000);
            SftpConnect(ConnectSettings);
        }
        ConnectSettings->neednewchannel = ConnectSettings->sftpsession == NULL;
    }
    return !ConnectSettings->neednewchannel;
}

int SftpFindFirstFileW(void* serverid, WCHAR* remotedir, void** davdataptr)
{
    LIBSSH2_SFTP_HANDLE *dirhandle;
    char dirname[wdirtypemax];
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    LoadStr(dirname, IDS_GET_DIR);
    walcopy(dirname + strlen(dirname), remotedir, (int)(sizeof(dirname) - strlen(dirname) - 1));
    ShowStatus(dirname);
    for (int i = 0; i < 10; i++)
        if (EscapePressed())
            Sleep(100);     // make sure it's not pressed from a previous aborted call!

    CopyStringW2A(ConnectSettings, remotedir, dirname, _countof(dirname));
    ReplaceBackslashBySlash(dirname);
    if (strlen(dirname) > 1) {
        char* p = dirname + strlen(dirname) - 1;
        if (p[0] != '/')            // ADD trailing slash!
            strlcat(dirname, "/", sizeof(dirname)-1);
    }

    if (ConnectSettings->scponly) {
        LIBSSH2_CHANNEL *channel;
        channel = ConnectChannel(ConnectSettings->session);
        if (!channel) {
            ShowStatus("no channel");
            return SFTP_FAILED;
        }
        char commandbuf[wdirtypemax+100];
        int trycustom = ConnectSettings->trycustomlistcommand;
        if (trycustom >= 1)
            strcpy(commandbuf, "export LC_ALL=C\n");
        else
            commandbuf[0] = 0;
        int lencmd0 = strlen(commandbuf);
        strlcat(commandbuf, "ls -la ", sizeof(commandbuf)-1);
        int lencmd1 = strlen(commandbuf);
        if (trycustom == 2)
            strlcat(commandbuf, "--time-style=\"+>>%Y%m%d_%H%M%S\" ", sizeof(commandbuf)-1);
        int lencmd2 = strlen(commandbuf);

        BOOL needquotes = strchr(dirname,' ')!=NULL || strchr(dirname,'(')!=NULL || strchr(dirname,')')!=NULL;
        if (needquotes)
            strlcat(commandbuf, "\"", sizeof(commandbuf)-3);
        strlcat(commandbuf, dirname, sizeof(commandbuf)-2);
        if (needquotes)
            strlcat(commandbuf, "\"", sizeof(commandbuf)-1);

        // 3 tries: 2. custom time style, 1. clear LANG, 0. plain ls -l
        char errorbuf[1024];
        errorbuf[0] = 0;
        int rcerr = 0;
        for (int i = trycustom; i >= 0; i--) {
            if (ConnectSettings->detailedlog)
                ShowStatus(commandbuf + ((i == 1) ? 0 : lencmd0));
            if (!SendChannelCommand(ConnectSettings->session, channel, commandbuf + ((i == 1) ? 0 : lencmd0))) {
                DisconnectShell(channel);
                ShowStatus("send command failed");
                return SFTP_FAILED;
            }
            // check whether the command was understood or not
            int rc = 0;
            rcerr = 0;
            do {
                errorbuf[0] = 0;
                rc = libssh2_channel_read(channel, errorbuf, 1);
                rcerr = libssh2_channel_read_stderr(channel, errorbuf, 1023);
                if (rcerr > 0) {
                    errorbuf[rcerr] = 0;
                    if (ConnectSettings->detailedlog)
                        ShowStatus(errorbuf);
                }
            } while ((rc == 0 || rc == LIBSSH2_ERROR_EAGAIN) && (rcerr == 0 || rcerr == LIBSSH2_ERROR_EAGAIN));
            if (rcerr > 0 && i > 0) {
                DisconnectShell(channel);
                channel=ConnectChannel(ConnectSettings->session);
                if (!channel) {
                    ShowStatus("no channel");
                    return SFTP_FAILED;
                }
                // remove time style parameter
                if (i == 2)
                    memmove(&commandbuf[lencmd1], &commandbuf[lencmd2], strlen(commandbuf + lencmd2) + 1);
            }
            if (rcerr == 0 || rcerr == LIBSSH2_ERROR_EAGAIN) {  // custom failed, normal OK -> no longer try custom
                ConnectSettings->trycustomlistcommand = i;
                break;
            }
        }

        SCP_DATA* scpd = (SCP_DATA*)malloc(sizeof(SCP_DATA));
        scpd->channel = channel;
        scpd->msgbuf[0] = 0;
        scpd->errbuf[0] = 0;

        *davdataptr = scpd;
        goto fin;
    }

    if (!ReconnectSFTPChannelIfNeeded(ConnectSettings))
        return SFTP_FAILED;
    
    /* Request a dir listing via SFTP */
    ConnectSettings->findstarttime = (int)GetTickCount();
    int aborttime = -1;
    int retrycount = 3;
    do {
        dirhandle = libssh2_sftp_opendir(ConnectSettings->sftpsession, dirname);

        int err = 0;
        if (!dirhandle) {
            err = libssh2_session_last_errno(ConnectSettings->session);
            if (err != LIBSSH2_ERROR_EAGAIN) {
                if (err == LIBSSH2_FX_EOF || err == LIBSSH2_FX_FAILURE || err == LIBSSH2_FX_BAD_MESSAGE ||
                    err == LIBSSH2_FX_NO_CONNECTION || err == LIBSSH2_FX_CONNECTION_LOST ||
                    err < 0)
                    retrycount--;
                else
                    retrycount = 0;
                if (retrycount <= 0)
                    break;
                ConnectSettings->neednewchannel = true;  // force reconnect
                if (!ReconnectSFTPChannelIfNeeded(ConnectSettings))
                    return SFTP_FAILED;
            } else
                IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
        }
        Sleep(50);
        int delta = (int)GetTickCount() - ConnectSettings->findstarttime;
        if (delta > 2000 && aborttime == -1) {
            if (ProgressProc(PluginNumber, dirname, "temp", (delta / 200) % 100))
                aborttime = GetTickCount() + 2000;  // give it 2 seconds to finish properly!
        }
        delta = (int)GetTickCount() - aborttime;
        if (aborttime != -1 && delta > 0) {
            ConnectSettings->neednewchannel = true;
            break;
        }
    } while (!dirhandle); 

    if (!dirhandle) {
        char* errmsg;
        int errmsg_len;
        LoadStr(dirname, IDS_ERR_GET_DIR);
        libssh2_session_last_error(ConnectSettings->session, &errmsg, &errmsg_len, false);
        strlcat(dirname, errmsg, sizeof(dirname)-1);
        ShowStatus(dirname);
        return SFTP_FAILED;
    } 
    *davdataptr = dirhandle;

fin:
    wcslcpy(ConnectSettings->lastactivepath, remotedir, countof(ConnectSettings->lastactivepath)-1);
    return SFTP_OK;
}

int SftpFindNextFileW(LPVOID serverid, LPVOID davdataptr, LPWIN32_FIND_DATAW FindData) noexcept
{
    char name[512]; 
    WCHAR namew[MAX_PATH];
    char completeline[2048];
    WCHAR completelinew[2048];
    int rc;
    LIBSSH2_SFTP_HANDLE *dirhandle;
    LIBSSH2_SFTP_ATTRIBUTES file;
    FILETIME datetime;
    DWORD attr = 0;
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    dirhandle = (LIBSSH2_SFTP_HANDLE*)davdataptr;
    if (!dirhandle)
        return SFTP_FAILED;

    completeline[0] = 0;
    name[0] = 0;
    namew[0] = 0;
    int aborttime = -1;

    if (ConnectSettings->scponly) {
        SCP_DATA* scpd = (SCP_DATA*)davdataptr;
        LIBSSH2_CHANNEL *channel = scpd->channel;
        if (!channel)
            return SFTP_FAILED;
        rc = 0;
        while (ReadChannelLine(channel, completeline, sizeof(completeline)-1, scpd->msgbuf, sizeof(scpd->msgbuf)-1, scpd->errbuf, sizeof(scpd->errbuf)-1)) {
            StripEscapeSequences(completeline);
            CopyStringA2W(ConnectSettings, completeline, completelinew, _countof(completelinew));

            if (ReadDirLineUNIX(completelinew, namew, countof(namew)-1, (__int64*)&file.filesize, &datetime, &attr, &file.permissions, 0)) {
                file.flags = LIBSSH2_SFTP_ATTR_SIZE | LIBSSH2_SFTP_ATTR_PERMISSIONS;
                rc = 1;
                break;
            }
        }
    } else {
        while ((rc = libssh2_sftp_readdir_ex(dirhandle, name, sizeof(name), completeline, sizeof(completeline), &file)) == LIBSSH2_ERROR_EAGAIN) {
            int delta = (int)GetTickCount() - ConnectSettings->findstarttime;
            if (delta > 2000 && aborttime == -1) {
                if (ProgressProc(PluginNumber, "dir", "temp", (delta / 200) % 100))
                    aborttime = GetTickCount() + 2000;  // give it 2 seconds to finish properly!
            }
            delta = (int)GetTickCount() - (int)aborttime;
            if (aborttime != -1 && delta > 0) {
                ConnectSettings->neednewchannel = true;
                break;
            }
            IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
        } 
    }
    if (rc > 0) {
        if (ConnectSettings->detailedlog)
            ShowStatus(completeline);

        FindData->dwFileAttributes = 0;
        if (namew[0]) {
            WCHAR* p = wcsstr(namew,L" -> ");
            if (p)
                p[0] = 0;
            wcslcpy2(FindData->cFileName, namew, countof(FindData->cFileName)-1);
        } else {
            CopyStringA2W(ConnectSettings, name, FindData->cFileName, _countof(FindData->cFileName));
        }
        if (file.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) {
            if ((file.permissions & S_IFMT) == S_IFDIR || (attr & FILE_ATTRIBUTE_DIRECTORY) != 0)
                FindData->dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
        } else if (completeline[0] == 'd')
            FindData->dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY;

        FindData->cAlternateFileName[0] = 0;
        FindData->ftCreationTime.dwHighDateTime = 0;
        FindData->ftCreationTime.dwLowDateTime = 0;
        FindData->ftLastAccessTime.dwHighDateTime = 0;
        FindData->ftLastAccessTime.dwLowDateTime = 0;
        
        if (file.flags & LIBSSH2_SFTP_ATTR_SIZE && FindData->dwFileAttributes == 0) {  
            FindData->nFileSizeHigh = (DWORD)(file.filesize >> 32);
            FindData->nFileSizeLow = (DWORD)file.filesize;
        } else {
            FindData->nFileSizeHigh = 0;
            FindData->nFileSizeLow = 0;
        }

        if (ConnectSettings->scponly) {
            FindData->ftLastWriteTime = datetime;
            if ((attr & FILE_ATTRIBUTE_DIRECTORY) != 0)
                FindData->dwFileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
        } else if (file.flags & LIBSSH2_SFTP_ATTR_ACMODTIME) {  
            __int64 tm = 0x019DB1DE;
            tm <<= 32;
            tm |= 0xD53E8000;
            tm += (__int64)10000000 * file.mtime;
            FindData->ftLastWriteTime.dwLowDateTime = (DWORD)tm;
            FindData->ftLastWriteTime.dwHighDateTime = (DWORD)(tm >> 32);
        }

        if (file.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) {
            FindData->dwFileAttributes |= 0x80000000;
            FindData->dwReserved0 = file.permissions & 0xFFFF; //attributes and format mask
        }
        return SFTP_OK;
    }
    return SFTP_FAILED;
}

int SftpFindClose(void* serverid, void* davdataptr)
{
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    LIBSSH2_SFTP_HANDLE *dirhandle;
    dirhandle = (LIBSSH2_SFTP_HANDLE*)davdataptr;
    if (!dirhandle)
        return SFTP_FAILED;
    int aborttime = -1;
    if (ConnectSettings->scponly) {
        SCP_DATA* scpd = (SCP_DATA*)davdataptr;
        LIBSSH2_CHANNEL *channel = scpd->channel;
        CloseRemote(serverid, NULL, channel, true, 100);
        return SFTP_OK;
    }
    while (LIBSSH2_ERROR_EAGAIN == libssh2_sftp_closedir(dirhandle)) {
        int delta = (int)GetTickCount() - ConnectSettings->findstarttime;
        if (delta > 2000 && aborttime == -1) {
            if (ProgressProc(PluginNumber, "close dir", "temp", (delta / 200) % 100))
                aborttime = GetTickCount() + 2000;  // give it 2 seconds to finish properly!
        }
        delta = (int)GetTickCount() - aborttime;
        if (aborttime != -1 && delta > 0) {
            ConnectSettings->neednewchannel = true;
            break;
        }
        IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
    }
    return SFTP_OK;
}

int SftpCreateDirectoryW(void* serverid, WCHAR* Path)
{
    char dirname[wdirtypemax];
    WCHAR dirnamedisp[wdirtypemax];
    int rc;
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (!ConnectSettings)
        return SFTP_FAILED;

    LoadStr(dirname, IDS_MK_DIR);
    awlcopy(dirnamedisp, dirname, wdirtypemax-1);
    wcslcat(dirnamedisp, Path, countof(dirnamedisp)-1);
    ShowStatusW(dirnamedisp);

    CopyStringW2A(ConnectSettings, Path, dirname, _countof(dirname));
    ReplaceBackslashBySlash(dirname);

    if (ConnectSettings->scponly) {
        char commandbuf[wdirtypemax+8];
        LIBSSH2_CHANNEL *channel;
        channel = ConnectChannel(ConnectSettings->session);
        strlcpy(commandbuf, "mkdir ", sizeof(commandbuf)-1);
        BOOL needquotes = strchr(dirname,' ')!=NULL || strchr(dirname,'(')!=NULL || strchr(dirname,')')!=NULL;
        if (needquotes)
            strlcat(commandbuf, "\"", sizeof(commandbuf)-3);
        strlcat(commandbuf, dirname, sizeof(commandbuf)-2);
        if (needquotes)
            strlcat(commandbuf, "\"", sizeof(commandbuf)-1);
        BOOL ok = GetChannelCommandReply(ConnectSettings->session, channel, commandbuf);
        DisconnectShell(channel);
        return ok ? SFTP_OK : SFTP_FAILED;
    }

    int starttime = (int)GetTickCount();
    int aborttime = -1;
    do {
        rc = libssh2_sftp_mkdir(ConnectSettings->sftpsession, dirname, ConnectSettings->dirmod);
        Sleep(50);
        int delta = (int)GetTickCount() - starttime;
        if (delta > 2000 && aborttime == -1) {
            if (EscapePressed())                // ProgressProc not working in this function!
                aborttime = GetTickCount() + 2000;  // give it 2 seconds to finish properly!
        }
        delta = (int)GetTickCount() - aborttime;
        if (aborttime != -1 && delta > 0) {
            ConnectSettings->neednewchannel = true;
            break;
        }
        if (rc == LIBSSH2_ERROR_EAGAIN)
            IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
    } while (rc == LIBSSH2_ERROR_EAGAIN);

    if (rc == 0) {
        // Set mod again,  because some servers don't seem to set it automatically
        if (ConnectSettings->dirmod != 0755) {
            LIBSSH2_SFTP_ATTRIBUTES attr;
            attr.flags = LIBSSH2_SFTP_ATTR_PERMISSIONS;
            attr.permissions = ConnectSettings->dirmod;
            do {
                rc = libssh2_sftp_setstat(ConnectSettings->sftpsession, dirname, &attr);
                if (EscapePressed()) {
                    ConnectSettings->neednewchannel = true;
                    break;
                }
                if (rc == LIBSSH2_ERROR_EAGAIN)
                    IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
            } while (rc == LIBSSH2_ERROR_EAGAIN);
        }
        return SFTP_OK;
    } else {
        char* errmsg;
        int errmsg_len;
        LoadStr(dirname, IDS_ERR_MK_DIR);
        libssh2_session_last_error(ConnectSettings->session, &errmsg, &errmsg_len, false);
        strlcat(dirname, errmsg, sizeof(dirname)-1);
        ShowStatus(dirname);
        return SFTP_FAILED;
    }
}

int SftpRenameMoveFileW(void* serverid, WCHAR* OldName, WCHAR* NewName, BOOL Move, BOOL Overwrite, BOOL isdir)
{
    int rc;
    char OldName2[wdirtypemax], NewName2[wdirtypemax], abuf[wdirtypemax];
    WCHAR buf[wdirtypemax], OldName2W[wdirtypemax], NewName2W[wdirtypemax];
    
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (!ConnectSettings)
        return SFTP_FAILED;

    CopyStringW2A(ConnectSettings, OldName, OldName2, _countof(OldName2));
    ReplaceBackslashBySlash(OldName2);
    CopyStringW2A(ConnectSettings, NewName, NewName2, _countof(NewName2));
    ReplaceBackslashBySlash(NewName2);

    if (!Overwrite) {
        if (ConnectSettings->scponly) {
            wcslcpy(NewName2W, NewName, countof(NewName2W)-1);
            ReplaceBackslashBySlashW(NewName2W);
            WCHAR cmdname[wdirtypemax + 8];
            wcslcpy(cmdname, L"stat ", countof(cmdname)-1);
            BOOL needquotes2 = wcschr(NewName2W,' ')!=NULL || wcschr(NewName2W,'(')!=NULL || wcschr(NewName2W,')')!=NULL;
            if (needquotes2)
                wcslcat(cmdname, L"\"", countof(cmdname)-1);
            wcslcat(cmdname, NewName2W, countof(cmdname)-1);
            if (needquotes2)
                wcslcat(cmdname, L"\"", countof(cmdname)-1);
            if (SftpQuoteCommand2W(serverid, NULL, cmdname, NULL, 0) == 0) {  // file found!
                int err = libssh2_session_last_errno(ConnectSettings->session);
                return SFTP_EXISTS;
            }
        } else {
            LIBSSH2_SFTP_ATTRIBUTES attr;
            do {
                rc = libssh2_sftp_lstat(ConnectSettings->sftpsession, NewName2, &attr);
                if (EscapePressed())
                    break;
                if (rc == LIBSSH2_ERROR_EAGAIN)
                    IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
            } while (rc == LIBSSH2_ERROR_EAGAIN);

            if (rc >= 0) {    // found!
                int err = libssh2_session_last_errno(ConnectSettings->session);
                return SFTP_EXISTS;
            } else if (rc == LIBSSH2_ERROR_EAGAIN) {
                ConnectSettings->neednewchannel = true;
                return SFTP_FAILED;
            }
        }
    }
    LoadStr(abuf, IDS_RENFR);
    awlcopy(buf, abuf, countof(buf)-1);
    wcslcat(buf, OldName, countof(buf)-1);
    ShowStatusW(buf);
    LoadStr(abuf, IDS_RENTO);
    awlcopy(buf, abuf, countof(buf)-1);
    wcslcat(buf, NewName, countof(buf)-1);
    ShowStatusW(buf);

    if (Move && !ConnectSettings->scponly) {
        do {
            rc = libssh2_sftp_rename(ConnectSettings->sftpsession, OldName2, NewName2);
            if (EscapePressed()) {
                ConnectSettings->neednewchannel = true;
                break;
            }
            if (rc == LIBSSH2_ERROR_EAGAIN)
                IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
        } while (rc == LIBSSH2_ERROR_EAGAIN);
    } else {
        WCHAR cmdname[2*wdirtypemax];
        // note: SftpQuoteCommand2 already converts from Ansi to UTF-8!!!
        wcslcpy(OldName2W, OldName, countof(OldName2W)-1);
        ReplaceBackslashBySlashW(OldName2W);
        wcslcpy(NewName2W, NewName, countof(NewName2W)-1);
        ReplaceBackslashBySlashW(NewName2W);

        wcslcpy(cmdname, Move ? L"mv " : L"cp ", countof(cmdname)-1);
        BOOL needquotes1 = wcschr(OldName2W, ' ')!=NULL || wcschr(OldName2W, '(')!=NULL || wcschr(OldName2W, ')')!=NULL;
        BOOL needquotes2 = wcschr(NewName2W, ' ')!=NULL || wcschr(NewName2W, '(')!=NULL || wcschr(NewName2W, ')')!=NULL;
        if (needquotes1)
            wcslcat(cmdname, L"\"", countof(cmdname)-1);
        wcslcat(cmdname, OldName2W, countof(cmdname)-1);
        if (needquotes1)
            wcslcat(cmdname, L"\"", countof(cmdname)-1);
        wcslcat(cmdname, L" ", countof(cmdname)-1);
        if (needquotes2)
            wcslcat(cmdname, L"\"", countof(cmdname)-1);
        wcslcat(cmdname, NewName2W, countof(cmdname)-1);
        if (needquotes2)
            wcslcat(cmdname, L"\"", countof(cmdname)-1);
        if (SftpQuoteCommand2W(serverid, NULL, cmdname, NULL, 0) == 0) {
            return SFTP_OK;
        } else
            return SFTP_FAILED;
    }

    if (rc == 0)
        return SFTP_OK;
    else {
        char* errmsg;
        int errmsg_len;
        LoadStr(abuf, IDS_ERR_RENAME);
        libssh2_session_last_error(ConnectSettings->session, &errmsg, &errmsg_len, false);
        strlcat(abuf, errmsg, sizeof(buf)-1);
        ShowStatus(abuf);
        return SFTP_FAILED;
    }
}

int GetPercent(__int64 offset, __int64 filesize)
{
    if (!filesize)
        return 0;
    int percent = (int)(offset * 100 / filesize);
    if (percent < 0) percent = 0;
    if (percent > 100) percent = 100;
    return percent;
}

int CheckInputOrTimeout(void* serverid, BOOL timeout, DWORD starttime, int percent)
{
    int retval = SFTP_OK;
    if (timeout) {
        if (GetTickCount() - starttime > 5000 && UpdatePercentBar(serverid, percent)) {
            retval = SFTP_ABORT;
        }
        if (GetTickCount() - starttime > 10000) {
            retval = SFTP_FAILED;
        }
    } else if (EscapePressed()) {
        retval = SFTP_ABORT;
    }
    return retval;
}

int CloseRemote(void* serverid, LIBSSH2_SFTP_HANDLE *remotefilesftp, LIBSSH2_CHANNEL *remotefilescp, BOOL timeout, int percent)
{
    int retval = SFTP_OK;
    DWORD starttime = GetTickCount();
    if (remotefilesftp) {
        while (LIBSSH2_ERROR_EAGAIN == libssh2_sftp_close(remotefilesftp)) {
            retval = CheckInputOrTimeout(serverid, timeout, starttime, percent);
            if (retval != SFTP_OK)
                break;
        }
        remotefilesftp = NULL;
    } else {
        while (LIBSSH2_ERROR_EAGAIN == libssh2_channel_send_eof(remotefilescp)) {
            retval = CheckInputOrTimeout(serverid, timeout, starttime, percent);
            if (retval != SFTP_OK)
                break;
        }
        while (LIBSSH2_ERROR_EAGAIN == libssh2_channel_free(remotefilescp)) {
            retval = CheckInputOrTimeout(serverid, timeout, starttime, percent);
            if (retval != SFTP_OK)
                break;
        }
        remotefilescp = NULL;
    }
    return retval;
}

#define RECV_BLOCK_SIZE 32768

int ConvertCrToCrLf(char* data, int len, BOOL* pLastWasCr)
{
    BOOL LastWasCr = *pLastWasCr;   // don't convert 0d0a->0d0d0a!
    char data2[RECV_BLOCK_SIZE];
    int j = 0;
    for (int i = 0; i < len; i++) {
        if (data[i] == 0x0d)
            LastWasCr = true;
        else if (data[i] == 0x0a && !LastWasCr) {
            data2[j] = 0x0d;
            j++;
            LastWasCr = false;
        } else
            LastWasCr = false;
        data2[j++] = data[i];
    }
    memcpy(data, &data2, j);
    *pLastWasCr = LastWasCr;  // remember across blocks!
    return j;
}

BOOL SftpDetermineTransferModeW(LPCWSTR RemoteName)  // true if text mode
{
    if (Global_TransferMode == 'A')
        return true;
    else if (Global_TransferMode == 'I')
        return false;
    else {  // mode 'auto'
        LPCWSTR p = wcsrchr(RemoteName, '/');
        if (!p)
            p = wcsrchr(RemoteName, '\\');
        if (!p)
            p = RemoteName;
        else
            p++;
        return MultiFileMatchW(Global_TextTypes, p);
    }
}

int SftpDownloadFileW(void* serverid, WCHAR* RemoteName, WCHAR* LocalName, BOOL alwaysoverwrite, __int64 filesize, FILETIME *ft, BOOL Resume)
{   
    LIBSSH2_SFTP_HANDLE *remotefilesftp = NULL;
    HANDLE localfile;
    char data[RECV_BLOCK_SIZE];
    char filename[wdirtypemax];
    __int64 sizeloaded = 0;
    __int64 resumepos = 0;
    LIBSSH2_CHANNEL *remotefilescp = NULL;
    libssh2_struct_stat fileinfoscp;
    __int64 scpremain = 0;

    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (!ConnectSettings)
        return SFTP_FAILED;

    BOOL LastWasCr = false;
    char abuf[MAX_PATH];
    WCHAR msgbuf[wdirtypemax];
    WCHAR *pend;
    
    BOOL scpdata = ConnectSettings->scpfordata;

    if (scpdata && Resume && !ConnectSettings->scponly)    // resume not possible with scp!
        scpdata = false;

    if (scpdata && filesize > (((__int64)1) << 31)) { // scp supports max 2 GB
        // libssh2 version >= 1.7.0 supports file size > 2 GB (for downloading)
        // But SCP on server side needs to be 64bit
        if (!SSH_ScpNo2GBLimit || (ConnectSettings->scpserver64bit != 1 && !ConnectSettings->scpserver64bittemporary)) {
            if (!SSH_ScpNo2GBLimit) {
                if (ConnectSettings->scponly) {
                    ShowErrorId(IDS_DLL_VERSION);
                    return SFTP_ABORT;
                } else
                    scpdata = false; // fallback to SFTP
            } else if (ConnectSettings->scponly) {
                char errorstr[256];
                LoadStr(errorstr, IDS_NO_2GB_SUPPORT);
                if (!RequestProc(PluginNumber, RT_MsgYesNo, "SFTP Error", errorstr, NULL, 0)) {
                    return SFTP_ABORT;
                } else
                    ConnectSettings->scpserver64bittemporary = true;
            } else {
                // we will try via SCP first, and if it fails, auto-resume via SFTP!
            }
        }
    }

    LoadStr(abuf, IDS_DOWNLOAD);
    awlcopy(msgbuf, abuf, wdirtypemax - 1);
    if (scpdata)
        wcslcat(msgbuf, L" (SCP)", wdirtypemax);

    pend = msgbuf + wcslen(msgbuf);
    wcslcat(msgbuf, RemoteName, countof(msgbuf)-1);
    ReplaceBackslashBySlashW(msgbuf);
    ShowStatusW(msgbuf);

    CopyStringW2A(ConnectSettings, RemoteName, filename, _countof(filename));
    ReplaceBackslashBySlash(filename);
    BOOL TextMode;
    TextMode = (ConnectSettings->unixlinebreaks == 1) && SftpDetermineTransferModeW(RemoteName);

    if (TextMode && Resume)
        return SFTP_FAILED;

    if (!ReconnectSFTPChannelIfNeeded(ConnectSettings))
        return SFTP_FAILED;

    if (scpdata) {
        char filename2[wdirtypemax];
        if (SSH_ScpNeedQuote && strchr(filename, ' ') != 0) {
            filename2[0] = '"';
            strlcpy(filename2 + 1, filename, sizeof(filename2)-3);
            strlcat(filename2, "\"", sizeof(filename2)-1);
        } else
            strlcpy(filename2, filename, sizeof(filename2)-1);
        do {
            remotefilescp = libssh2_scp_recv2(ConnectSettings->session, filename2, &fileinfoscp);
            if (EscapePressed()) {
                ConnectSettings->neednewchannel = true;
                break;
            }
        } while (remotefilescp == 0 && libssh2_session_last_errno(ConnectSettings->session) == LIBSSH2_ERROR_EAGAIN);
        if (!remotefilescp) {
            SftpLogLastError("SCP download error: ", libssh2_session_last_errno(ConnectSettings->session));

            // Note: It seems that scp sometimes fails to get file names with non-English characters!
            BOOL hasnonenglish=false;
            for (int i = 0; i < (int)wcslen(RemoteName); i++) {
                if (RemoteName[i] > 127) {
                    hasnonenglish = true;
                    break;
                }
            }
            if (hasnonenglish)
                scpdata = false;
            else
             return SFTP_READFAILED;
        }
        scpremain = fileinfoscp.st_size;
    }
    if (!scpdata) {
        do {
            remotefilesftp = libssh2_sftp_open(ConnectSettings->sftpsession, filename, LIBSSH2_FXF_READ, 0);
            if (EscapePressed()) {
                ConnectSettings->neednewchannel = true;
                break;
            }
            if (remotefilesftp == 0)
                IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
        } while (remotefilesftp == 0 && libssh2_session_last_errno(ConnectSettings->session) == LIBSSH2_ERROR_EAGAIN);
        if (!remotefilesftp)
            return SFTP_READFAILED;
    }
    
    if (Resume) {
        localfile = CreateFileT(LocalName, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, 
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (localfile != INVALID_HANDLE_VALUE) {
            DWORD szh;
            sizeloaded = GetFileSize(localfile, &szh);
            sizeloaded |= ((__int64)szh) << 32;
            SetFilePointer(localfile, 0, NULL, SEEK_END);

            if (filesize <= sizeloaded || sizeloaded >= ((__int64)1 << 31) - 1) {  // local file is larger!
                CloseHandle(localfile);
                if (SFTP_OK != CloseRemote(serverid, remotefilesftp, remotefilescp, false, 0)) {
                    ConnectSettings->neednewchannel = true;
                }
                return filesize == sizeloaded ? SFTP_OK : SFTP_WRITEFAILED;
            }
        }
        resumepos = sizeloaded;
    } else {
        localfile = CreateFileT(LocalName, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, 
            alwaysoverwrite ? CREATE_ALWAYS : CREATE_NEW, 
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    }
    if (localfile == INVALID_HANDLE_VALUE) {
        if (SFTP_OK != CloseRemote(serverid, remotefilesftp, remotefilescp, false, 0)) {
            ConnectSettings->neednewchannel = true;
        }
        int err = GetLastError();
        switch (err) {
        case ERROR_ACCESS_DENIED:return SFTP_EXISTS;
        case ERROR_SHARING_VIOLATION:return SFTP_EXISTS;
        default:return SFTP_WRITEFAILED;
        }
    }

    if (Resume && sizeloaded > 0) {   // seek!
        libssh2_sftp_seek(remotefilesftp, (int)sizeloaded);
        // Better check whether seek was successful!
        if (libssh2_sftp_tell(remotefilesftp) != (DWORD)sizeloaded) {
            if (SFTP_OK!=CloseRemote(serverid, remotefilesftp, remotefilescp, false, 0)) {
                ConnectSettings->neednewchannel = true;
            }
            CloseHandle(localfile);
            return SFTP_READFAILED;
        }
    }

    ProgressProcT(PluginNumber, pend, LocalName, 0);

    int len = 0;
    int maxblocksize = sizeof(data);
    if (TextMode)
        maxblocksize /= 2;  // in worst case,  we have all line breaks (0A)
    int retval = SFTP_OK;
    int aborttime = -1;
    do {
        if (scpdata) {
            if (scpremain <= 0)
                break;
            // Note: We must limit the receive buffer so we don't
            // read beyond the length of the file,  otherwise we will get 1 byte too much!
            len = libssh2_channel_read(remotefilescp, data, (size_t)min(scpremain, maxblocksize));
            if (len > 0)
                scpremain -= len;
        } else
            len = libssh2_sftp_read(remotefilesftp, data, maxblocksize);
        if (len > 0) {
            DWORD written;
            if (TextMode && sizeloaded == 0) {   // test first block if it's binary
                for (int i=0; i < len; i++)
                    if (data[i] == 0) {
                        TextMode = false;
                        break;
                    }
            }

            sizeloaded += len;    // the unconverted size!
            if (TextMode)
                len = ConvertCrToCrLf(data, len, &LastWasCr);
            if (!WriteFile(localfile, &data, len, &written, NULL) || (int)written != len){
                retval = SFTP_WRITEFAILED;
                break;
            }
        }
        // Always,  for aborting!
        if (UpdatePercentBar(serverid, GetPercent(sizeloaded, filesize))) {
            aborttime = (int)GetTickCount() + 2000;  // give it 2 seconds to finish properly!
            retval = SFTP_ABORT;
        }
        if (len == LIBSSH2_ERROR_EAGAIN) {
            IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
            len = 1;
        }
        else {
            if (len < 0)
                SftpLogLastError("Download read error: ", len);
            if (aborttime != -1)
                break;
        }
        // if there is no data until the abort time is reached,  abort anyway
        // this can corrupt the sftp channel,  so discard it on the next read
        int delta = (int)GetTickCount() - aborttime;
        if (aborttime != -1 && delta > 0) {
            ConnectSettings->neednewchannel = true;
            break;
        }
    } while (len > 0);

    int retval2 = CloseRemote(serverid, remotefilesftp, remotefilescp, true, GetPercent(sizeloaded, filesize));
    if (retval2 != SFTP_OK)
        ConnectSettings->neednewchannel = true;
    if (retval == SFTP_OK)
        retval = retval2;

    SetFileTime(localfile, NULL, NULL, ft);
    CloseHandle(localfile);

    if (len < 0)
        retval = SFTP_READFAILED;

    // Auto-resume if read failed in the middle, and we downloaded at least one byte since the last call
    if (retval != SFTP_ABORT && retval != SFTP_WRITEFAILED && sizeloaded < filesize && sizeloaded > resumepos && !ConnectSettings->scponly)
        retval = SFTP_PARTIAL;
    return retval;
}

#define SEND_BLOCK_SIZE 16384

int ConvertCrLfToCr(char* data, int len)  // simply remove all <CR> characters!
{
    char data2[SEND_BLOCK_SIZE];
    int j = 0;
    for (int i = 0; i < len; i++) {
        if (data[i] != 0x0d)
            data2[j++] = data[i];
    }
    memcpy(data, &data2, j);
    return j;
}

__int64 GetTextModeFileSize(HANDLE localfile, BOOL entirefile)
{
    char data[SEND_BLOCK_SIZE];
    __int64 filesize = 0;
    DWORD len;
    while (ReadFile(localfile, &data, sizeof(data), &len, NULL) && len>0) {
        DWORD numcrs = 0;
        for (DWORD i = 0; i < len; i++)
            if (data[i] == 0x0d)
                numcrs++;
            else if (data[i] == 0) {
                filesize = -1;       // binary -> do not convert!
                break;
            }
        if (filesize == -1 || !entirefile) // just check first block for 0 characters
            break;
        filesize += len - numcrs;
    }
    SetFilePointer(localfile, 0, NULL, FILE_BEGIN);
    return filesize;
}

DWORD GetTextUploadResumePos(HANDLE localfile, DWORD resumepos)
{
    char data[SEND_BLOCK_SIZE];
    DWORD localfilesize = 0;
    DWORD convertedfilesize = 0;
    DWORD len;
    while (ReadFile(localfile, &data, sizeof(data), &len, NULL) && len > 0) {
        DWORD numcrs = 0;
        for (DWORD i = 0; i < len; i++) {
            localfilesize++;
            if (data[i] != 0x0d)
                convertedfilesize++;
            if (convertedfilesize >= resumepos) {
                if (convertedfilesize > resumepos)
                    localfilesize = 0xFFFFFFFF;
                SetFilePointer(localfile, 0, NULL, FILE_BEGIN);
                return localfilesize;
            }
        }
    }
    SetFilePointer(localfile, 0, NULL, FILE_BEGIN);
    return 0xFFFFFFFF;
}

int SftpUploadFileW(void* serverid, LPCWSTR LocalName, WCHAR* RemoteName, BOOL Resume, BOOL setattr)
{
    LIBSSH2_SFTP_HANDLE *remotefilesftp = NULL;
    LIBSSH2_CHANNEL *remotefilescp = NULL;
    HANDLE localfile;
    char data[SEND_BLOCK_SIZE];   // 32k does NOT work!
    char thename[wdirtypemax];    // remote name in server encoding
    int rc;
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (!ConnectSettings)
        return SFTP_FAILED;

    CopyStringW2A(ConnectSettings, RemoteName, thename, _countof(thename));
    if (ConnectSettings->utf8names == 0) {
        if (strchr(thename, '?')) {
            return SFTP_WRITEFAILED;  // invalid remote name
        }
    }
    ReplaceBackslashBySlash(thename);

    BOOL TextMode;
    TextMode = (ConnectSettings->unixlinebreaks == 1) && SftpDetermineTransferModeW(LocalName);

    BOOL scpdata = ConnectSettings->scpfordata;

    if (scpdata && Resume)    // resume not possible with scp!
        scpdata = false;
    
    if (!ReconnectSFTPChannelIfNeeded(ConnectSettings))
        return SFTP_FAILED;

    int retval = SFTP_WRITEFAILED;

    char abuf[MAX_PATH];
    WCHAR msgbuf[wdirtypemax];
    LoadStr(abuf, IDS_UPLOAD);
    awlcopy(msgbuf, abuf, wdirtypemax-1);

    localfile = CreateFileT(LocalName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);

    if (localfile != INVALID_HANDLE_VALUE) {
        DWORD sizehigh;
        __int64 sizesent = 0;
        __int64 filesize = GetFileSize(localfile, &sizehigh);
        filesize |= (((__int64)sizehigh) << 32);
        __int64 sizeloaded = 0;

        if (scpdata && filesize > (((__int64)1) << 31)) {  // scp supports max 2 GB
            // libssh2 version >= 1.2.6 supports file size > 2 GB
            // But SCP on server side needs to be 64bit
            if (!SSH_ScpNo2GBLimit || (ConnectSettings->scpserver64bit != 1 && !ConnectSettings->scpserver64bittemporary)) {
                if (!SSH_ScpNo2GBLimit) {
                    if (ConnectSettings->scponly) {
                        ShowErrorId(IDS_DLL_VERSION);
                        CloseHandle(localfile);
                        return SFTP_ABORT;
                    } else
                        scpdata = false; // fallback to SFTP
                } else {
                    char errorstr[256];
                    LoadStr(errorstr, IDS_NO_2GB_SUPPORT);
                    if (!RequestProc(PluginNumber, RT_MsgYesNo, "SFTP Error", errorstr, NULL, 0)) {
                        if (ConnectSettings->scponly) {
                            CloseHandle(localfile);
                            return SFTP_ABORT;
                        } else
                            scpdata = false; // fallback to SFTP
                    } else
                        ConnectSettings->scpserver64bittemporary = true;
                }
            }
        }

        if (scpdata)
            wcslcat(msgbuf, L" (SCP)", wdirtypemax);
        wcslcat(msgbuf, RemoteName, countof(msgbuf)-1);
        ReplaceBackslashBySlashW(msgbuf);
        ShowStatusW(msgbuf);

        if (scpdata) {
            char thename2[wdirtypemax];
            if (SSH_ScpNeedQuote && strchr(thename, ' ') != 0) {
                thename2[0] = '"';
                strlcpy(thename2+1, thename, sizeof(thename2)-3);
                strlcat(thename2, "\"", sizeof(thename2)-1);
            } else
                strlcpy(thename2, thename, sizeof(thename2)-1);
            if (TextMode) {
                __int64 filesize2 = GetTextModeFileSize(localfile, true);
                if (filesize2 == -1)
                    TextMode = false;
                else
                    filesize = filesize2;
            }
            FILETIME ft;
            long mtime = 0;
            // the filemod is only set when also setting the timestamps.
            // we must not set it when overwriting, though!
            // when using SFTP commands, we can set the mode afterwards with the timestamp
            if (ConnectSettings->scponly && setattr) {
                if (GetFileTime(localfile, NULL, NULL, &ft)) {
                    __int64 tm2 = ft.dwHighDateTime;
                    tm2 <<= 32;
                    tm2 |= ft.dwLowDateTime;
                    __int64 tm = 0x019DB1DE;
                    tm <<= 32;
                    tm |= 0xD53E8000;
                    tm2 -= tm;
                    mtime = (DWORD)(tm2 / (__int64)10000000);
                }
            }

            do {
                if (!SSH_ScpNo2GBLimit)
                    remotefilescp = libssh2_scp_send_ex(ConnectSettings->session, thename2, ConnectSettings->filemod, (int)filesize, mtime, 0);
                else
                    remotefilescp = libssh2_scp_send64(ConnectSettings->session, thename2, ConnectSettings->filemod, (libssh2_uint64_t)filesize, mtime, 0);

                if (EscapePressed()) {
                    ConnectSettings->neednewchannel = true;
                    break;
                }
            } while (remotefilescp == 0 && libssh2_session_last_errno(ConnectSettings->session) == LIBSSH2_ERROR_EAGAIN);
            if (!remotefilescp) {
                SftpLogLastError("SCP upload error: ", libssh2_session_last_errno(ConnectSettings->session));
                CloseHandle(localfile);
                return SFTP_READFAILED;
            }
        } else {
            if (TextMode && -1 == GetTextModeFileSize(localfile, false))
                TextMode = false;
            do {
                remotefilesftp = libssh2_sftp_open(ConnectSettings->sftpsession, thename, Resume ? LIBSSH2_FXF_WRITE : LIBSSH2_FXF_WRITE|LIBSSH2_FXF_CREAT|LIBSSH2_FXF_TRUNC, 
                    0644);     // ConnectSettings->filemod is ignored!!!
                if (EscapePressed()) {
                    ConnectSettings->neednewchannel = true;
                    break;
                }
                if (remotefilesftp == 0)
                    IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
            } while (remotefilesftp == 0 && libssh2_session_last_errno(ConnectSettings->session) == LIBSSH2_ERROR_EAGAIN);
        }
        if (remotefilescp || remotefilesftp) {
            if (Resume) {   // seek!
                DWORD resumepos = 0;
                LIBSSH2_SFTP_ATTRIBUTES attr;
                memset(&attr, 0, sizeof(attr));
                attr.flags = LIBSSH2_SFTP_ATTR_PERMISSIONS;
                do {
                    rc = libssh2_sftp_fstat(remotefilesftp, &attr);
                    if (EscapePressed()) {
                        ConnectSettings->neednewchannel = true;
                        break;
                    }
                    if (rc == LIBSSH2_ERROR_EAGAIN)
                        IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
                } while (rc == LIBSSH2_ERROR_EAGAIN);
                if (rc == 0) {
                    resumepos = (DWORD)attr.filesize;
                    libssh2_sftp_seek(remotefilesftp, resumepos);
                    // Better check whether seek was successful!
                    if (libssh2_sftp_tell(remotefilesftp) != resumepos) {
                        if (SFTP_OK!=CloseRemote(serverid, remotefilesftp, remotefilescp, false, 0)) {
                            ConnectSettings->neednewchannel = true;
                        }           
                        CloseHandle(localfile);
                        return SFTP_WRITEFAILED;
                    }
                    if (Resume && TextMode) {
                        resumepos = GetTextUploadResumePos(localfile, resumepos);
                    }
                    if (resumepos == 0xFFFFFFFF || resumepos != SetFilePointer(localfile, resumepos, NULL, SEEK_SET)) {
                        if (SFTP_OK != CloseRemote(serverid, remotefilesftp, remotefilescp, false, 0)) {
                            ConnectSettings->neednewchannel = true;
                        }           
                        CloseHandle(localfile);
                        return SFTP_WRITEFAILED;
                    }
                    sizeloaded = resumepos;
                } else
                    Resume = false;
            }

            // Switch back to blocking mode,  because libssh2_channel_write is faulty in non-blocking mode!!!

            BOOL needblockingmode = scpdata && SSH_ScpNeedBlockingMode;

            if (needblockingmode) {
                SetBlockingSocket(ConnectSettings->sock, true);
                libssh2_channel_set_blocking(remotefilescp, 1);
                libssh2_session_set_blocking(ConnectSettings->session, 1);
            }

            DWORD starttime;
            DWORD len;
            retval = SFTP_OK;
            while (ReadFile(localfile, &data, sizeof(data), &len, NULL) && len > 0) {
                int dataread, written;
                dataread = len;
                char* pdata = data;
                if (TextMode)
                    len = ConvertCrLfToCr(data, len);
                do {
                    if (scpdata)
                        written = libssh2_channel_write(remotefilescp, pdata, len);
                    else
                        written = libssh2_sftp_write(remotefilesftp, pdata, len);
                    if (written >= 0) {
                        if (written > (int)len) {  // libssh2_channel_write sometiomes returns values > len!
                            retval = SFTP_WRITEFAILED;
                            // return to non-blocking mode
                            if (needblockingmode) {
                                SetBlockingSocket(ConnectSettings->sock, false);
                                libssh2_channel_set_blocking(remotefilescp, 0);
                                libssh2_session_set_blocking(ConnectSettings->session,  0);
                            }
                            written = -1;
                            break;
                        }
                        pdata += written;
                        len -= written;
                        if (len == 0)
                            sizeloaded += dataread;  // not the converted size!
                    } else if (written != LIBSSH2_ERROR_EAGAIN) { // error?
                        SftpLogLastError("Upload write error: ", libssh2_session_last_errno(ConnectSettings->session));
                        len = 0;
                    } else {
                        if (!IsSocketWritable(ConnectSettings->sock))  // sleep to avoid 100% CPU!
                            Sleep(10);
                    }

                    if (UpdatePercentBar(serverid, GetPercent(sizeloaded, filesize))) {
                        // graceful abort if last reply was EAGAIN
                        starttime = GetTickCount();
                        while (written == LIBSSH2_ERROR_EAGAIN) {
                            if (scpdata)
                                written = libssh2_channel_write(remotefilescp, pdata, len);
                            else
                                written = libssh2_sftp_write(remotefilesftp, pdata, len);
                            if (GetTickCount() - starttime > 5000)
                                break;
                            IsSocketWritable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
                        }
                        written = -1;
                        retval = SFTP_ABORT;
                        break;
                    }
                } while (written == LIBSSH2_ERROR_EAGAIN || len > 0);
                if(written < 0) {
                    if (retval != SFTP_ABORT)
                        retval = SFTP_WRITEFAILED;
                    break;
                }
            }
            int retval2 = CloseRemote(serverid, remotefilesftp, remotefilescp, true, GetPercent(sizeloaded, filesize));
            if (retval2 != SFTP_OK)
                ConnectSettings->neednewchannel = true;
            if (retval == SFTP_OK)
                retval = retval2;

            if (needblockingmode) {
                // return to non-blocking mode
                SetBlockingSocket(ConnectSettings->sock, false);
                libssh2_session_set_blocking(ConnectSettings->session, 0);
            }

            if (retval == SFTP_OK && !ConnectSettings->scponly) {
                LIBSSH2_SFTP_ATTRIBUTES attr;
                FILETIME ft;
                // set modification time ONLY if target didn't exist yet!!!
                memset(&attr, 0, sizeof(attr));
                attr.flags = LIBSSH2_SFTP_ATTR_ACMODTIME | (setattr ? LIBSSH2_SFTP_ATTR_PERMISSIONS : 0);
                if (GetFileTime(localfile, NULL, NULL, &ft)) {
                    __int64 tm2 = ft.dwHighDateTime;
                    tm2 <<= 32;
                    tm2 |= ft.dwLowDateTime;
                    __int64 tm = 0x019DB1DE;
                    tm <<= 32;
                    tm |= 0xD53E8000;
                    tm2 -= tm;
                    attr.mtime = (DWORD)(tm2 / (__int64)10000000);
                    attr.atime = attr.mtime;
                    if (setattr)
                        attr.permissions = ConnectSettings->filemod;
                }                       
                while (LIBSSH2_ERROR_EAGAIN == libssh2_sftp_setstat(ConnectSettings->sftpsession, thename, &attr)) {
                    if (EscapePressed()) {
                        ConnectSettings->neednewchannel = true;
                        break;
                    }
                    IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
                }
            } else if (retval == SFTP_OK) {
                FILETIME ft;
                if (GetFileTime(localfile, NULL, NULL, &ft)) {
                    if (SFTP_FAILED == SftpSetDateTimeW(ConnectSettings, RemoteName, &ft)) {
                        // handle error?
                    }
                }
            }
        } else
            retval = SFTP_WRITEFAILED;
        CloseHandle(localfile);
    } else {
        wcslcat(msgbuf, RemoteName, countof(msgbuf)-1);
        ReplaceBackslashBySlashW(msgbuf);
        ShowStatusW(msgbuf);
        LogProc(PluginNumber, MSGTYPE_IMPORTANTERROR, "Error opening local file!");
        retval = SFTP_READFAILED;
    }
    if (retval == SFTP_OK) {
        FILETIME ft;
        if (GetFileTime(localfile, NULL, NULL, &ft)) {
            if (SFTP_FAILED == SftpSetDateTimeW(ConnectSettings, RemoteName, &ft)) {
                // handle error?
            }
        }
    }
    return retval;
}

int SftpDeleteFileW(void* serverid, WCHAR* RemoteName, BOOL isdir)
{
    char dirname[wdirtypemax], abuf[wdirtypemax];
    WCHAR buf[wdirtypemax];
    int rc;
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (!ConnectSettings)
        return SFTP_FAILED;

    CopyStringW2A(ConnectSettings, RemoteName, dirname, _countof(dirname));
    ReplaceBackslashBySlash(dirname);

    if (strcmp(dirname, "/~") == 0)    // go to home dir special link
        return SFTP_FAILED;

    LoadStr(abuf, IDS_DELETE);
    awlcopy(buf, abuf, countof(buf)-1);
    wcslcat(buf, RemoteName, sizeof(buf)-1);
    ShowStatusW(buf);

    if (ConnectSettings->scponly) {
        char commandbuf[wdirtypemax + 8];
        LIBSSH2_CHANNEL *channel;
        channel = ConnectChannel(ConnectSettings->session);
        if (isdir)
            strlcpy(commandbuf, "rmdir ", sizeof(commandbuf)-1);
        else
            strlcpy(commandbuf, "rm ", sizeof(commandbuf)-1);
        BOOL needquotes = strchr(dirname,' ')!=NULL || strchr(dirname,'(')!=NULL || strchr(dirname,')')!=NULL;
        if (needquotes)
            strlcat(commandbuf, "\"", sizeof(commandbuf)-3);
        strlcat(commandbuf, dirname, sizeof(commandbuf)-2);
        if (needquotes)
            strlcat(commandbuf, "\"", sizeof(commandbuf)-1);
        BOOL ok = GetChannelCommandReply(ConnectSettings->session, channel, commandbuf);
        DisconnectShell(channel);
        return ok ? SFTP_OK : SFTP_FAILED;
    }

    int starttime = (int)GetTickCount();
    int aborttime = -1;
    do {
        if (isdir)
            rc = libssh2_sftp_rmdir(ConnectSettings->sftpsession, dirname);
        else
            rc = libssh2_sftp_unlink(ConnectSettings->sftpsession, dirname);

        int delta = (int)GetTickCount() - starttime;
        if (delta > 2000 && aborttime == -1) {
            if (ProgressProcT(PluginNumber, buf, L"delete", (delta / 200) % 100))
                aborttime = GetTickCount() + 2000;  // give it 2 seconds to finish properly!
        }
        delta = (int)GetTickCount() - aborttime;
        if (aborttime != -1 && delta > 0) {
            ConnectSettings->neednewchannel = true;
            break;
        }
        if (rc == LIBSSH2_ERROR_EAGAIN)
            IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
    } while (rc == LIBSSH2_ERROR_EAGAIN);
    if (rc == 0)
        return SFTP_OK;
    else {
        char* errmsg;
        int errmsg_len;
        LoadStr(abuf, IDS_ERR_DELETE);
        libssh2_session_last_error(ConnectSettings->session, &errmsg, &errmsg_len, false);
        awlcopy(buf, abuf, countof(buf)-1);
        awlcopy(buf + wcslen(buf), errmsg, countof(buf) - wcslen(buf) - 1);
        wcslcat(buf, L" ", countof(buf)-1);
        wcslcat(buf, RemoteName, countof(buf)-1);
        ShowStatusW(buf);
        return SFTP_FAILED;
    }
}

int SftpSetAttr(void* serverid, char* RemoteName, int NewAttr)
{
    return SFTP_FAILED;
}

int SftpSetDateTimeW(void* serverid, WCHAR* RemoteName, FILETIME *LastWriteTime)
{
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (!ConnectSettings)
        return SFTP_FAILED;

    int rc = 0;
    WCHAR msgbuf[wdirtypemax];
    char filename[wdirtypemax];

    CopyStringW2A(ConnectSettings, RemoteName, filename, _countof(filename));
    ReplaceBackslashBySlash(filename);

    wcslcpy(msgbuf,L"Set date/time for: ",countof(msgbuf)-1);
    wcslcat(msgbuf,RemoteName,countof(msgbuf)-1);
    ReplaceBackslashBySlashW(msgbuf);
    ShowStatusW(msgbuf);


    // touch -t 201501311530.21 test.py
    if (ConnectSettings->scponly) {
        SYSTEMTIME tdt = {0};
        FILETIME lft;
        char commandbuf[wdirtypemax + 32];
        LIBSSH2_CHANNEL *channel;
        channel = ConnectChannel(ConnectSettings->session);
        FileTimeToLocalFileTime(LastWriteTime, &lft);
        FileTimeToSystemTime(&lft, &tdt);
#ifdef sprintf_s
        sprintf_s(commandbuf, sizeof(commandbuf), "touch -t %04d%02d%02d%02d%02d.%02d ", tdt.wYear, tdt.wMonth, tdt.wDay, tdt.wHour, tdt.wMinute, tdt.wSecond);
#else
        sprintf(commandbuf, "touch -t %04d%02d%02d%02d%02d.%02d ", tdt.wYear, tdt.wMonth, tdt.wDay, tdt.wHour, tdt.wMinute, tdt.wSecond);
#endif
        BOOL needquotes = strchr(filename,' ')!=NULL || strchr(filename,'(')!=NULL || strchr(filename,')')!=NULL;
        if (needquotes)
            strlcat(commandbuf, "\"", sizeof(commandbuf)-3);
        strlcat(commandbuf, filename, sizeof(commandbuf)-2);
        if (needquotes)
            strlcat(commandbuf, "\"", sizeof(commandbuf)-1);
        BOOL ok = GetChannelCommandReply(ConnectSettings->session, channel, commandbuf);
        DisconnectShell(channel);
        return ok ? SFTP_OK : SFTP_FAILED;
    }

    LIBSSH2_SFTP_ATTRIBUTES attr;
    attr.flags = LIBSSH2_SFTP_ATTR_ACMODTIME;
    __int64 tm2 = LastWriteTime->dwHighDateTime;
    tm2 <<= 32;
    tm2 |= LastWriteTime->dwLowDateTime;
    __int64 tm = 0x019DB1DE;
    tm <<= 32;
    tm |= 0xD53E8000;
    tm2 -= tm;
    attr.mtime = (DWORD)(tm2 / (__int64)10000000);
    attr.atime = attr.mtime;
    do {
        rc = libssh2_sftp_setstat(ConnectSettings->sftpsession, filename, &attr);
        if (EscapePressed()) {
            ConnectSettings->neednewchannel = true;
            break;
        }
        if (rc == LIBSSH2_ERROR_EAGAIN)
            IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
    } while (rc == LIBSSH2_ERROR_EAGAIN);
    if (rc) 
        return SFTP_FAILED;
    else
        return SFTP_OK;
}

BOOL SftpChmodW(void* serverid, WCHAR* RemoteName, LPCWSTR chmod)
{
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (!ConnectSettings)
        return SFTP_FAILED;

    int rc = 0;
    WCHAR msgbuf[wdirtypemax];
    char filename[wdirtypemax];
    CopyStringW2A(ConnectSettings, RemoteName, filename, _countof(filename));
    ReplaceBackslashBySlash(filename);

    wcslcpy(msgbuf, L"Set attributes for: ", countof(msgbuf)-1);
    wcslcat(msgbuf, RemoteName, countof(msgbuf)-1);
    ReplaceBackslashBySlashW(msgbuf);
    ShowStatusW(msgbuf);

    LIBSSH2_SFTP_ATTRIBUTES attr;
    attr.flags = LIBSSH2_SFTP_ATTR_PERMISSIONS;
    attr.permissions = (chmod[0]-'0')*8*8 + (chmod[1]-'0')*8 + (chmod[2]-'0');
    // 4 digits? -> use command line because libssh2_sftp_setstat fails to set extended attributes!
    // also when not using SFTP subsystem
    if (ConnectSettings->scponly || (chmod[3] >= '0' && chmod[3] <= '9')) {
        char reply[wdirtypemax];
        wcslcpy(msgbuf, L"chmod ", countof(msgbuf)-1);
        wcslcat(msgbuf, chmod, countof(msgbuf));
        wcslcat(msgbuf, L" ", countof(msgbuf));
        BOOL needquotes = wcschr(RemoteName, ' ')!=NULL || wcschr(RemoteName, '(')!=NULL || wcschr(RemoteName, ')')!=NULL;
        if (needquotes)
            wcslcat(msgbuf, L"\"", countof(msgbuf)-1);
        wcslcat(msgbuf, RemoteName, countof(msgbuf)-2);
        ReplaceBackslashBySlashW(msgbuf);
        if (needquotes)
            wcslcat(msgbuf, L"\"", countof(msgbuf)-1);
        reply[0] = 0;
        return SftpQuoteCommand2W(serverid, NULL, msgbuf, reply, sizeof(reply)-1) >= 0;
    }
    do {
        rc = libssh2_sftp_setstat(ConnectSettings->sftpsession, filename, &attr);
        if (EscapePressed()) {
            ConnectSettings->neednewchannel = true;
            break;
        }
        if (rc == LIBSSH2_ERROR_EAGAIN)
            IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
    } while (rc == LIBSSH2_ERROR_EAGAIN);
    if (rc) 
        return false;
    else
        return true;
}

BOOL SftpLinkFolderTargetW(void* serverid, WCHAR* RemoteName, int maxlen)
{
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (!ConnectSettings)
        return false;

    int rc = 0;
    WCHAR msgbuf[wdirtypemax];
    char filename[wdirtypemax];
    CopyStringW2A(ConnectSettings, RemoteName, filename, _countof(filename));
    ReplaceBackslashBySlash(filename);
    BOOL needquotes = strchr(filename,' ')!=NULL || strchr(filename,'(')!=NULL || strchr(filename,')')!=NULL;

    wcslcpy(msgbuf, L"Follow link: ", sizeof(msgbuf)-1);
    wcslcat(msgbuf, RemoteName, sizeof(msgbuf)-1);
    ReplaceBackslashBySlashW(msgbuf);
    ShowStatusW(msgbuf);

    if (strcmp(filename, "/~") == 0 || strcmp(filename, "/home/~") == 0) {   // go to home dir special link
        char ReturnedName[wdirtypemax];
        WCHAR cmdname[MAX_PATH];
        wcslcpy(cmdname, L"echo $HOME", countof(cmdname)-1);
        ReturnedName[0] = 0;
        if (SftpQuoteCommand2W(ConnectSettings, NULL, cmdname, ReturnedName, wdirtypemax-1) == 0 && ReturnedName[0] == '/') {
            char* p = strchr(ReturnedName, '\r');
            if (p)
                p[0] = 0;
            p = strchr(ReturnedName, '\n');
            if (p)
                p[0] = 0;
            ReplaceSlashByBackslash(ReturnedName);
        } else {        
            strlcpy(ReturnedName, "\\home\\", min(maxlen, wdirtypemax));
            strlcat(ReturnedName, ConnectSettings->user, min(maxlen, wdirtypemax));
        }
        CopyStringA2W(ConnectSettings, ReturnedName, RemoteName, maxlen);
        return true;
    } else {
        char linktarget[wdirtypemax];
        linktarget[0] = 0;
        if (!ConnectSettings->scponly) {
            // first check whether the link really points to a directory:
            LIBSSH2_SFTP_ATTRIBUTES attr;
            rc = -1;
            do {
                // stat requests the info of the link target
                attr.flags = LIBSSH2_SFTP_ATTR_PERMISSIONS;
                rc = libssh2_sftp_stat(ConnectSettings->sftpsession, filename, &attr);
                if (EscapePressed()) {
                    ConnectSettings->neednewchannel = true;
                    break;
                }
                if (rc == LIBSSH2_ERROR_EAGAIN)
                    IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
            } while (rc == LIBSSH2_ERROR_EAGAIN);
            if (rc != 0 || (attr.permissions & S_IFMT) != S_IFDIR)   // not found
                return false;

            do {
                rc = libssh2_sftp_readlink(ConnectSettings->sftpsession, filename, linktarget, sizeof(linktarget)-2);
                if (EscapePressed()) {
                    ConnectSettings->neednewchannel = true;
                    break;
                }
                if (rc == LIBSSH2_ERROR_EAGAIN)
                    IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
            } while (rc == LIBSSH2_ERROR_EAGAIN);
            if (rc <= 0)  // it returns the length of the link target!
                return false;
            else
                linktarget[rc] = 0;
        } else {    // follow link without SFTP functions
            char ReturnedName[2048];
            WCHAR cmdname[MAX_PATH];
            wcslcpy(cmdname, L"export LC_ALL=C\nstat -L ", countof(cmdname)-1);
            if (needquotes)
                wcslcat(cmdname, L"\"", countof(cmdname)-1);
            wcslcat(cmdname, RemoteName, countof(cmdname)-1);
            if (needquotes)
                wcslcat(cmdname, L"\"", countof(cmdname)-1);
            ReplaceBackslashBySlashW(cmdname);
            ReturnedName[0] = 0;
            BOOL isadir = false;
            if (SftpQuoteCommand2W(ConnectSettings, NULL, cmdname, ReturnedName, 2048 - 1)==0) {
                _strlwr(ReturnedName);
                char* p = strstr(ReturnedName, "size:");
                if (p) {
                    char* p2 = strchr(p,'\r');
                    if (!p2)
                        p2 = strchr(p, '\n');
                    if (p2) {
                        p2 -= 9;
                        if (p2 > p && strncmp(p2, "directory", 9) == 0) {
                            ShowStatusW(L"Link type: directory");
                            isadir = true;
                        }
                    }
                }
            }
            if (!isadir)
                return false;

            wcslcpy(cmdname, L"export LC_ALL=C\nreadlink -f ", countof(cmdname)-1);
            if (needquotes)
                wcslcat(cmdname, L"\"",countof(cmdname)-1);
            wcslcat(cmdname, RemoteName, countof(cmdname)-1);
            if (needquotes)
                wcslcat(cmdname, L"\"", countof(cmdname)-1);
            ReplaceBackslashBySlashW(cmdname);
            linktarget[0] = 0;
            if (!SftpQuoteCommand2W(ConnectSettings, NULL, cmdname, linktarget, sizeof(linktarget)-1) == 0)
                return false;
        }
        if (linktarget[0]) {
            WCHAR linktargetW[wdirtypemax];
            CopyStringA2W(ConnectSettings, linktarget, linktargetW, _countof(linktargetW));
            ShowStatusW(L"Link target:");
            ShowStatusW(linktargetW);
            // handle the case of relative links!
            if (linktargetW[0] != '/') {
                ReplaceSlashByBackslashW(RemoteName);
                WCHAR* p = wcsrchr(RemoteName, '\\');
                if (p)     // cut off the name of the link itself!
                    p[0] = 0;
                wcslcat(RemoteName, L"\\", maxlen);
                wcslcat(RemoteName, linktargetW, maxlen);
            } else
                wcslcpy(RemoteName, linktargetW, maxlen);
            return true;
        }
    }
    return false;
}

BOOL isnumeric(char ch)
{
    return (ch >= '0' && ch <= '9');
}

void StripEscapeSequences(char *msgbuf)
{
    char* pin = msgbuf;
    char* pout = msgbuf;
    while (pin[0]) {
        if (pin[0] == 0x1B) {   // escape!
            // search for 0 or 'm'
            pin++;
            while (pin[0] && pin[0] != 'm')
                pin++;
            if (pin[0] == 0)
                break;
            pin++;
        } else if (pin[0] == '\\' && isnumeric(pin[1]) && isnumeric(pin[2]) && isnumeric(pin[3])) {
            // special characters are encoded in octal: \123
            char nrbuf[4];
            strlcpy(nrbuf, pin + 1, 3);
            pout++[0] = (char)strtol(nrbuf, NULL, 8);
            pin += 4;
        } else
            pout++[0] = pin++[0];
    }
    pout[0] = 0;
}

void DisconnectShell(LIBSSH2_CHANNEL *channel)
{
    while (libssh2_channel_free(channel) == LIBSSH2_ERROR_EAGAIN) {
        if (EscapePressed())
            break;
    }
}

LIBSSH2_CHANNEL* ConnectChannel(LIBSSH2_SESSION *session)
{
    LIBSSH2_CHANNEL *channel;
    if (!session)
        return NULL;
    int starttime = (int)GetTickCount();

    do {
        channel = libssh2_channel_open_session(session);
        if (abs((int)GetTickCount() - starttime) > 1000 && EscapePressed())
            break;
    } while (!channel && libssh2_session_last_errno(session) == LIBSSH2_ERROR_EAGAIN);

    if (!channel) {
        char errmsg[128];
        char numbuf[16];
        strlcpy(errmsg, "Unable to open a session", sizeof(errmsg)-1);
        int err = libssh2_session_last_errno(session);
        switch (err) {
            case LIBSSH2_ERROR_ALLOC:
                strlcat(errmsg, ": internal memory allocation call failed", sizeof(errmsg)-1);
                break;
            case LIBSSH2_ERROR_SOCKET_SEND:
                strlcat(errmsg, ": Unable to send data on socket", sizeof(errmsg)-1);
                break;
            case LIBSSH2_ERROR_CHANNEL_FAILURE:
                strlcat(errmsg, ": Channel failure", sizeof(errmsg)-1);
                break;
            default:
                _itoa(err,numbuf,10);
                strlcat(errmsg, ": Error code ", sizeof(errmsg)-1);
                strlcat(errmsg, numbuf, sizeof(errmsg)-1);
                break;
        }
        ShowStatus(errmsg);
        return NULL;
    }
    libssh2_channel_set_blocking(channel, 0);
    return channel;
}

BOOL SendChannelCommandNoEof(LIBSSH2_SESSION *session, LIBSSH2_CHANNEL *channel, char* command)
{
    int rc = -1;
    do {
        rc = libssh2_channel_exec(channel,  command);
        if (rc < 0) {
            if (rc == -1)
                rc = libssh2_session_last_errno(session);
            if (rc != LIBSSH2_ERROR_EAGAIN)
                break;
        }
        if (EscapePressed())
            break;
    } while (rc < 0);
    while (libssh2_channel_flush(channel) == LIBSSH2_ERROR_EAGAIN) {
        if (EscapePressed())
            break;
    }
    return rc >= 0;
}

BOOL SendChannelCommand(LIBSSH2_SESSION *session, LIBSSH2_CHANNEL *channel, char* command)
{
    BOOL ret = SendChannelCommandNoEof(session, channel, command);
    while (libssh2_channel_send_eof(channel) == LIBSSH2_ERROR_EAGAIN) {
        if (EscapePressed())
            break;
    }
    return ret;
}

BOOL GetChannelCommandReply(LIBSSH2_SESSION *session, LIBSSH2_CHANNEL *channel, char* command)
{
    BOOL hasstderr = false;
    if (!SendChannelCommand(session, channel, command))
        return false;
    while (!libssh2_channel_eof(channel)) {
        char buf[1024];
        if (0 < libssh2_channel_read_stderr(channel, buf, sizeof(buf)-1))
            hasstderr = true;

        libssh2_channel_read(channel, buf, sizeof(buf)-1);
        if (EscapePressed())
            break;
    }
    return 0 == libssh2_channel_get_exit_status(channel) && !hasstderr;
}

BOOL onlylinebreaks(char* msgbuf)
{
    BOOL onlylinebreaks2 = true;
    while (msgbuf[0]) {
        if (msgbuf[0] != '\r' && msgbuf[0] != '\n') {
            onlylinebreaks2 = false;
            break;
        }
        msgbuf++;
    }
    return onlylinebreaks2;
}

BOOL ReadChannelLine(LIBSSH2_CHANNEL *channel, char *line, int linelen, char* msgbuf, int msgbuflen, char* errbuf, int errbuflen)
{
    int rc, rcerr;
    DWORD startdatatime = GetTickCount();
    DWORD lastdatatime = startdatatime;
    BOOL endreceived = false;
    BOOL detectingcrlf = true;
    do {
        // we need to read from both,  otherwise eof will not become true!
        int prevlen = (int)strlen(msgbuf);
        int remain = msgbuflen - prevlen;
        int remainerr = errbuflen - (int)strlen(errbuf);
        char* perr = errbuf + strlen(errbuf);   // errbuf contains previously received error data
        char* p = msgbuf + strlen(msgbuf);   // msgbuf contains previously received data!!!
        if (libssh2_channel_eof(channel)) {   // end signal AND no more data!
            endreceived = true;
        }
        rcerr = libssh2_channel_read_stderr(channel, perr, remainerr);
        rc = libssh2_channel_read(channel, p, remain);
        if (EscapePressed())
            break;
        if (rcerr > 0) {
            perr[rcerr] = 0;
            perr += rcerr;
            remainerr -= rcerr;
        }
        if (rc >= 0 || prevlen > 0) {
            lastdatatime = GetTickCount();
            if (rc >= 0)
                p[rc] = 0;
            char* p1;
            p1 = strchr(msgbuf, '\n');
            if (p1) {
                int l;
                p1[0] = 0;
                p1++;
                l = (int)strlen(msgbuf);
                if (l && msgbuf[l-1] == '\r') {
                    if (detectingcrlf && global_detectcrlf==-1)
                        global_detectcrlf = 1;
                    msgbuf[l-1] = 0;
                } else if (detectingcrlf && global_detectcrlf==-1)
                    global_detectcrlf = 0;
                strlcpy(line, msgbuf, linelen);
                StripEscapeSequences(line);
                char* p0 = msgbuf;
                memmove(p0, p1, strlen(p1) + 1);
                return true;
            } else
                p1 = NULL;
        } else if (rc == LIBSSH2_ERROR_EAGAIN) {
            Sleep(50);
            DWORD thisdatatime = GetTickCount();
            if (thisdatatime - lastdatatime < 1000 ||
                thisdatatime - startdatatime < 5000)
                rc = 1;
        }
        if (endreceived && rc <= 0 && rc != LIBSSH2_ERROR_EAGAIN) {
            if (msgbuf[0] && !onlylinebreaks(msgbuf)) {
                if (detectingcrlf) {   // only append it once - do not use this appended to detect!
                    detectingcrlf = false;
                    strlcat(msgbuf, "\r\n", sizeof(msgbuf)-1);
                }
            } else {
                return false;
            }
        }
    } while (true);
    return false;
}

void SftpSetTransferModeW(LPCWSTR mode)
{
    Global_TransferMode = (size_t)CharUpperW((LPWSTR)mode[0]) & 0xFF;
    if (Global_TransferMode == 'X')
        wcslcpy(Global_TextTypes, mode + 1, countof(Global_TextTypes)-1);
}

// returns -1 for error,  >=0 is the return value of the called function
int SftpQuoteCommand2(void* serverid, char* remotedir, char* cmd, char* reply, int replylen)
{
    LIBSSH2_CHANNEL *channel = NULL;

    if (reply && replylen)
        reply[0] = 0;

    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (!ConnectSettings)
        return -1;

    int rc = 0;
    char msgbuf[1024];
    char line[1024];
    char dirname[wdirtypemax], cmdname[wdirtypemax];
    dirname[0] = 0;
    if (ConnectSettings->utf8names) {
        if (remotedir)
            strlcpyansitoutf8(dirname, remotedir, sizeof(dirname)-1);
        strlcpyansitoutf8(cmdname, cmd, sizeof(cmdname)-1);
    } else {
        if (remotedir)
            strlcpy(dirname, remotedir, sizeof(dirname)-1);
        strlcpy(cmdname, cmd, sizeof(cmdname)-1);
    }
    ReplaceBackslashBySlash(dirname);

    strlcpy(msgbuf, "Quote: ", sizeof(msgbuf)-1);
    strlcat(msgbuf, cmd, sizeof(msgbuf)-1);
    ReplaceBackslashBySlash(msgbuf);
    ShowStatus(msgbuf);

    channel = ConnectChannel(ConnectSettings->session);
    if (!channel)
        return -1;

    // first set the current directory!
    if (remotedir) {
        strlcpy(msgbuf, "cd ", sizeof(msgbuf));
        BOOL needquotes = strchr(dirname, ' ')!=NULL || strchr(dirname, '(')!=NULL || strchr(dirname, ')')!=NULL;
        if (needquotes)
            strlcat(msgbuf, "\"", sizeof(msgbuf)-1);
        strlcat(msgbuf, dirname, sizeof(msgbuf)-2);
        if (needquotes)
            strlcat(msgbuf, "\"", sizeof(msgbuf)-1);
        strlcat(msgbuf, " && ", sizeof(msgbuf)-2);
    } else
        msgbuf[0] = 0;
    // then send the actual command!
    strlcat(msgbuf, cmdname, sizeof(msgbuf)-2);

    if (!SendChannelCommand(ConnectSettings->session, channel, msgbuf)) {
        DisconnectShell(channel);
        return -1;
    }

    char errbuf[2048];
    msgbuf[0] = 0;
    errbuf[0] = 0;
    while (ReadChannelLine(channel, line, sizeof(line)-1, msgbuf, sizeof(msgbuf)-1, errbuf, sizeof(errbuf)-1)) {
        StripEscapeSequences(line);
        if (!reply) {
            ShowStatus(line);
        } else {
            if (reply[0])
                strlcat(reply, "\r\n", replylen-1);
            strlcat(reply, line, replylen-1);
        }
    }

    rc = libssh2_channel_get_exit_status(channel);
    if (rc != 0) {   // read stderr
#ifdef sprintf_s
        sprintf_s(msgbuf, sizeof(msgbuf), "Function return code: %d", rc);
#else
        sprintf(msgbuf, "Function return code: %d", rc);
#endif
        ShowStatus(msgbuf);
        if (errbuf[0]) {
            StripEscapeSequences(errbuf);
            char* p = errbuf;
            if (strncmp(p, "stdin: is not a tty", 19) == 0) {
                p += 19;
                while (p[0] == '\r' || p[0] == '\n')
                    p++;
            }
            ShowStatus(p);
            if (reply) {
                if (reply[0])
                    strlcat(reply, "\r\n", replylen);
                strlcat(reply, p, replylen);
            }
        }
    }

    while (libssh2_channel_free(channel) == LIBSSH2_ERROR_EAGAIN) {
        if (EscapePressed())
            break;
        IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
    }
    if (rc < 0)
        rc = 1;
    return rc;
}

// returns -1 for error, >=0 is the return value of the called function
int SftpQuoteCommand2W(void* serverid, WCHAR* remotedir, LPCWSTR cmd, char* reply, int replylen)
{
    LIBSSH2_CHANNEL *channel = NULL;

    if (reply && replylen)
        reply[0] = 0;

    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (!ConnectSettings)
        return -1;

    int rc = 0;
    char msgbuf[2*wdirtypemax];
    WCHAR msgbufW[wdirtypemax];
    char line[2*wdirtypemax];
    WCHAR wline[2*wdirtypemax];
    char dirname[wdirtypemax], cmdname[wdirtypemax];
    dirname[0] = 0;
    if (ConnectSettings->utf8names) {
        if (remotedir)
            wcslcpytoutf8(dirname, remotedir, sizeof(dirname)-1);
        wcslcpytoutf8(cmdname, cmd, sizeof(cmdname)-1);
    } else {
        if (remotedir)
            walcopyCP(ConnectSettings->codepage, dirname, remotedir, sizeof(dirname)-1);
        walcopyCP(ConnectSettings->codepage, cmdname, cmd, sizeof(cmdname)-1);
    }
    ReplaceBackslashBySlash(dirname);

    wcslcpy(msgbufW, L"Quote: ", countof(msgbufW)-1);
    wcslcat(msgbufW, cmd, countof(msgbufW)-1);
    ReplaceBackslashBySlashW(msgbufW);
    ShowStatusW(msgbufW);

    channel = ConnectChannel(ConnectSettings->session);
    if (!channel)
        return -1;

    // first set the current directory!
    if (remotedir) {
        strlcpy(msgbuf, "cd ", sizeof(msgbuf)-1);
        BOOL needquotes = strchr(dirname, ' ')!=NULL || strchr(dirname, '(')!=NULL || strchr(dirname, ')')!=NULL;
        if (needquotes)
            strlcat(msgbuf, "\"", sizeof(msgbuf)-1);
        strlcat(msgbuf, dirname, sizeof(msgbuf)-3);
        if (needquotes)
            strlcat(msgbuf, "\"", sizeof(msgbuf)-1);
        strlcat(msgbuf, " && ", sizeof(msgbuf)-3);
    } else
        msgbuf[0] = 0;
    // then send the actual command!
    strlcat(msgbuf, cmdname, sizeof(msgbuf)-3);

    if (!SendChannelCommand(ConnectSettings->session, channel, msgbuf)) {
        DisconnectShell(channel);
        return -1;
    }

    char errbuf[2048];
    msgbuf[0] = 0;
    errbuf[0] = 0;
    DWORD starttime = GetCurrentTime();
    DWORD lasttime = starttime;
    int loop = 0;
    while (ReadChannelLine(channel, line, sizeof(line)-1, msgbuf, sizeof(msgbuf)-1, errbuf, sizeof(errbuf)-1)) {
        StripEscapeSequences(line);
        if (!reply) {
            CopyStringA2W(ConnectSettings, line, wline, countof(wline), false);
            ShowStatusW(wline);
        } else {
            if (reply[0])
                strlcat(reply, "\r\n", replylen);
            strlcat(reply, line, replylen);
        }
        if (GetCurrentTime() - starttime > 2000)
            if (ProgressLoop("QUOTE", 0, 100, &loop, &lasttime))
                break;
    }

    rc = libssh2_channel_get_exit_status(channel);
    if (rc != 0) {   // read stderr
#ifdef sprintf_s
        sprintf_s(msgbuf, sizeof(msgbuf), "Function return code: %d", rc);
#else
        sprintf(msgbuf, "Function return code: %d", rc);
#endif
        ShowStatus(msgbuf);
        if (errbuf[0]) {
            StripEscapeSequences(errbuf);
            char* p = errbuf;
            if (strncmp(p, "stdin: is not a tty", 19) == 0) {
                p += 19;
                while (p[0] == '\r' || p[0] == '\n')
                    p++;
            }
            CopyStringA2W(ConnectSettings, p, wline, countof(wline), false);
            ShowStatusW(wline);
            if (reply) {
                if (reply[0])
                    strlcat(reply, "\r\n", replylen);
                strlcat(reply, p, replylen);
            }
        }
    }

    while (libssh2_channel_free(channel) == LIBSSH2_ERROR_EAGAIN) {
        if (EscapePressed())
            break;
        IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
    }
    if (rc < 0)
        rc = 1;
    return rc;
}

BOOL SftpQuoteCommand(void* serverid, char* remotedir, char* cmd)
{
    return (SftpQuoteCommand2(serverid, remotedir, cmd, NULL, 0) >= 0);
}

char* FindStatString(char* searchin, char* searchfor, char* deletedchar)
{
    char* p, *p2;
    deletedchar[0] = 0;
    p = strstr(searchin, searchfor);
    if (p) {
        p += strlen(searchfor);
        while (p[0] == ' ') p++;
        if (p[0] == '(') {
            p++;
            p2 = p + 1;
            while (strchr(")\r\n", p2[0]) == NULL && p2[0] != 0)
                p2++;
        } else if (p[0] == '\'' || p[0] == '`'  || p[0] == '"') {   // Link: `file' -> `target'
            p2 = p + 1;
            while (strchr("\"'`\r\n", p2[0]) == NULL && p2[0] != 0)
                p2++;
            p2++;
            if (strncmp(p2, " -> ", 4) == 0) {
                p2 += 5;
                while (strchr("\"'`\r\n", p2[0]) == NULL && p2[0] != 0)
                    p2++;
                p2++;
            }
        } else {
            p2 = p + 1;
            while (strchr(" \r\n", p2[0]) == NULL && p2[0] != 0)
                p2++;
        }
        deletedchar[0] = p2[0];
        p2[0] = 0;
    }
    return p;
}

WCHAR* FindStatStringW(WCHAR* searchin, WCHAR* searchfor, WCHAR* deletedchar)
{
    WCHAR* p, *p2;
    deletedchar[0] = 0;
    p = wcsstr(searchin, searchfor);
    if (p) {
        p += wcslen(searchfor);
        while (p[0] == ' ') p++;
        if (p[0] == '(') {
            p++;
            p2 = p + 1;
            while (wcschr(L")\r\n", p2[0]) == NULL && p2[0] != 0)
                p2++;
        } else if (p[0] == '\'' || p[0] == '`'  || p[0] == '"') {   // Link: `file' -> `target'
            p2 = p + 1;
            while (wcschr(L"\"'`\r\n", p2[0]) == NULL && p2[0] != 0)
                p2++;
            p2++;
            if (wcsncmp(p2, L" -> ", 4) == 0) {
                p2 += 5;
                while (wcschr(L"\"'`\r\n", p2[0]) == NULL && p2[0] != 0)
                    p2++;
                p2++;
            }
        } else {
            p2 = p + 1;
            while (wcschr(L" \r\n", p2[0]) == NULL && p2[0] != 0)
                p2++;
        }
        deletedchar[0] = p2[0];
        p2[0] = 0;
    }
    return p;
}

WCHAR* g_statreplyW;
WCHAR* g_filenameW;
char* g_statreplyA;
BOOL g_command_ls;

myint __stdcall PropDlgProc(HWND hWnd, unsigned int Message, WPARAM wParam, LPARAM lParam)
{
    RECT rt1, rt2;
    int w, h, DlgWidth, DlgHeight, NewPosX, NewPosY;
    char *p, *p2;

    switch (Message) {
    case WM_INITDIALOG: {
        char ch;
        WCHAR chw, *wp;
        HDC dc = GetDC(hWnd);
        HFONT fixedfont = CreateFont(-MulDiv(8,  GetDeviceCaps(dc,  LOGPIXELSY), 72), 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, FIXED_PITCH | FF_DONTCARE, "Courier New");
        ReleaseDC(hWnd, dc);
        if (fixedfont)
            SendDlgItemMessage(hWnd, IDC_PROP_RAWSTAT, WM_SETFONT, (WPARAM)fixedfont, true);

        if (usys())
            SetDlgItemTextW(hWnd, IDC_PROP_RAWSTAT, g_statreplyW);
        else
            SetDlgItemText(hWnd, IDC_PROP_RAWSTAT, g_statreplyA);

        if (!g_command_ls) {
            if (usys()) {
                WCHAR *wp;
                wp = FindStatStringW(g_statreplyW, L"File:", &chw);
                if (wp) {
                    SetDlgItemTextW(hWnd, IDC_PROP_NAME, wp);
                    wp[wcslen(wp)] = chw;
                }
            } else {
                p = FindStatString(g_statreplyA, "File:", &ch);
                if (p) {
                    SetDlgItemText(hWnd, IDC_PROP_NAME, p);
                    p[strlen(p)] = ch;
                }
            }
            p = FindStatString(g_statreplyA, "Size:", &ch);
            if (p) {
                SetDlgItemText(hWnd, IDC_PROP_SIZE, p);
                p[strlen(p)] = ch;
            }
            p = FindStatString(g_statreplyA, "Access:", &ch);
            if (p) {
                SetDlgItemText(hWnd, IDC_PROP_PERMISSIONS, p);
                p[strlen(p)] = ch;
            }
            p = FindStatString(g_statreplyA, "Uid:", &ch);
            if (p) {
                SetDlgItemText(hWnd, IDC_PROP_OWNER, p);
                p[strlen(p)] = ch;
            }
            p = FindStatString(g_statreplyA, "Gid:", &ch);
            if (p) {
                SetDlgItemText(hWnd, IDC_PROP_GROUP, p);
                p[strlen(p)] = ch;
            }
            p = FindStatString(g_statreplyA, "Modify:", &ch);
            if (p) {
                int timezone = 0;
                int tzhours, tzminutes;
                SYSTEMTIME tdt = {0};
                FILETIME ft, lft;
                p[strlen(p)] = ch;
                char* p2 = strchr(p, '\n');  // contains spaces!!!
                if (p2)
                    p2[0] = 0;
                // is it in ISO format? -> If yes,  calculate local time!
                // 2008-08-17 12:51:55.000000000 -0400
                if (strlen(p) > 20 && p[4] == '-' && p[7] == '-' && p[10] == ' ' && p[13] == ':' && p[16] == ':' && p[19] == '.') {
                    p[4] = ' ';
                    p[7] = ' ';
                    p[10] = ' ';
                    p[13] = ' ';
                    p[16] = ' ';
                    p[19] = ' ';
                    sscanf(p, "%hd %hd %hd %hd %hd %hd %hd %d", &tdt.wYear, &tdt.wMonth, &tdt.wDay, &tdt.wHour, &tdt.wMinute, &tdt.wSecond, &tdt.wMilliseconds, &timezone);
                    SystemTimeToFileTime(&tdt, &ft);
                    tzhours = abs(timezone) / 100;
                    tzminutes = abs(timezone) - 100*tzhours;
                    __int64 tm = ft.dwHighDateTime;
                    tm <<= 32;
                    tm += ft.dwLowDateTime;
                    if (timezone > 0)   // it's reversed!
                        tm -= (__int64)10000000 * 60 * (tzminutes + 60*tzhours);
                    else
                        tm += (__int64)10000000 * 60 * (tzminutes + 60*tzhours);
                    ft.dwHighDateTime = (DWORD)(tm >> 32);
                    ft.dwLowDateTime = (DWORD)(tm);
                    FileTimeToLocalFileTime(&ft, &lft);
                    FileTimeToSystemTime(&lft, &tdt);
                    char buf[128];
#ifdef sprintf_s
                    sprintf_s(buf, sizeof(buf), "%d-%02d-%02d %02d:%02d:%02d (local)", tdt.wYear, tdt.wMonth, tdt.wDay, tdt.wHour, tdt.wMinute, tdt.wSecond);
#else
                    sprintf(buf, "%d-%02d-%02d %02d:%02d:%02d (local)", tdt.wYear, tdt.wMonth, tdt.wDay, tdt.wHour, tdt.wMinute, tdt.wSecond);
#endif
                    SetDlgItemText(hWnd, IDC_PROP_MODIFIED, buf);
                } else {
                    SetDlgItemText(hWnd, IDC_PROP_MODIFIED, p);
                }
            }
        } else {  // g_command_ls
            char abuf[wdirtypemax];
            wp = wcsrchr(g_filenameW, '/');
            if (wp)
                wp++;
            else
                wp = g_filenameW;
            walcopy(abuf, wp, sizeof(abuf)-1);
            if (usys()) {
                SetDlgItemTextW(hWnd, IDC_PROP_NAME, g_filenameW);
            } else {
                SetDlgItemText(hWnd, IDC_PROP_NAME, abuf);
            }
            walcopy(abuf, g_filenameW, sizeof(abuf)-1);
            p = strstr(g_statreplyA, abuf);
            if (!p) {
                walcopy(abuf, wp, sizeof(abuf)-1);
                p = strstr(g_statreplyA, abuf);
            }
            if (p && p > g_statreplyA) {
                p[0] = 0;
                p--;
                // now cut off time in form APR 1 2001 or APR 1 13:30
                while (p > g_statreplyA && p[0] == ' ')
                    p--;
                while (p > g_statreplyA && p[0] != ' ')
                    p--; //time or year
                while (p > g_statreplyA && p[0] == ' ')
                    p--;
                while (p > g_statreplyA && p[0] != ' ')
                    p--; //day
                while (p > g_statreplyA && p[0] == ' ')
                    p--;
                while (p > g_statreplyA && (p[0] < '0' || p[0] > '9'))
                    p--;  // find size
                p2 = p + 1;
                while (p2[0] == ' ') p2++;
                SetDlgItemText(hWnd, IDC_PROP_MODIFIED, p2);
                p[1] = 0;
                while (p > g_statreplyA && p[0] >= '0' && p[0] <= '9')
                    p--;  // find size
                if (p[0] == ' ') p++;
                SetDlgItemText(hWnd, IDC_PROP_SIZE, p);

                if (p > g_statreplyA) {
                    p--;
                    while (p > g_statreplyA && p[0] == ' ')
                        p--;
                    p[1] = 0;
                    while (p > g_statreplyA && p[0] != ' ')
                        p--; //group
                    p2 = p;
                    if (p2[0] == ' ') p2++;
                    SetDlgItemText(hWnd, IDC_PROP_GROUP, p2);
                    while (p > g_statreplyA && p[0] == ' ')
                        p--;
                    p[1] = 0;
                    while (p > g_statreplyA && p[0]!=' ')
                        p--; //group
                    if (p[0] == ' ') p++;
                    SetDlgItemText(hWnd, IDC_PROP_OWNER, p);
                }
                // permissions
                p = strchr(g_statreplyA, ' ');
                if (p) {
                    p[0] = 0;
                    SetDlgItemText(hWnd, IDC_PROP_PERMISSIONS, g_statreplyA);
                }
            }
        }
        // trying to center the About dialog
        if (GetWindowRect(hWnd,  &rt1) && GetWindowRect(GetParent(hWnd), &rt2)) {
            w = rt2.right  - rt2.left;
            h = rt2.bottom - rt2.top;
            DlgWidth   = rt1.right - rt1.left;
            DlgHeight  = rt1.bottom - rt1.top ;
            NewPosX    = rt2.left + (w - DlgWidth)/2;
            NewPosY    = rt2.top + (h - DlgHeight)/2;
            SetWindowPos(hWnd, 0, NewPosX, NewPosY, 0, 0, SWP_NOZORDER | SWP_NOSIZE);
        }
        return 1;
        break;
    }
    case WM_SHOWWINDOW: {
        break;
    }
    case WM_COMMAND: {
        switch(LOWORD(wParam)) {
            case IDOK:
            case IDCANCEL: {
                EndDialog(hWnd,  IDOK);
                return 1;
            }
        }
    }
    }
    return 0;
}

void SftpShowPropertiesW(void* serverid, WCHAR* remotename)
{
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (!ConnectSettings)
        return;
    WCHAR filename[wdirtypemax], cmdname[wdirtypemax], replyW[8192];
    char replyA[8192];

    // note: SftpQuoteCommand2 already converts from Ansi to UTF-8!!!
    wcslcpy(filename, remotename, countof(filename)-1);
    ReplaceBackslashBySlashW(filename);

    wcslcpy(cmdname, L"stat ", countof(cmdname)-1);
    BOOL needquotes = wcschr(filename, ' ')!=NULL || wcschr(filename, '(')!=NULL || wcschr(filename, ')')!=NULL;
    if (needquotes)
        wcslcat(cmdname, L"\"", countof(cmdname)-1);
    wcslcat(cmdname, filename, countof(cmdname)-1);
    if (needquotes)
        wcslcat(cmdname, L"\"", countof(cmdname)-1);
    replyA[0] = 0;
    replyW[0] = 0;
    g_statreplyA = NULL;
    g_statreplyW = NULL;
    if (SftpQuoteCommand2W(serverid, NULL, cmdname, replyA, sizeof(replyA)-1) >= 0) {
        CopyStringA2W(ConnectSettings, replyA, replyW, _countof(replyW));
        walcopy(replyA, replyW, sizeof(replyA)-1);
        g_command_ls = false;
        g_statreplyA = replyA;
        g_statreplyW = replyW;
    }

    BOOL statworked = g_statreplyW != NULL;
    if (statworked) {
        WCHAR chw, *wp;
        wp = FindStatStringW(g_statreplyW, L"File:", &chw);
        if (wp) {
            wp[wcslen(wp)] = chw;
        } else 
            statworked = false;
    }
    if (!statworked) {  // stat failed -> try "ls -la filename"
        wcslcpy(replyW, cmdname + 5, countof(replyW)-1);
        wcslcpy(cmdname, L"ls -la ", countof(cmdname)-1);
        wcslcat(cmdname, replyW, wdirtypemax-1);
        if (SftpQuoteCommand2W(serverid, NULL, cmdname, replyA, sizeof(replyA)-1) >= 0) {
            g_command_ls = true;
            CopyStringA2W(ConnectSettings, replyA, replyW, _countof(replyW));
            walcopy(replyA, replyW, sizeof(replyA)-1);
            g_statreplyA = replyA;
            g_statreplyW = replyW;
        }
    }

    if (g_statreplyA) {
        g_filenameW = filename;
        if (usys())
            DialogBoxW(hinst, MAKEINTRESOURCEW(IDD_PROPERTIES), GetActiveWindow(), PropDlgProc);
        else
            DialogBox(hinst, MAKEINTRESOURCE(IDD_PROPERTIES), GetActiveWindow(), PropDlgProc);
    }
}

void SftpGetLastActivePathW(void* serverid, WCHAR* RelativePath, int maxlen)
{
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (ConnectSettings)
        wcslcpy(RelativePath, ConnectSettings->lastactivepath, maxlen);
    else
        RelativePath[0] = 0;
}

BOOL SftpSupportsResume(void* serverid)
{
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (ConnectSettings)
        return !ConnectSettings->scponly;
    else
        return false;
}

BOOL IsHexChar(char ch)
{
    return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
}

BOOL CheckChecksumSupport(char* buf,char* type,int hashlen)
{
    char *p = strstr(buf, type);
    if (p) {
        p += strlen(type);
        while (p[0] && !IsHexChar(p[0])) p++;
        char* pend = p;
        while (IsHexChar(pend[0])) pend++;
        if ((pend - p) == hashlen)
            return true;
    }
    return false;
}


int SftpServerSupportsChecksumsW(void* serverid, WCHAR* RemoteName)
{
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (!ConnectSettings)
        return SFTP_FAILED;

    int supported = 0;
    ShowStatusW(L"Check whether the server supports checksum functions...");

    LIBSSH2_CHANNEL *channel;
    channel = ConnectChannel(ConnectSettings->session);
    if (channel == NULL)
        return NULL;
    if (!SendChannelCommand(ConnectSettings->session, channel, "echo md5\nmd5sum\necho sha1\nsha1sum\necho sha256\nsha256sum\necho sha512\nsha512sum\n")) {
        DisconnectShell(channel);
        return 0;
    }
    char buf[4096];
    char errbuf[1024];
    int buflen = 0;
    while (!libssh2_channel_eof(channel)) {
        int len2 = libssh2_channel_read(channel, buf + buflen, sizeof(buf) - buflen - 1);
        if (len2 > 0)
            buflen += len2;
        if (!libssh2_channel_eof(channel))
            libssh2_channel_read_stderr(channel, errbuf, sizeof(errbuf)-1); // ignore errors
        if (EscapePressed())
            break;
    }
    DisconnectShell(channel);
    buf[buflen] = 0;
    // Analyse result: It should return
    // d41d8cd98f00b204e9800998ecf8427e  -
    // da39a3ee5e6b4b0d3255bfef95601890afd80709  -
    // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  -
    if (CheckChecksumSupport(buf, "md5", 32))
        supported |= FS_CHK_MD5;
    if (CheckChecksumSupport(buf, "sha1", 40))
        supported |= FS_CHK_SHA1;
    if (CheckChecksumSupport(buf, "sha256", 64))
        supported |= FS_CHK_SHA256;
    if (CheckChecksumSupport(buf, "sha512", 128))
        supported |= FS_CHK_SHA512;
    return supported;
}

HANDLE SftpStartFileChecksumW(int ChecksumType, void* serverid, WCHAR* RemoteName)
{
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (!ConnectSettings)
        return NULL;

    WCHAR msgbuf[wdirtypemax];
    char filename[wdirtypemax];
    CopyStringW2A(ConnectSettings, RemoteName, filename, _countof(filename));
    ReplaceBackslashBySlash(filename);

    wcslcpy(msgbuf, L"Get ", countof(msgbuf)-1);

    char commandbuf[wdirtypemax+8];
    switch (ChecksumType) {
    case FS_CHK_MD5:
        strlcpy(commandbuf, "md5sum ", sizeof(commandbuf)-1);
        wcslcat(msgbuf, L"md5", countof(msgbuf)-1);
        break;
    case FS_CHK_SHA1:
        strlcpy(commandbuf, "sha1sum ", sizeof(commandbuf)-1);
        wcslcat(msgbuf, L"sha1", countof(msgbuf)-1);
        break;
    case FS_CHK_SHA256:
        strlcpy(commandbuf, "sha256sum ", sizeof(commandbuf)-1);
        wcslcat(msgbuf, L"sha256", countof(msgbuf)-1);
        break;
    case FS_CHK_SHA512:
        strlcpy(commandbuf, "sha512sum ", sizeof(commandbuf)-1);
        wcslcat(msgbuf, L"sha512", countof(msgbuf)-1);
        break;
    default:
        return NULL;
    }

    BOOL needquotes = strchr(filename,' ')!=NULL || strchr(filename,'(')!=NULL || strchr(filename,')')!=NULL;
    if (needquotes)
        strlcat(commandbuf, "\"", sizeof(commandbuf)-3);
    strlcat(commandbuf, filename, sizeof(commandbuf)-2);
    if (needquotes)
        strlcat(commandbuf, "\"", sizeof(commandbuf)-1);
    strlcat(commandbuf, "\nexit\n", sizeof(commandbuf)-3);  // needed because we don't send EOF, so we can abort!

    wcslcat(msgbuf, L" checksum for: ", countof(msgbuf)-1);
    wcslcat(msgbuf, RemoteName, countof(msgbuf)-1);
    ReplaceBackslashBySlashW(msgbuf);
    ShowStatusW(msgbuf);

    LIBSSH2_CHANNEL *channel;
    channel = ConnectChannel(ConnectSettings->session);
    if (channel == NULL)
        return NULL;

    // Request VT102 terminal, so character 3 works as abort!
    while (LIBSSH2_ERROR_EAGAIN == libssh2_channel_request_pty_ex(channel, "vt102", 5, "", 0, 80, 40, 640, 480)) {}

    if (!SendChannelCommandNoEof(ConnectSettings->session, channel, commandbuf)) {
        DisconnectShell(channel);
        return NULL;
    }
    return (HANDLE)channel;
}


int SftpGetFileChecksumResultW(BOOL WantResult, HANDLE ChecksumHandle, void* serverid, char* checksum, int maxlen)
{
    LIBSSH2_CHANNEL *channel = (LIBSSH2_CHANNEL*)ChecksumHandle;
    if (channel == NULL)
        return NULL;
    char buf[2048];

    if (WantResult) {
        char errbuf[1024];
        int buflen = 0;
        while (!libssh2_channel_eof(channel)) {
            int len2 = libssh2_channel_read(channel, buf + buflen, sizeof(buf) - buflen - 1);
            if (len2 > 0)
                buflen += len2;
            else
                break;
            if (!libssh2_channel_eof(channel))
                libssh2_channel_read_stderr(channel, errbuf, sizeof(errbuf)-1); // ignore errors
            if (EscapePressed())
                break;

        }
        if (libssh2_channel_eof(channel)) {
            DisconnectShell(channel);
            channel = NULL;
        }

        buf[buflen] = 0;
        char *p = buf;
        while (p[0] && !IsHexChar(p[0])) p++;
        char* pend = p;
        while (IsHexChar(pend[0])) pend++;
        int len = (pend - p);
        if (len > maxlen)
            len = maxlen;
        if (len > 0) {
            strlcpy(checksum, p, len);
            DisconnectShell(channel);
            return len;
        }
        if (channel == NULL)
            return FS_CHK_ERR_FAIL;
        else
            return FS_CHK_ERR_BUSY;  // didn't receive the checksum yet!
    } else {
        if (!libssh2_channel_eof(channel)) {
            buf[0] = 3;
            while (libssh2_channel_write_ex(channel, 0, buf, 1) == LIBSSH2_ERROR_EAGAIN) { // Ctrl+C!
                if (EscapePressed())
                    break;
            }
        }

        DisconnectShell(channel);
    }
    return 0;
}

VOID CALLBACK TimerProc(HWND hwnd, UINT uMsg, myuint idEvent, DWORD dwTime)
{
    if (uMsg == WM_TIMER && idEvent == 1000) { 
        ::KillTimer(hwnd, idEvent);

        pConnectSettings ConnectSettings = ghWndToConnectSettings[hwnd];

        if (ConnectSettings) {
            char connbuf[MAX_PATH];
            strlcpy(connbuf, "KEEP-ALIVE \\", sizeof(connbuf)-1);
            strlcat(connbuf, ConnectSettings->DisplayName, sizeof(connbuf)-1);
            LogProc(PluginNumber, MSGTYPE_DETAILS, connbuf);

            int iRet = 0;

            int i = libssh2_keepalive_send(ConnectSettings->session, &iRet);

            ::SetTimer(hwnd, idEvent, (iRet > 0 ? iRet : ConnectSettings->keepAliveIntervalSeconds) * 1000, TimerProc);
        }
    }
}

