#include "global.h"
#include <windows.h>
#include <ws2tcpip.h>
#include <shellapi.h>
#include <commdlg.h>
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

bool serverfieldchangedbyuser = false;
char Global_TransferMode = 'I';  //I=Binary,  A=Ansi,  X=Auto
WCHAR Global_TextTypes[1024];
char global_detectcrlf = 0;

VOID CALLBACK TimerProc(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime) noexcept;

LIBSSH2_CHANNEL * ConnectChannel(LIBSSH2_SESSION *session) noexcept;
bool SendChannelCommand(LIBSSH2_SESSION * session, LIBSSH2_CHANNEL * channel, LPCSTR command) noexcept;
bool GetChannelCommandReply(LIBSSH2_SESSION * session, LIBSSH2_CHANNEL * channel, LPCSTR command) noexcept;
void DisconnectShell(LIBSSH2_CHANNEL * channel) noexcept;
void StripEscapeSequences(LPSTR msgbuf) noexcept;
bool ReadChannelLine(LIBSSH2_CHANNEL * channel, LPSTR line, size_t linelen, LPSTR msgbuf, size_t msgbuflen, LPSTR errbuf, size_t errbuflen);
int  CloseRemote(SERVERID serverid, LIBSSH2_SFTP_HANDLE * remotefilesftp, LIBSSH2_CHANNEL * remotefilescp, bool timeout, int percent) noexcept;

pConnectSettings gConnectResults;
LPCSTR gDisplayName;
LPCSTR gIniFileName;
int g_focusset = 0;

#ifndef SFTP_ALLINONE
HINSTANCE sshlib = NULL;
#endif
bool loadOK, loadAgent;

void EncryptString(LPCSTR pszPlain, LPSTR pszEncrypted, size_t cchEncrypted);


typedef struct {
    LIBSSH2_CHANNEL *channel;
    char msgbuf[2048];   // previously received data
    char errbuf[2048];
} SCP_DATA;

bool EscapePressed() noexcept
{
    // Abort with ESCAPE pressed in same program only!
    if (GetAsyncKeyState(VK_ESCAPE) < 0) {
        DWORD procid1 = 0;
        HWND hwnd = GetActiveWindow();
        if (hwnd) {
            GetWindowThreadProcessId(hwnd, &procid1);
            if (procid1 == GetCurrentProcessId())
                return true;
        }
    }
    return false;
}

void strlcpyansitoutf8(LPSTR utf8str, LPCSTR ansistr, size_t maxlen) noexcept
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


#ifndef SFTP_ALLINONE

static FARPROC GetProcAddress2(HMODULE hModule, LPCSTR lpProcName) noexcept
{
    FARPROC retval = GetProcAddress(hModule, lpProcName);
    if (!retval)
        loadOK = false;
    return retval;
}

static FARPROC GetProcAddressAgent(HMODULE hModule, LPCSTR lpProcName) noexcept
{
    FARPROC retval = GetProcAddress(hModule, lpProcName);
    if (!retval)
        loadAgent = false;
    return retval;
}


#define FUNCDEF(r, f, p) typedef r (*t##f) p;
#define FUNCDEF2(r, f, p) typedef r (*t##f) p;
#include "sshdynfunctions.h"
#undef FUNCDEF2
#undef FUNCDEF


#define FUNCDEF(r, f, p) t##f f=NULL;
#define FUNCDEF2(r, f, p) t##f f=NULL;
#include "sshdynfunctions.h"
#undef FUNCDEF2
#undef FUNCDEF


static HINSTANCE LoadDllAdv(LPCSTR path, LPCSTR subdir, LPCSTR name, DWORD flags = 0) noexcept
{
    HMODULE lib = NULL;
    char dllname[MAX_PATH];
    strlcpy(dllname, path, countof(dllname) - 1);
    if (subdir && subdir[0]) {
        strlcat(dllname, subdir, countof(dllname) - 1);
        strlcat(dllname, "\\", countof(dllname) - 1);
    }
    strlcat(dllname, name, countof(dllname) - 1);
    if (flags) {
        lib = LoadLibraryExA(dllname, NULL, flags);
    } else {
        lib = LoadLibraryA(dllname);
    }
    return (HINSTANCE)lib;
}

static HINSTANCE LoadAllLibs(LPCSTR dllpath) noexcept
{
    HMODULE lib = NULL;
    // Load libeay32.dll first,  otherwise it will not be found!
#ifdef _WIN64
    LoadDllAdv(dllpath, "64", "zlibwapi.dll");
    LoadDllAdv(dllpath, "64", "zlib1.dll");
    LoadDllAdv(dllpath, "64", "libeay32.dll");
    lib = LoadDllAdv(dllpath, "64", "libssh2.dll");
    if (!lib) {
        LoadDllAdv(dllpath, "x64", "zlibwapi.dll");
        LoadDllAdv(dllpath, "x64", "zlib1.dll");
        LoadDllAdv(dllpath, "x64", "libeay32.dll");
        lib = LoadDllAdv(dllpath, "x64", "libssh2.dll");
    }
#endif
    if (!lib) {
        LoadDllAdv(dllpath, "", "zlibwapi.dll");
        LoadDllAdv(dllpath, "", "zlib1.dll");
        LoadDllAdv(dllpath, "", "libeay32.dll");
        lib = LoadDllAdv(dllpath, "", "libssh2.dll");
    }
    return (HINSTANCE)lib;
}

bool LoadSSHLib() noexcept
{
    if (sshlib)
        return loadOK;

    LogProc(PluginNumber, MSGTYPE_DETAILS, "Loading SSH Library");
    int olderrormode = SetErrorMode(0x8001);
    char dllname[MAX_PATH];
    dllname[0] = 0;

    // first, try in the DLL directory (changed from previous versions)
    GetModuleFileName(hinst, dllname, sizeof(dllname)-10);
    LPSTR p = strrchr(dllname, '\\');
    p = p ? p + 1 : dllname;
    p[0] = 0;
    sshlib = LoadAllLibs(dllname);

    if (!sshlib) {
        GetModuleFileName(NULL, dllname, sizeof(dllname) - 10);
        LPSTR p = strrchr(dllname, '\\');
        p = p ? p + 1 : dllname;
        p[0] = 0;
        sshlib = LoadAllLibs(dllname);
    }
    if (!sshlib) {
        // try also in Total Commander dir and the path!
        // we don't need to load libeay32.dll then,  because
        // libssh2.dll would find it in the path anyway!
        sshlib = (HINSTANCE)LoadLibraryA("libssh2.dll");
    }
    if (!sshlib) {
        OSVERSIONINFO vx;
        vx.dwOSVersionInfoSize = sizeof(vx);
        GetVersionEx(&vx);
        if (vx.dwPlatformId == VER_PLATFORM_WIN32_NT && vx.dwMajorVersion < 6) {  // XP or older?
            GetModuleFileName(hinst, dllname, sizeof(dllname)-10);
            LPSTR p = strrchr(dllname,'\\');
            p = p ? p + 1 : dllname;
            p[0] = 0;
#ifdef _WIN64
            sshlib = LoadDllAdv(dllname, "64", "libssh2.dll", LOAD_LIBRARY_AS_DATAFILE);
            if (!sshlib) {
                sshlib = LoadDllAdv(dllname, "x64", "libssh2.dll", LOAD_LIBRARY_AS_DATAFILE);
            }
#endif
            if (!sshlib) {
                sshlib = LoadDllAdv(dllname, "", "libssh2.dll", LOAD_LIBRARY_AS_DATAFILE);
            }
            if (sshlib) {
                HICON icon = LoadIcon(sshlib, MAKEINTRESOURCE(12345));   /* FIXME: magic number! */
                FreeLibrary(sshlib);
                sshlib = NULL;
                if (icon) {
                    LPCSTR txt = "This plugin requires Windows Vista, 7 or newer. "
                                 "Please get the separate plugin for Windows XP or older from www.ghisler.com!";
                    MessageBox(GetActiveWindow(), txt, "Error", MB_ICONSTOP);
                    return false;
                }
            }
        }
        LPCSTR txt = "Please put the openssl dlls either\n"
                     "- in the same directory as the plugin, or\n"
                     "- in the Total Commander dir, or\n"
#ifdef _WIN64
                     "- in subdir \"64\" of the plugin or TC directory, or\n"
#endif
                     "- somewhere in your PATH!\n\nDownload now?";

        int res = MessageBox(GetActiveWindow(), txt, "Error", MB_YESNO | MB_ICONSTOP);
        if (res == IDYES)
            ShellExecute(GetActiveWindow(), NULL, "https://www.ghisler.com/openssl", NULL, NULL, SW_SHOW);
        return false;
    }

    SetErrorMode(olderrormode);
    loadOK = true;
    loadAgent = true;

    // the following will load all the functions!
    #define FUNCDEF(r, f, p) f=(t##f)GetProcAddress2(sshlib,  #f)
    #define FUNCDEF2(r, f, p) f=(t##f)GetProcAddressAgent(sshlib,  #f)
    #include "sshdynfunctions.h"
    #undef FUNCDEF2
    #undef FUNCDEF

    return loadOK;
}

#else

bool LoadSSHLib() noexcept
{
    loadOK = true;
    loadAgent = true;
    return true;
}

#endif  /* SFTP_ALLINONE */

extern "C"
void kbd_callback(LPCSTR name, int name_len,
                  LPCSTR instruction, int instruction_len, int num_prompts,
                  const LIBSSH2_USERAUTH_KBDINT_PROMPT * prompts,
                  LIBSSH2_USERAUTH_KBDINT_RESPONSE * responses,
                  LPVOID * abstract)
{
    char buf[1024];
    char retbuf[256];
    pConnectSettings ConnectSettings = (pConnectSettings)*abstract;

    for (int i = 0; i < num_prompts; i++) {
        // Special case: Pass the stored password as the first response to the interactive prompts
        // Note: We may get multiple calls to kbd_callback - this is tracked with "InteractivePasswordSent"
        strlcpy(retbuf, prompts[i].text, min(prompts[i].length, sizeof(retbuf)-1));
        ShowStatus(retbuf);
        bool autoSendPassword = (ConnectSettings && ConnectSettings->password[0] && !ConnectSettings->InteractivePasswordSent);
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
            size_t len = strlen(ConnectSettings->password);
            if (p && ConnectSettings->password[0] == '"' && ConnectSettings->password[len-1] == '"') {
                // two passwords -> use second one!
                ConnectSettings->password[len-1] = 0;
                if (p[3] == 0)
                    autoSendPassword = false;
                else
                    responses[i].text = _strdup(p + 3);
                ConnectSettings->password[len-1] = '"';
            } else {
                responses[i].text = _strdup(ConnectSettings->password);
            }
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

extern "C"
LPVOID myalloc(size_t count, LPVOID * abstract)
{
    return malloc(count);
}

extern "C"
LPVOID myrealloc(LPVOID ptr, size_t count, LPVOID * abstract)
{
    // avoid possible memory leak if realloc fails
    LPVOID ptrSav = ptr;

    ptr = realloc(ptr, count);

    if (ptr == NULL && ptrSav != NULL)
        free(ptrSav);

    return ptr;
}

extern "C"
void myfree(LPVOID ptr, LPVOID * abstract)
{
    free(ptr);
}

static bool ismimechar(const char ch)
{
    return ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
             ch == '/' || ch == '+' || ch == '=' || ch == '\r' || ch == '\n');
}

/* return false when TASK aborted */
bool ProgressLoop(LPCSTR progresstext, int start, int end, int * loopval, SYSTICKS * lasttime)
{
    SYSTICKS time = get_sys_ticks();
    if (time - *lasttime > 100 || *loopval < start) {    /* FIXME: magic number! */
        *lasttime = time;
        (*loopval)++;
        if (*loopval < start || *loopval > end)
            *loopval = start;
        return ProgressProc(PluginNumber, progresstext, "-", *loopval) != 0;    /* FIXME: magic number! */
    }
    return false;
}

static void SftpLogLastError(LPCSTR errtext, int errnr)
{
    char errbuf[128];
    if (errnr == 0 || errnr == LIBSSH2_ERROR_EAGAIN)   //no error -> do not log
        return;
    strlcpy(errbuf, errtext, countof(errbuf) - 10);
    errnr = -errnr;
    if (errnr >= 0 && errnr < countof(ERRORNAMES)) {
        strlcat(errbuf, ERRORNAMES[errnr], sizeof(errbuf)-8);
        strlcat(errbuf, " (", sizeof(errbuf)-6);
        _itoa(errnr, errbuf + strlen(errbuf), 10);
        strlcat(errbuf, ")", sizeof(errbuf)-1);
    } else {
        _itoa(errnr, errbuf + strlen(errbuf), 10);
    }
    LogProc(PluginNumber, MSGTYPE_IMPORTANTERROR, errbuf);
}

static void ShowMessageIdEx(int errorid, LPCSTR p1, int p2, bool silent)
{
    char errorstr[256];
    char fmt[256];
    if (errorid < 0)
        return;
    LoadStr(errorstr, errorid);
    if (p1) {
        strcpy(fmt, errorstr);
        if (strstr(errorstr, "%s"))
            sprintf_s(errorstr, countof(errorstr), fmt, p1);
        else if (strstr(errorstr, "%d"))
            sprintf_s(errorstr, countof(errorstr), fmt, p2);
        else
            strlcat(errorstr, p1, sizeof(errorstr)-1);
    }
    ShowStatus(errorstr);  // log it
    if (!silent)
        RequestProc(PluginNumber, RT_MsgOK, "SFTP Error", errorstr, NULL, 0);
}

static void ShowStatusId(int errorid, bool silent, int value)
{
    ShowMessageIdEx(errorid, "", value, silent);
}

static void ShowStatusId(int errorid, LPCSTR suffix, bool silent = true)
{
    ShowMessageIdEx(errorid, suffix, 0, silent);
}

static void ShowErrorId(int errorid, LPCSTR suffix = NULL)
{
    ShowMessageIdEx(errorid, NULL, 0, false);
}

static void ShowError(LPCSTR error)
{
    ShowStatus(error);  // log it
    RequestProc(PluginNumber, RT_MsgOK, "SFTP Error", error, NULL, 0);
}


static void SetBlockingSocket(SOCKET s, bool blocking)
{
    u_long arg = blocking ? 0 : 1;
    ioctlsocket(s, FIONBIO, &arg);
}

static bool IsSocketError(SOCKET s)
{
    fd_set fds;
    timeval timeout = gettimeval(50);   /* FIXME: magic number! */
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    return 1 == select(0, NULL, NULL, &fds, &timeout);
}

static bool IsSocketWritable(SOCKET s)
{
    fd_set fds;
    timeval timeout = gettimeval(50);   /* FIXME: magic number! */
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    return 1 == select(0, NULL, &fds, NULL, &timeout);
}

static bool IsSocketReadable(SOCKET s)
{
    fd_set fds;
    timeval timeout = gettimeval(1000);  // This is absolutely necessary, otherwise wingate local will not work!  /* FIXME: magic number! */
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    int err = select(0, &fds, NULL, NULL, &timeout);
    return (err == 1);
}

extern "C"
int mysend(SOCKET s, LPCSTR buf, int len, int flags, LPCSTR progressmessage, int progressstart, int * ploop, SYSTICKS * plasttime)
{
    int ret = SOCKET_ERROR;
    while (true) {
        ret = send(s, buf, len, flags);
        if (ret != len)
            MessageBeep(0);   /* FIXME: ???????? */
        if (ret >= 0)
            return ret;
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            if (ProgressLoop(progressmessage, progressstart, progressstart + 10, ploop, plasttime))
                break;
        }
    }
    return ret;
}

extern "C"
int myrecv(SOCKET s, LPSTR buf, int len, int flags, LPCSTR progressmessage, int progressstart, int * ploop, SYSTICKS * plasttime)
{
    int totallen = len;
    int ret = SOCKET_ERROR;
    while (true) {
        if (IsSocketReadable(s)) {
            ret = recv(s, buf, len, flags);
            if (ret == len)
                return totallen;
            if (ret > 0) {
                buf += ret;
                len -= ret;
                continue;
            }
            if (WSAGetLastError() != WSAEWOULDBLOCK)
                return ret;
        }
        if (ProgressLoop(progressmessage, progressstart, progressstart + 10, ploop, plasttime))
            break;   /* task aborted */
        Sleep(50);   /* FIXME: magic number! */
    }
    return ret;
}

extern "C"
void newpassfunc(LIBSSH2_SESSION * session, LPSTR * newpw, int * newpw_len, LPVOID * abstract)
{
    pConnectSettings PassConnectSettings = (pConnectSettings)*abstract;
    char title[128], buf1[128];
    char newpass[128];
    LoadStr(title, IDS_PASS_TITLE);
    LoadStr(buf1, IDS_PASS_CHANGE_REQUEST);
    newpass[0] = 0;
    if (RequestProc(PluginNumber, RT_Password, title, buf1, newpass, sizeof(newpass)-1)) {
        size_t bufsize = strlen(newpass) + 1;
        *newpw = (char*)malloc(bufsize);
        strlcpy(*newpw, newpass, bufsize);
        *newpw_len = (int)bufsize;
        if (PassConnectSettings) {
            strlcpy(PassConnectSettings->password, newpass, sizeof(PassConnectSettings->password)-1);
            switch (PassConnectSettings->passSaveMode) {
            case sftp::PassSaveMode::crypt:
                CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_SAVE_PASSWORD, PassConnectSettings->DisplayName, newpass, 0);
                break;
            case sftp::PassSaveMode::plain:
                if (newpass[0] == 0) {
                    WritePrivateProfileString(PassConnectSettings->DisplayName, "password", NULL, gIniFileName);
                } else {
                    char szEncryptedPassword[256];
                    EncryptString(newpass, szEncryptedPassword, countof(szEncryptedPassword));
                    WritePrivateProfileString(PassConnectSettings->DisplayName, "password", szEncryptedPassword, gIniFileName);
                }
                break;
            }
        }
    }
}

static int SftpConnectProxyHttp(pConnectSettings ConnectSettings, LPCSTR progressbuf, int progress, int * ploop, SYSTICKS * plasttime)
{
    char buf[1024];
    // Send "CONNECT hostname:port HTTP/1.1"<CRLF>"Host: hostname:port"<2xCRLF> to the proxy
    LPCSTR txt;
    if (IsNumericIPv6(ConnectSettings->server))
        txt = "CONNECT [%s]:%d HTTP/1.1\r\nHost: [%s]:%d\r\n";
    else
        txt = "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n";
    sprintf_s(buf, sizeof(buf), txt, ConnectSettings->server, ConnectSettings->customport, ConnectSettings->server, ConnectSettings->customport);
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
    mysend(ConnectSettings->sock, buf, (int)strlen(buf), 0, progressbuf, progress, ploop, plasttime);
    // Response;
    // HTTP/1.0 200 Connection established
    // Proxy-agent: WinProxy/1.5.3<2xCRLF>
    bool lastcrlfcrlf = false;
    int nrbytes = myrecv(ConnectSettings->sock, buf, 12, 0, progressbuf, progress, ploop, plasttime);
    if (nrbytes == 12 && buf[9] == '2') {    // proxy signals success!!
                                             // read data until we get 2xCRLF
        bool lastcrlf = false;
        bool lastcr = false;
        while (1) {
            nrbytes = myrecv(ConnectSettings->sock, buf, 1, 0, progressbuf, progress, ploop, plasttime);
            if (nrbytes <= 0)
                break;
            if (buf[0] == '\r') {
                lastcr = true;
                continue;
            }
            if (buf[0] != '\n') {
                lastcr = false;
                lastcrlf = false;
                continue;
            }
            if (!lastcr) {
                lastcrlf = false;
                continue;
            }
            if (!lastcrlf) {
                lastcrlf = true;
                continue;
            }
            lastcrlfcrlf = true;
            break;
        }
    }
    if (!lastcrlfcrlf) {
        ShowErrorId(IDS_VIA_PROXY_CONNECT);
        return -1;
    }
    return SFTP_OK;
}

static int SftpConnectProxySocks4(pConnectSettings ConnectSettings, LPCSTR progressbuf, int progress, int * ploop, SYSTICKS * plasttime)
{
    char buf[1024];
    ZeroMemory(buf, sizeof(buf));
    buf[0] = 4; // version        /* FIXME: use SOCKS packet struct */
    buf[1] = 1; // TCP connect
    *((PWORD)&buf[2]) = htons(ConnectSettings->customport);

    // numerical IPv4 given?
    ULONG hostaddr = inet_addr(ConnectSettings->server);
    if (hostaddr == INADDR_NONE)
        *((PLONG)&buf[4]) = htonl(0x00000001);     /* FIXME: magic number! */
    else
        *((PLONG)&buf[4]) = hostaddr;  // it's already in network order!
    size_t nrbytes = 8;    /* FIXME: magic number! */
    strlcpy(&buf[nrbytes], ConnectSettings->proxyuser, sizeof(buf) - nrbytes - 1);
    nrbytes += strlen(ConnectSettings->proxyuser) + 1;
    if (hostaddr == INADDR_NONE) {  // SOCKS4A
        strlcpy(&buf[nrbytes], ConnectSettings->server, sizeof(buf) - nrbytes - 1);
        nrbytes += strlen(ConnectSettings->server) + 1;
    }
    //
    mysend(ConnectSettings->sock, buf, nrbytes, 0, progressbuf, progress, ploop, plasttime);
    int rc = myrecv(ConnectSettings->sock, buf, 8, 0, progressbuf, progress, ploop, plasttime);
    if (rc != 8 || buf[0] != 0 || buf[1] != 0x5a) {
        ShowErrorId(IDS_VIA_PROXY_CONNECT);
        return -1;
    }
    return SFTP_OK;
}

static int SftpConnectProxySocks5(pConnectSettings ConnectSettings, int connecttoport, LPCSTR progressbuf, int progress, int * ploop, SYSTICKS * plasttime)
{
    char buf[1024];
    ZeroMemory(buf, sizeof(buf));
    buf[0] = 5; // version       /* FIXME: use SOCKS packet struct */
    buf[2] = 0; // no auth
    int nrbytes = 3;
    if (ConnectSettings->proxyuser[0]) {
        buf[3] = 2; // user/pass auth
        nrbytes++;
    }
    buf[1] = nrbytes - 2; // nr. of methods

    mysend(ConnectSettings->sock, buf, nrbytes, 0, progressbuf, progress, ploop, plasttime);
    nrbytes = myrecv(ConnectSettings->sock, buf, 2, 0, progressbuf, progress, ploop, plasttime);
    if (!ConnectSettings->proxyuser[0] && buf[1] != 0) {
        *((PBYTE)&buf[1]) = 0xff;
    }
    if (nrbytes != 2 || buf[0] != 5 || buf[1] == 0xff) {
        ShowErrorId(IDS_VIA_PROXY_CONNECT);
        return -1;
    }
    if (buf[1] == 2) { // user/pass auth
        size_t len;
        ZeroMemory(buf, sizeof(buf));
        buf[0] = 1; // version
        len = strlen(ConnectSettings->proxyuser);
        buf[1] = len;
        strlcpy(&buf[2], ConnectSettings->proxyuser, sizeof(buf)-3);
        nrbytes = len + 2;
        len = strlen(ConnectSettings->proxypassword);
        buf[nrbytes] = len;
        strlcpy(&buf[nrbytes+1], ConnectSettings->proxypassword, sizeof(buf) - nrbytes - 1);
        nrbytes += len + 1;

        mysend(ConnectSettings->sock, buf, nrbytes, 0, progressbuf, progress, ploop, plasttime);
        nrbytes = myrecv(ConnectSettings->sock, buf, 2, 0, progressbuf, progress, ploop, plasttime);
        if (nrbytes != 2 || buf[1] != 0) {
            LoadStr(buf, IDS_SOCKS5PROXYERR);
            ShowError(buf);
            return -2;
        }
    }

    ZeroMemory(buf,  sizeof(buf));
    buf[0] = 5; // version         /* FIXME: use SOCKS packet struct */
    buf[1] = 1; // TCP connect
    buf[2] = 0; // reserved

    ULONG hostaddr = inet_addr(ConnectSettings->server);
    if (hostaddr != INADDR_NONE) {
        buf[3] = 1; // addrtype (IPv4)
        *((PLONG)&buf[4]) = hostaddr;  // it's already in network order!
        nrbytes = 4 + 4;
    } else {
        bool numipv6 = false;  // is it an IPv6 numeric address?
        if (IsNumericIPv6(ConnectSettings->server)) {
            struct addrinfo hints;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET6;
            hints.ai_socktype = SOCK_STREAM;
            sprintf_s(buf, sizeof(buf), "%d", connecttoport);
            struct addrinfo * res = NULL;
            if (getaddrinfo(ConnectSettings->server, buf, &hints, &res) == 0) {
                if (res->ai_addrlen >= sizeof(sockaddr_in6)) {
                    numipv6 = true;
                    buf[3] = 4; // IPv6
                    memcpy(&buf[4], &((sockaddr_in6 *)res->ai_addr)->sin6_addr, 16);
                    nrbytes = 4 + 16;
                }
                freeaddrinfo(res);
            }
        }
        if (!numipv6) {
            buf[3] = 3; // addrtype (domainname)
            buf[4] = (char)strlen(ConnectSettings->server);
            strlcpy(&buf[5], ConnectSettings->server, sizeof(buf)-6);
            nrbytes = (UCHAR)buf[4] + 5;
        }
    }
    *((PWORD)&buf[nrbytes]) = htons(ConnectSettings->customport);
    nrbytes += 2;

    mysend(ConnectSettings->sock, buf, nrbytes, 0, progressbuf, progress, ploop, plasttime);
    nrbytes = myrecv(ConnectSettings->sock, buf, 4, 0, progressbuf, progress, ploop, plasttime);
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
                sprintf_s(buf, sizeof(buf), buf2, buf[1]);
            }
        }
        ShowError(buf);
        return -3;
    }
    int needread = 0;
    switch(buf[3]) {
        case 1: 
            needread = 6;   // IPv4+port
            break;
        case 3:
            nrbytes = myrecv(ConnectSettings->sock, buf, 1, 0, progressbuf, progress, ploop, plasttime);
            if (nrbytes == 1)
                needread = buf[0] + 2;
            break;    // Domain Name+port
        case 4:
            needread = 18;   // IPv6+port
            break;
    }
    nrbytes = myrecv(ConnectSettings->sock, buf, needread, 0, progressbuf, progress, ploop, plasttime);
    if (nrbytes != needread) {
        ShowErrorId(IDS_VIA_PROXY_CONNECT);
        return -4;
    }
    return SFTP_OK;
}

const int SSH_AUTH_PASSWORD = 0x01;
const int SSH_AUTH_KEYBOARD = 0x02;
const int SSH_AUTH_PUBKEY   = 0x04;

static int SftpAuthPageant(pConnectSettings ConnectSettings, LPCSTR progressbuf, int progress, int * ploop, SYSTICKS * plasttime, int * auth_pw)
{
    int hr = -IDS_AGENT_AUTHFAILED;
    char buf[1024];
    struct libssh2_agent_publickey * identity = NULL;
    struct libssh2_agent_publickey * prev_identity = NULL;

    LIBSSH2_AGENT * agent = libssh2_agent_init(ConnectSettings->session);

    if (!agent || libssh2_agent_connect(agent) != 0) {
        if (agent) {
            libssh2_agent_disconnect(agent);
            libssh2_agent_free(agent);
            agent = NULL;
        }
        // Try to launch Pageant!
        char linkname[MAX_PATH], dirname[MAX_PATH];
        dirname[0] = 0;
        GetModuleFileName(hinst, dirname, sizeof(dirname)-10);
        char* p = strrchr(dirname, '\\');
        p = p ? p + 1 : dirname;
        p[0] = 0;
        strlcpy(linkname, dirname, MAX_PATH-1);
        strlcat(linkname, "pageant.lnk", MAX_PATH-1);
        if (GetFileAttributesA(linkname) == INVALID_FILE_ATTRIBUTES)
            FIN(-IDS_AGENT_CONNECTERROR);

        HWND active = GetForegroundWindow();
        ShellExecute(active, NULL, linkname, NULL, dirname, SW_SHOW);
        Sleep(2000);
        SYSTICKS starttime = get_sys_ticks();
        while (active != GetForegroundWindow() && get_ticks_between(starttime) < 20000) {  /* FIXME: magic number! */
            Sleep(200);
            if (ProgressLoop(progressbuf, progress, progress + 5, ploop, plasttime))
                break;
        }
        agent = libssh2_agent_init(ConnectSettings->session);
        FIN_IF(!agent, -IDS_AGENT_CONNECTERROR);
        int rc = libssh2_agent_connect(agent);
        FIN_IF(rc, -IDS_AGENT_CONNECTERROR);
    }

    int rc = libssh2_agent_list_identities(agent);
    FIN_IF(rc, -IDS_AGENT_REQUESTIDENTITIES);
    while (1) {
        int auth = libssh2_agent_get_identity(agent, &identity, prev_identity);
        FIN_IF(auth == 1, -IDS_AGENT_AUTHFAILED);  /* pub key */
        FIN_IF(auth < 0, -IDS_AGENT_NOIDENTITY);
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
        while ((auth = libssh2_agent_userauth(agent, ConnectSettings->user, identity)) == LIBSSH2_ERROR_EAGAIN);
#ifndef SFTP_ALLINONE
        if (auth == LIBSSH2_ERROR_REQUIRE_KEYBOARD) {     /* FIXME: patch libssh2 */
            *auth_pw = SSH_AUTH_KEYBOARD;
            FIN(SSH_AUTH_KEYBOARD);
        }
        if (auth == LIBSSH2_ERROR_REQUIRE_PASSWORD) {   /* FIXME: patch libssh2 */
            *auth_pw = SSH_AUTH_PASSWORD;
            FIN(SSH_AUTH_PASSWORD);
        }
#endif
        FIN_IF(auth == 0, 0);   /* OK */
        prev_identity = identity;
    }

    hr = -IDS_AGENT_AUTHFAILED;
    
fin:
    if (hr < 0) {
        ShowStatusId(-hr, NULL, true);
    }
    if (hr == 0) {
        ShowStatusId(IDS_AGENT_AUTHSUCCEEDED, NULL, true);
    }
    if (agent) {
        libssh2_agent_disconnect(agent);
        libssh2_agent_free(agent);
    }
    return hr;
}

static int SftpAuthPubKey(pConnectSettings ConnectSettings, LPCSTR progressbuf, int progress, int * ploop, SYSTICKS * plasttime, int * auth_pw)
{
    int hr = -LIBSSH2_ERROR_FILE;
    char buf[1024];
    bool pubkeybad = false;
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
    DWORD dwShareMode = FILE_SHARE_READ | FILE_SHARE_WRITE;
    DWORD dwFlags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN;    
    HANDLE hf = CreateFileA(pubkeyfile, GENERIC_READ, dwShareMode, NULL, OPEN_EXISTING, dwFlags, NULL);
    FIN_IF(!hf || hf == INVALID_HANDLE_VALUE, -IDS_ERR_LOAD_PUBKEY);
    DWORD dataread = 0;
    if (ReadFile(hf, &filebuf, 35, &dataread, NULL)) {
        if (_strnicmp(filebuf, "ssh-", 4) != 0 && 
            _strnicmp(filebuf, "ecdsa-", 6) != 0 &&
            _strnicmp(filebuf, "-----BEGIN OPENSSH PRIVATE KEY-----", 35) != 0)
        {
            FIN(-IDS_ERR_PUBKEY_WRONG_FORMAT);
        }
    }
    CloseHandle(hf);

    // do not ask for the pass phrase if the key isn't encrypted!
    hf = CreateFile(privkeyfile, GENERIC_READ, dwShareMode, NULL, OPEN_EXISTING, dwFlags, NULL);
    FIN_IF(!hf || hf == INVALID_HANDLE_VALUE, IDS_ERR_LOAD_PRIVKEY);
    dataread = 0;
    bool isencrypted = true; 
    if (ReadFile(hf, &filebuf, sizeof(filebuf)-32, &dataread, NULL)) {
        filebuf[dataread] = 0;
        LPSTR p = strchr(filebuf, '\n');
        if (!p)
            p = strchr(filebuf, '\r');
        if (p) {
            p++;
            while (p[0] == '\r' || p[0] == '\n')
                p++;
            isencrypted = false;
            // if there is something else than just MIME-encoded data, 
            // then the key is encrypted -> we need a pass phrase
            for (int i = 0; i < 32; i++)
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
                    int len = MimeDecode(p, min(64, strlen(p)), outbuf, sizeof(outbuf));
                    for (int i = 0; i < len - 6; i++) {
                        if (outbuf[i] == 'b' && strncmp(outbuf + i, "bcrypt", 6) == 0) {
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
            size_t len = strlen(ConnectSettings->password);
            if (p && ConnectSettings->password[0] == '"' && ConnectSettings->password[len-1] == '"') {
                // two passwords -> use second one!
                p[0] = 0;
                strlcpy(passphrase, ConnectSettings->password + 1, sizeof(passphrase)-1);
                p[0] = '"';
            } else {
                strlcpy(passphrase, ConnectSettings->password, sizeof(passphrase)-1);
            }
        } else {
            RequestProc(PluginNumber, RT_Password, title, buf, passphrase, sizeof(passphrase)-1);
        }
    }

    ShowStatusId(IDS_AUTH_PUBKEY_FOR, ConnectSettings->user, true);

    if (strcmp(pubkeyfile, privkeyfile) == 0)
        pubkeyfileptr = NULL;

    LoadStr(buf, IDS_AUTH_PUBKEY);
    pConnectSettings cs = ConnectSettings;
    int auth;
    while ((auth = libssh2_userauth_publickey_fromfile(cs->session, cs->user, pubkeyfileptr, privkeyfile, passphrase)) == LIBSSH2_ERROR_EAGAIN) {
        if (ProgressLoop(buf, progress, progress + 10, ploop, plasttime))
            break;
        IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
    }
#ifndef SFTP_ALLINONE
    if (auth == LIBSSH2_ERROR_REQUIRE_KEYBOARD) {
        *auth_pw = SSH_AUTH_KEYBOARD;
        FIN(SSH_AUTH_KEYBOARD);
    }
    if (auth == LIBSSH2_ERROR_REQUIRE_PASSWORD) {
        *auth_pw = SSH_AUTH_PASSWORD;
        FIN(SSH_AUTH_PASSWORD);
    }
#endif
    if (auth) {
        SftpLogLastError("libssh2_userauth_publickey_fromfile: ", auth);
        ShowErrorId(IDS_ERR_AUTH_PUBKEY);
        return -IDS_ERR_AUTH_PUBKEY;
    }
    if (!ConnectSettings->password[0])
        strlcpy(ConnectSettings->password, passphrase, sizeof(ConnectSettings->password)-1);

fin:
    if (hr < 0) {
        if (hr == -IDS_ERR_LOAD_PUBKEY)
            ShowStatusId(-hr, pubkeyfile, true);
        else if (hr == -IDS_ERR_LOAD_PRIVKEY)
            ShowStatusId(-hr, privkeyfile, true);
        else
            ShowStatusId(-hr, nullptr, true);
        hr = -LIBSSH2_ERROR_FILE;
    }
    return hr;
}

static int SftpSessionDetectUtf8(pConnectSettings ConnectSettings)
{
    int hr = 0;
    char cmdname[MAX_PATH];
    char reply[8192];
    strlcpy(cmdname, "echo $LC_ALL $LC_CTYPE $LANG", sizeof(cmdname)-1);
    reply[0] = 0;
    if (SftpQuoteCommand2(ConnectSettings, NULL, cmdname, reply, sizeof(reply)-1) == 0) {
        _strupr_s(reply, sizeof(reply));
        if (strstr(reply, "UTF-8")) {
            FIN(1);    /* FIXME: magic number! */
        }
        strlcpy(cmdname, "locale", sizeof(cmdname)-1);
        if (SftpQuoteCommand2(ConnectSettings, NULL, cmdname, reply, sizeof(reply)-1) == 0) {
            _strupr_s(reply, sizeof(reply));
            if (strstr(reply, "UTF-8"))
                FIN(1);    /* FIXME: magic number! */
        }
    }
    hr = 0;
fin:
    // store the result!
    if (strcmp(ConnectSettings->DisplayName, s_quickconnect) != 0)
        WritePrivateProfileString(ConnectSettings->DisplayName, "utf8", hr ? "1" : "0", ConnectSettings->IniFileName);
    return hr;
}

static int SftpSessionDetectLineBreaks(pConnectSettings ConnectSettings)
{
    int hr = 0;
    char cmdname[MAX_PATH];
    char reply[8192];
    strlcpy(cmdname, "echo $OSTYPE", sizeof(cmdname)-1);
    reply[0] = 0;
    if (SftpQuoteCommand2(ConnectSettings, NULL, cmdname, reply, sizeof(reply)-1) == 0) {
        _strupr_s(reply, sizeof(reply));
        if (strstr(reply, "LINUX") || strstr(reply, "UNIX") || strstr(reply, "AIX")) {
            FIN(1);    /* FIXME: magic number! */
        }
        // look whether the returned data ends with LF or CRLF!
        global_detectcrlf = -1;
        strlcpy(cmdname, "ls -l", sizeof(cmdname)-1); // try to get some multi-line reply
        if (SftpQuoteCommand2(ConnectSettings, NULL, cmdname, reply, sizeof(reply)-1) == 0) {
            if (global_detectcrlf == 0)
                FIN(1);
        }
    }
    hr = 0;
fin:
    // store the result!
    if (strcmp(ConnectSettings->DisplayName, s_quickconnect) !=0 )
        WritePrivateProfileString(ConnectSettings->DisplayName, "unixlinebreaks", hr ? "1" : "0", ConnectSettings->IniFileName);
    return hr;
}

static int SftpSessionSendCommand(pConnectSettings ConnectSettings, LPCSTR progressbuf, int progress, int * ploop, SYSTICKS * plasttime)
{
    char buf[1024];
    strlcpy(buf, ConnectSettings->connectsendcommand, sizeof(buf)-1);
    LIBSSH2_CHANNEL * channel = ConnectChannel(ConnectSettings->session);
    /* FIXME: check channel for NULL */
    SftpLogLastError("ConnectChannel: ", libssh2_session_last_errno(ConnectSettings->session));
    if (ConnectSettings->sendcommandmode <= 1) {    /* FIXME: magic number */
        if (SendChannelCommand(ConnectSettings->session, channel, ConnectSettings->connectsendcommand)) {
            while (!libssh2_channel_eof(channel)) {
                if (ProgressLoop(buf, progress, progress + 10, ploop, plasttime))
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
                if (libssh2_channel_eof(channel))
                    break;
                if (0 < libssh2_channel_read(channel, databuf, sizeof(databuf)-1)) {
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
        return 0;
    }
    int rc = -1;
    do {
        rc = libssh2_channel_exec(channel, ConnectSettings->connectsendcommand);
        if (rc < 0) {
            if (rc == -1)
                rc = libssh2_session_last_errno(ConnectSettings->session);
            if (rc != LIBSSH2_ERROR_EAGAIN)
                break;
        }
        if (EscapePressed())
            break;
    } while (rc < 0);

    return 0;
}

int SftpConnect(pConnectSettings ConnectSettings)
{
    int hr = 0;
    if (!LoadSSHLib())
        return SFTP_FAILED;
    if (!loadAgent && ConnectSettings->useagent) {
        char buf[128], buf1[128];
        LoadStr(buf1, IDS_SSH2_TOO_OLD);
        sprintf_s(buf, countof(buf), buf1, LIBSSH2_VERSION);
        MessageBoxA(GetActiveWindow(), buf, "Error", MB_ICONSTOP);
        return SFTP_FAILED;
    }
    char buf[1024];
    char connecttoserver[250];
    char progressbuf[250];
    char* errmsg;
    int errmsg_len;

    int progress = 0;
    unsigned short connecttoport;
    struct addrinfo hints;
    bool connected = false;
    int auth, loop;
    int err;
    SYSTICKS lasttime = get_sys_ticks();

    if (ConnectSettings->session)
        return SFTP_OK;

    if (ConnectSettings->sftpsession)
        return -1;    /* fatal error */

    if (ConnectSettings->sock)
        return -2;    /* fatal error */

    if (ProgressProc(PluginNumber, "Connecting...", "-", progress))
        FIN(-9);

    switch (ConnectSettings->proxytype) {
    case sftp::Proxy::notused:
        strlcpy(connecttoserver, ConnectSettings->server, sizeof(connecttoserver)-1);
        connecttoport = ConnectSettings->customport;
        break;
    case sftp::Proxy::http: // HTTP connect
        if (!ParseAddress(ConnectSettings->proxyserver, &connecttoserver[0], &connecttoport, 8080)) {
            MessageBox(GetActiveWindow(), "Invalid proxy server address.", "SFTP Error", MB_ICONSTOP);
            FIN(-11);
        }
        break;
    case sftp::Proxy::socks4: // SOCKS4a
    case sftp::Proxy::socks5: // SOCKS5
        if (!ParseAddress(ConnectSettings->proxyserver, &connecttoserver[0],  &connecttoport, 1080)) {
            MessageBox(GetActiveWindow(), "Invalid proxy server address.", "SFTP Error", MB_ICONSTOP);
            FIN(-12);
        }
        break;
    default:
        MessageBox(GetActiveWindow(), "Function not supported yet!", "SFTP Error", MB_ICONSTOP);
        FIN(-13);
    }
    ShowStatus(" ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  == ");
    ShowStatusId(IDS_CONNECT_TO, ConnectSettings->server, true);

    progress = 20;   /* FIXME: magic number! */
    {
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
        sprintf_s(buf, sizeof(buf), "%d", connecttoport);
        struct addrinfo * res = NULL;
        if (getaddrinfo(connecttoserver, buf, &hints, &res) != 0) {
            ShowErrorId(IDS_ERR_GETADDRINFO);
            FIN(-20);
        }
        ConnectSettings->sock = INVALID_SOCKET;
        for (struct addrinfo * ai = res; ai; ai = ai->ai_next) {
            closesocket(ConnectSettings->sock);
            ConnectSettings->sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (ConnectSettings->sock == INVALID_SOCKET)
                continue;
            DWORD len = (DWORD)(sizeof(buf) - strlen(buf));
            strlcpy(buf, "IP address: ", sizeof(buf)-1);
            WSAAddressToString(ai->ai_addr, ai->ai_addrlen, NULL, buf + strlen(buf), &len);
            ShowStatus(buf);

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
                    if (ProgressLoop(buf, 0, progress, &loop, &lasttime))
                        break;
                }
            }
            if (connected)
                break;
        }
        freeaddrinfo(res);
    }

    if (!connected) {
        if (ConnectSettings->proxytype != sftp::Proxy::notused)
            ShowErrorId(IDS_ERR_PROXYCONNECT);
        else
            ShowErrorId(IDS_ERR_SERVERCONNECT);
        FIN(-30);
    }

    // **********************************************************
    //  Proxy?
    if (ConnectSettings->proxytype != sftp::Proxy::notused) {
        progress = 20;   /* FIXME: magic number! */
        LoadStr(progressbuf, IDS_PROXY_CONNECT);
        if (ProgressProc(PluginNumber, progressbuf, "-", progress))
            FIN(-40);
        hr = 0;
        switch (ConnectSettings->proxytype) {
        case sftp::Proxy::http: // HTTP CONNECT
            hr = SftpConnectProxyHttp(ConnectSettings, progressbuf, progress, &loop, &lasttime);
            FIN_IF(hr, -12040 - hr);
            break;
        case sftp::Proxy::socks4: // SOCKS4 / SOCKS4A
            hr = SftpConnectProxySocks4(ConnectSettings, progressbuf, progress, &loop, &lasttime);
            FIN_IF(hr, -13040 - hr);
            break;
        case sftp::Proxy::socks5:  // SOCKS5
            hr = SftpConnectProxySocks5(ConnectSettings, connecttoport, progressbuf, progress, &loop, &lasttime);
            FIN_IF(hr, -14040 - hr);
            break;
        }
    }

    progress = 30;    /* FIXME: magic number! */
    LoadStr(buf, IDS_INITSSH2);
    if (ProgressProc(PluginNumber, buf, "-", progress))
        FIN(-50);

    ConnectSettings->session = libssh2_session_init_ex(myalloc, myfree, myrealloc, ConnectSettings);
    if (!ConnectSettings->session) {
        SftpLogLastError("libssh2_session_init_ex: ", libssh2_session_last_errno(ConnectSettings->session));
        ShowErrorId(IDS_ERR_INIT_SSH2);
        FIN(-60);
    }
    /* Since we have set non-blocking, tell libssh2 we are non-blocking */
    libssh2_session_set_blocking(ConnectSettings->session, 0);

    // Set ZLIB compression on/off
    // Always allow "none" for the case that the server doesn't support compression
    loop = 30;
    LoadStr(buf, IDS_SET_COMPRESSION);
    LPCSTR ses_prefs = ConnectSettings->compressed ? "zlib,none" : "none";
 
    while ((err = libssh2_session_method_pref(ConnectSettings->session, LIBSSH2_METHOD_COMP_CS, ses_prefs)) == LIBSSH2_ERROR_EAGAIN) {
        if (ProgressLoop(buf, progress, progress + 10, &loop, &lasttime))
            break;
        IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
    }
    SftpLogLastError("libssh2_session_method_pref: ", err);

    while ((err = libssh2_session_method_pref(ConnectSettings->session, LIBSSH2_METHOD_COMP_SC, ses_prefs)) == LIBSSH2_ERROR_EAGAIN) {
        if (ProgressLoop(buf, progress, progress + 10, &loop, &lasttime))
            break;
        IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
    }
    SftpLogLastError("libssh2_session_method_pref2: ", err);

    /* ... start it up. This will trade welcome banners, exchange keys, and setup crypto, compression, and MAC layers */
    progress = 40;    /* FIXME: magic number! */
    LoadStr(buf, IDS_SESSION_STARTUP);
    while ((auth = libssh2_session_startup(ConnectSettings->session, (int)ConnectSettings->sock)) == LIBSSH2_ERROR_EAGAIN) {
        if (ProgressLoop(buf, progress, progress + 20, &loop, &lasttime))
            break;
        IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
    } 

    if (auth) {
        libssh2_session_last_error(ConnectSettings->session, &errmsg, &errmsg_len, false);
        ShowErrorId(IDS_ERR_SSH_SESSION, errmsg);
        FIN(-70);
    }
    SftpLogLastError("libssh2_session_startup: ", libssh2_session_last_errno(ConnectSettings->session));

    progress = 60;    /* FIXME: magic number! */
    LoadStr(buf, IDS_SSH_LOGIN);
    if (ProgressProc(PluginNumber, buf, "-", progress))
        FIN(-80);

    LPCSTR fingerprint = libssh2_hostkey_hash(ConnectSettings->session, LIBSSH2_HOSTKEY_HASH_MD5);
    if (fingerprint == NULL) {
        SftpLogLastError("Fingerprint error: ", libssh2_session_last_errno(ConnectSettings->session));
        FIN(-90);
    }
    ShowStatusId(IDS_SERVER_FINGERPRINT, NULL, true);
    buf[0] = 0;
    for (size_t i = 0; i < 16; i++) {
        char buf1[20];
        sprintf_s(buf1, sizeof(buf1), "%02X", (UCHAR)fingerprint[i]);
        strlcat(buf, buf1, sizeof(buf)-1);
        if (i < 15)
            strlcat(buf, " ", sizeof(buf)-1);
    }
    ShowStatus(buf);

    // Verify server
    if (ConnectSettings->savedfingerprint[0] == 0 || strcmp(ConnectSettings->savedfingerprint, buf) != 0) {
        // a new server, or changed fingerprint
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
        if (!RequestProc(PluginNumber, RT_MsgYesNo, buf2, buf1, NULL, 0))
            FIN(-100);

        // Store it,  also for quick connections!
        WritePrivateProfileString(ConnectSettings->DisplayName, "fingerprint", buf, ConnectSettings->IniFileName);
        strlcpy(ConnectSettings->savedfingerprint, buf, sizeof(ConnectSettings->savedfingerprint)-1);
    }

    // Ask for user name if none was entered
    if (ConnectSettings->user[0] == 0) {
        char title[250];
        LoadStr(title, IDS_USERNAME_FOR);
        strlcat(title, ConnectSettings->server, sizeof(title)-1);
        if (!RequestProc(PluginNumber, RT_UserName, title, NULL, ConnectSettings->user, sizeof(ConnectSettings->user)-1))
            FIN(-110);
    }

    progress = 60;    /* FIXME: magic number! */
    char* userauthlist;
    do {
        userauthlist = libssh2_userauth_list(ConnectSettings->session, ConnectSettings->user, (UINT)strlen(ConnectSettings->user));
        LoadStr(buf, IDS_USER_AUTH_LIST);
        if (ProgressLoop(buf, progress, progress + 10, &loop, &lasttime))
            break;
    } while (userauthlist == NULL && libssh2_session_last_errno(ConnectSettings->session) == LIBSSH2_ERROR_EAGAIN);

    int auth_pw = 0;
    if (userauthlist) {
        ShowStatusId(IDS_SUPPORTED_AUTH_METHODS, userauthlist, true);
        _strlwr_s(userauthlist, strlen(userauthlist) + 1);
        if (strstr(userauthlist, "password")) {
            auth_pw |= SSH_AUTH_PASSWORD;
        }
        if (strstr(userauthlist,  "keyboard-interactive")) {
            auth_pw |= SSH_AUTH_KEYBOARD;
        }
        if (strstr(userauthlist,  "publickey")) {
            auth_pw |= SSH_AUTH_PUBKEY;
        } 
    } else {
        SftpLogLastError("libssh2_userauth_list: ", libssh2_session_last_errno(ConnectSettings->session));
        auth_pw = SSH_AUTH_PASSWORD | SSH_AUTH_PUBKEY;   // assume password+pubkey allowed
    }

    auth = 0;
    if (libssh2_userauth_authenticated(ConnectSettings->session)) {
        ShowStatus("User authenticated without password.");
    } else if ((auth_pw & SSH_AUTH_PUBKEY) && ConnectSettings->useagent && loadAgent) {
        progress = 65;
        int rc = SftpAuthPageant(ConnectSettings, progressbuf, progress, &loop, &lasttime, &auth_pw);
        auth = (rc < 0) ? LIBSSH2_ERROR_AGENT_PROTOCOL : 0;
    } else if ((auth_pw & SSH_AUTH_PUBKEY) && ConnectSettings->pubkeyfile[0] && ConnectSettings->privkeyfile[0]) {
        int rc = SftpAuthPubKey(ConnectSettings, progressbuf, progress, &loop, &lasttime, &auth_pw);
        auth = (rc < 0) ? LIBSSH2_ERROR_FILE : 0;
    } else {
        auth_pw &= ~SSH_AUTH_PUBKEY;
    }

    progress = 70;    /* FIXME: magic number! */
    if ((auth_pw & SSH_AUTH_PUBKEY) == 0) {
        if (auth_pw & SSH_AUTH_KEYBOARD) {   // keyboard-interactive
            ShowStatusId(IDS_AUTH_KEYBDINT_FOR, ConnectSettings->user, true);
            LoadStr(buf, IDS_AUTH_KEYBDINT);
            pConnectSettings cs = ConnectSettings;
            cs->InteractivePasswordSent = false;
            while ((auth = libssh2_userauth_keyboard_interactive(cs->session, cs->user, &kbd_callback)) == LIBSSH2_ERROR_EAGAIN) {
                if (ProgressLoop(buf, progress, progress + 10, &loop, &lasttime))
                    break;
                IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
            }
            if (auth) {
                SftpLogLastError("libssh2_userauth_keyboard_interactive: ", auth);
                if ((auth_pw & SSH_AUTH_PASSWORD) == 0)  // only show error if password auth isn't supported - otherwise try that
                    ShowErrorId(IDS_ERR_AUTH_KEYBDINT);
            }
        } else {
            auth = LIBSSH2_ERROR_INVAL;
        }
        if (auth != 0 && (auth_pw & SSH_AUTH_PASSWORD) != 0) {
            char passphrase[256];

            char* p = strstr(ConnectSettings->password, "\",\"");
            size_t len = strlen(ConnectSettings->password);
            if (p && ConnectSettings->password[0] == '"' && ConnectSettings->password[len-1] == '"') {
                // two passwords -> use second one!
                ConnectSettings->password[len-1] = 0;
                strlcpy(passphrase, p + 3, sizeof(passphrase)-1);
                ConnectSettings->password[len-1] = '"';
            } else {
                strlcpy(passphrase, ConnectSettings->password, sizeof(passphrase)-1);
            }
            if (passphrase[0] == 0) {
                char title[250];
                strlcpy(title, "SFTP password for ", sizeof(title)-1);
                strlcat(title, ConnectSettings->user, sizeof(title)-1);
                strlcat(title, "@", sizeof(title)-1);
                strlcat(title, ConnectSettings->server, sizeof(title)-1);
                RequestProc(PluginNumber, RT_Password, title, NULL, passphrase, sizeof(passphrase)-1);
            }
 
            ShowStatusId(IDS_AUTH_PASSWORD_FOR, ConnectSettings->user, true);

            LoadStr(buf, IDS_AUTH_PASSWORD);
            /* We could authenticate via password */
            while(1) {
                auth = libssh2_userauth_password_ex(ConnectSettings->session, ConnectSettings->user, strlen(ConnectSettings->user), passphrase, strlen(passphrase), &newpassfunc);
                if (auth != LIBSSH2_ERROR_EAGAIN && auth != LIBSSH2_ERROR_PASSWORD_EXPIRED)
                    break;
                if (ProgressLoop(buf, progress, progress + 10, &loop, &lasttime))
                    break;
                IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
            }
            if (auth) {
                SftpLogLastError("libssh2_userauth_password_ex: ", auth);
                ShowErrorId(IDS_ERR_AUTH_PASSWORD);
            }
            else if (!ConnectSettings->password[0])
                strlcpy(ConnectSettings->password, passphrase, sizeof(ConnectSettings->password)-1);
        }
    } 

    FIN_IF(auth, SFTP_FAILED);

    // try to auto-detect UTF-8 settings
    if (ConnectSettings->utf8names == -1) {    /* FIXME: magic number! */
        ConnectSettings->codepage = 0;
        ConnectSettings->utf8names = 0;
        int rc = SftpSessionDetectUtf8(ConnectSettings);
        ConnectSettings->utf8names = (rc == 1) ? 1 : 0;   /* FIXME: magic number! */
    }
    if (ConnectSettings->unixlinebreaks == -1) {    /* FIXME: magic number! */
        ConnectSettings->unixlinebreaks = 0;
        int rc = SftpSessionDetectLineBreaks(ConnectSettings);
        ConnectSettings->unixlinebreaks = (rc == 1) ? 1 : 0;   /* FIXME: magic number! */
    }

    progress = 80;    /* FIXME: magic number! */

    // Send user-defined command line
    if (ConnectSettings->connectsendcommand[0]) {
        ShowStatus("Sending user-defined command:");
        ShowStatus(ConnectSettings->connectsendcommand);
        SftpSessionSendCommand(ConnectSettings, progressbuf, progress, &loop, &lasttime);
        Sleep(1000);
    }

    if (ConnectSettings->scpfordata && ConnectSettings->scpserver64bit == -1) {      /* FIXME: magic number! */
        ConnectSettings->scpserver64bit = 0;
        char cmdname[MAX_PATH];
        char reply[8192];
        strlcpy(cmdname, "file `which scp`", sizeof(cmdname)-1);
        reply[0] = 0;
        if (SftpQuoteCommand2(ConnectSettings, NULL, cmdname, reply, sizeof(reply)-1) == 0) {
            _strupr_s(reply, sizeof(reply));
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

    progress = 80;    /* FIXME: magic number! */

    if (!ConnectSettings->scponly) {
        ShowStatusId(IDS_SESSION_STARTUP, " (SFTP)", true);
        do {
            ConnectSettings->sftpsession = NULL;
            if (ProgressLoop(buf, progress, progress + 10, &loop, &lasttime))
                break;
            ConnectSettings->sftpsession = libssh2_sftp_init(ConnectSettings->session);
            if (!ConnectSettings->sftpsession) {
                if (libssh2_session_last_errno(ConnectSettings->session) != LIBSSH2_ERROR_EAGAIN)
                    break;
            }
            IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
        } while (!ConnectSettings->sftpsession);

        if (!ConnectSettings->sftpsession){
            libssh2_session_last_error(ConnectSettings->session, &errmsg, &errmsg_len, false);
            ShowStatusId(IDS_ERR_INIT_SFTP, errmsg, true);
            FIN(SFTP_FAILED);
        }

        // Seems that we need to set it again,  so the sftpsession is informed too!
        // Otherwise disconnect hangs with CoreFTP mini-sftp-server in libssh2_sftp_shutdown
        libssh2_session_set_blocking(ConnectSettings->session, 0);
    }

    progress = 90;    /* FIXME: magic number! */

    LoadStr(buf, IDS_GET_DIRECTORY);
    if (ProgressProc(PluginNumber, buf, "-", progress))
        FIN(SFTP_FAILED);

    return SFTP_OK;
    
fin:    
    if (hr) {
        LoadStr(buf, IDS_DISCONNECTING);
        int rc;
        if (ConnectSettings->sftpsession) {
            do {
                rc = libssh2_sftp_shutdown(ConnectSettings->sftpsession);
                if (ProgressLoop(buf, progress, 90, &loop, &lasttime))
                    break;
                IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
            } while (rc == LIBSSH2_ERROR_EAGAIN);
            ConnectSettings->sftpsession = NULL;
            progress = 90;
        }
        if (ConnectSettings->session) {
            int rc;
            do {
                rc = libssh2_session_disconnect(ConnectSettings->session, "Shutdown");
                if (ProgressLoop(buf, progress, 100, &loop, &lasttime))
                    break;
                IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
            } while (rc == LIBSSH2_ERROR_EAGAIN);
            libssh2_session_free(ConnectSettings->session); 
            ConnectSettings->session = NULL;
        }
        Sleep(1000);    /* FIXME: ?????????? */
        if (ConnectSettings->sock) {
            closesocket(ConnectSettings->sock); 
            ConnectSettings->sock = 0;
        }
    }
    return hr;
}

const char g_pszKey[] = "unpzScGeCInX7XcRM2z+svTK+gegRLhz9KXVbYKJl5boSvVCcfym";

void EncryptString(LPCSTR pszPlain, LPSTR pszEncrypted, size_t cchEncrypted)
{
    const size_t iPlainLength = lstrlen(pszPlain);
    const size_t iKeyLength = sizeof(g_pszKey);
    const size_t iPos = lstrlen(pszPlain) % iKeyLength;

    pszEncrypted[0] = '\0';
    
    for (size_t iChar = 0; iChar < iPlainLength; iChar++) {
        int num = (BYTE)pszPlain[iChar] ^ (BYTE)g_pszKey[(iChar + iPos) % iKeyLength];
        sprintf_s(pszEncrypted, cchEncrypted, ("%s%03d"), pszEncrypted, num);
    }
}

void DecryptString(LPCSTR pszEncrypted, LPSTR pszPlain, size_t cchPlain)
{
    int hr = 0;
    if (strcmp(pszEncrypted, "!") == 0) {   // signal password-protected password
        if (CryptProc)
            strlcpy(pszPlain, "\001", cchPlain-1);
        else
            pszPlain[0] = 0;
        return;
    }
    const size_t iKeyLength = sizeof(g_pszKey);
    const size_t iEncryptedLength = lstrlen(pszEncrypted);
    const size_t iPos = (iEncryptedLength / 3) % iKeyLength;
    size_t iChar;

    pszPlain[0] = ('\0');

    for (iChar = 0; iChar < iEncryptedLength / 3 && iChar < cchPlain - 1; iChar++) {
        int iDigit = pszEncrypted[iChar * 3];
        FIN_IF(iDigit < '0' || iDigit > '9', -1);
        int iNumber = (iDigit - '0') * 100;

        iDigit = pszEncrypted[iChar * 3 + 1];
        FIN_IF(iDigit < '0' || iDigit > '9', -1);
        iNumber += (iDigit - '0') * 10;

        iDigit = pszEncrypted[iChar * 3 + 2];
        FIN_IF(iDigit < '0' || iDigit > '9', -1);
        iNumber += iDigit - '0';
        
        pszPlain[iChar] = ((char)iNumber ^ g_pszKey[(iChar + iPos) % iKeyLength]);
    }
    pszPlain[iChar] = '\0';
    return;
fin:
    pszPlain[0] = '\0';
}

void SftpGetServerBasePathW(LPCWSTR DisplayName, LPWSTR RelativePath, size_t maxlen, LPCSTR inifilename)
{
    char DisplayNameA[MAX_PATH], server[MAX_PATH];
    walcopy(DisplayNameA, DisplayName, countof(DisplayNameA)-1);
    GetPrivateProfileString(DisplayNameA, "server", "", server, countof(server)-1, inifilename);
    ReplaceBackslashBySlash(server);
    // Remove trailing sftp://
    if (_strnicmp(server, "sftp://", 7) == 0)
        memmove(server, server+7, strlen(server)-6);
    ReplaceBackslashBySlash(server);
    LPSTR p = strchr(server, '/');
    if (p)
        awlcopy(RelativePath, p, maxlen);
    else
        wcslcpy(RelativePath, L"/", maxlen);
}

static bool LoadProxySettingsFromNr(int proxynr, pConnectSettings ConnectResults)
{
    ConnectResults->proxytype = sftp::Proxy::notused;
    ConnectResults->proxyserver[0] = 0;
    ConnectResults->proxyuser[0] = 0;
    ConnectResults->proxypassword[0] = 0;
    if (proxynr <= 0)
        return false;

    CHAR proxyentry[64];
    if (proxynr > 1)
        sprintf_s(proxyentry, sizeof(proxyentry), "proxy%d", proxynr);
    else
        strlcpy(proxyentry, "proxy", sizeof(proxyentry)-1);
    ConnectResults->proxytype = sftp::Proxy::notused;
    int type = GetPrivateProfileInt(proxyentry, "proxytype", -1, gIniFileName);
    if (type >= 0)
        ConnectResults->proxytype = (sftp::Proxy)type;
    GetPrivateProfileString(proxyentry, "proxyserver", "", ConnectResults->proxyserver, countof(ConnectResults->proxyuser)-1, gIniFileName);
    GetPrivateProfileString(proxyentry, "proxyuser", "", ConnectResults->proxyuser, countof(ConnectResults->proxyuser)-1, gIniFileName);
    char szPassword[MAX_PATH];
    if (GetPrivateProfileString(proxyentry, "proxypassword", "", szPassword, countof(szPassword), gIniFileName)) {
        DecryptString(szPassword,  ConnectResults->proxypassword, countof(ConnectResults->proxypassword));
    }            
    return (type != -1 || proxynr == 1);   // nr 1 is always valid
}

static bool LoadServerSettings(LPCSTR DisplayName, pConnectSettings ConnectResults)
{
    char szPassword[MAX_PATH], modbuf[6];
    strlcpy(ConnectResults->DisplayName, DisplayName, sizeof(ConnectResults->DisplayName)-1);
    strlcpy(ConnectResults->IniFileName, gIniFileName, sizeof(ConnectResults->IniFileName)-1);
    GetPrivateProfileString(DisplayName, "server", "", ConnectResults->server, sizeof(ConnectResults->server)-1, gIniFileName);
    ConnectResults->protocoltype = GetPrivateProfileInt(DisplayName, "protocol", 0, gIniFileName);
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
    if (GetPrivateProfileString(gDisplayName, "password", "", szPassword, countof(szPassword), gIniFileName)) {
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

static void EnableControlsPageant(HWND hWnd, bool enable)
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

static bool GetDialogPosition(HWND hWnd, POINT * pos)
{
    RECT rt1, rt2;
    if (GetWindowRect(hWnd, &rt1) && GetWindowRect(GetParent(hWnd), &rt2)) {
        int w = rt2.right  - rt2.left;
        int h = rt2.bottom - rt2.top;
        int DlgWidth   = rt1.right  - rt1.left;
        int DlgHeight  = rt1.bottom - rt1.top;
        pos->x = rt2.left + (w - DlgWidth)/2;
        pos->y = rt2.top  + (h - DlgHeight)/2;
        return true;
    }
    return false;
}

static bool SetDialogPosToCenter(HWND hWnd, DWORD dwFlags = SWP_NOZORDER | SWP_NOSIZE)
{
    POINT pos;
    if (!GetDialogPosition(hWnd, &pos))
        return false;
    BOOL x = SetWindowPos(hWnd, 0, pos.x, pos.y, 0, 0, dwFlags);
    return !!x;
}

int gProxyNr = 0;

INT_PTR WINAPI ProxyDlgProc(HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam)
{
    int hr = 0;
    tConnectSettings * ConnectData = (tConnectSettings *)calloc(1, sizeof(tConnectSettings));
    FIN_IF(!ConnectData, 0);

    switch (Message) {
    case WM_INITDIALOG: {
        LoadProxySettingsFromNr(gProxyNr, ConnectData);

        switch (ConnectData->proxytype) {
        case sftp::Proxy::http:   g_focusset = IDC_OTHERPROXY; break;
        case sftp::Proxy::socks4: g_focusset = IDC_SOCKS4APROXY; break;
        case sftp::Proxy::socks5: g_focusset = IDC_SOCKS5PROXY; break;
        default: g_focusset = IDC_NOPROXY;
        }
        CheckRadioButton(hWnd, IDC_NOPROXY, IDC_SOCKS5PROXY, g_focusset);

        BOOL showProxySettings = (ConnectData->proxytype != sftp::Proxy::notused);
        EnableWindow(GetDlgItem(hWnd, IDC_PROXYSERVER), showProxySettings);
        EnableWindow(GetDlgItem(hWnd, IDC_PROXYUSERNAME), showProxySettings);
        EnableWindow(GetDlgItem(hWnd, IDC_PROXYPASSWORD), showProxySettings);
        SetDlgItemText(hWnd, IDC_PROXYSERVER, ConnectData->proxyserver);
        SetDlgItemText(hWnd, IDC_PROXYUSERNAME, ConnectData->proxyuser);

        if (strcmp(ConnectData->proxypassword, "\001") == 0 && CryptProc) {
            char proxyentry[64];
            if (gProxyNr > 1)
                sprintf_s(proxyentry, sizeof(proxyentry), "proxy%d", gProxyNr);
            else
                strlcpy(proxyentry, "proxy", sizeof(proxyentry)-1);

            strlcat(proxyentry, "$$pass", sizeof(proxyentry)-1);

            int rc = CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_LOAD_PASSWORD_NO_UI, proxyentry, ConnectData->proxypassword, countof(ConnectData->proxypassword) - 1);
            if (rc == FS_FILE_OK) {
                SetDlgItemText(hWnd, IDC_PROXYPASSWORD, ConnectData->proxypassword);
                CheckDlgButton(hWnd, IDC_CRYPTPASS, BST_CHECKED);
            } else {
                ShowWindow(GetDlgItem(hWnd, IDC_PROXYPASSWORD), SW_HIDE);
                ShowWindow(GetDlgItem(hWnd, IDC_CRYPTPASS), SW_HIDE);
                ShowWindow(GetDlgItem(hWnd, IDC_EDITPASS), SW_SHOW);
            }
        } else {
            SetDlgItemText(hWnd, IDC_PROXYPASSWORD, ConnectData->proxypassword);
            if (!CryptProc)
                EnableWindow(GetDlgItem(hWnd, IDC_CRYPTPASS), FALSE);
            else if (ConnectData->proxypassword[0] == 0 && CryptCheckPass)
                CheckDlgButton(hWnd, IDC_CRYPTPASS, BST_CHECKED);
        }
        
        // trying to center the About dialog
        SetDialogPosToCenter(hWnd);
        FIN(1);
    }
    case WM_SHOWWINDOW: {
        if (g_focusset)
            SetFocus(GetDlgItem(hWnd, g_focusset));
        break;
    }
    case WM_COMMAND: {
        switch (LOWORD(wParam)) {
        case IDOK: {
            ConnectData->proxytype = sftp::Proxy::notused;
            if (IsDlgButtonChecked(hWnd, IDC_OTHERPROXY))
                ConnectData->proxytype = sftp::Proxy::http;
            else if (IsDlgButtonChecked(hWnd, IDC_SOCKS4APROXY))
                ConnectData->proxytype = sftp::Proxy::socks4;
            else if (IsDlgButtonChecked(hWnd, IDC_SOCKS5PROXY))
                ConnectData->proxytype = sftp::Proxy::socks5;

            GetDlgItemText(hWnd, IDC_PROXYSERVER, ConnectData->proxyserver, sizeof(ConnectData->proxyserver)-1);
            GetDlgItemText(hWnd, IDC_PROXYUSERNAME, ConnectData->proxyuser, sizeof(ConnectData->proxyuser)-1);
            GetDlgItemText(hWnd, IDC_PROXYPASSWORD, ConnectData->proxypassword, sizeof(ConnectData->proxypassword)-1);

            char proxyentry[64];
            if (gProxyNr > 1)
                sprintf_s(proxyentry, sizeof(proxyentry), "proxy%d", gProxyNr);
            else
                strlcpy(proxyentry, "proxy", sizeof(proxyentry)-1);

            WritePrivateProfileString(proxyentry, "proxyserver", ConnectData->proxyserver, gIniFileName);
            WritePrivateProfileString(proxyentry, "proxyuser", ConnectData->proxyuser, gIniFileName);
            char buf[64];
            _itoa_s((int)ConnectData->proxytype, buf, sizeof(buf), 10);
            LPSTR proxy_str = (ConnectData->proxytype == sftp::Proxy::notused) ? NULL : buf;
            WritePrivateProfileString(proxyentry, "proxytype", proxy_str, gIniFileName);

            char szEncryptedPassword[256];
            if (!IsWindowVisible(GetDlgItem(hWnd, IDC_EDITPASS))) {  //button not visible
                if (ConnectData->proxypassword[0] == 0) {
                    WritePrivateProfileString(proxyentry, "proxypassword", NULL, gIniFileName);
                } else if (CryptProc && IsDlgButtonChecked(hWnd, IDC_CRYPTPASS)) {
                    char proxyentry2[64];
                    strlcpy(proxyentry2, proxyentry, sizeof(proxyentry2)-1);
                    strlcat(proxyentry2, "$$pass", sizeof(proxyentry2)-1);
                    bool ok = CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_SAVE_PASSWORD, proxyentry2, ConnectData->proxypassword, 0) == FS_FILE_OK;
                    WritePrivateProfileString(proxyentry, "proxypassword", ok? "!" : NULL, gIniFileName);
                    CryptCheckPass = true;
                } else {
                    EncryptString(ConnectData->proxypassword, szEncryptedPassword, countof(szEncryptedPassword));
                    WritePrivateProfileString(proxyentry, "proxypassword", szEncryptedPassword, gIniFileName);
                }
            }
            
            EndDialog(hWnd, IDOK);
            FIN(1);
        }
        case IDCANCEL:
        {
            EndDialog(hWnd, IDCANCEL);
            FIN(1);
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
            CHAR szCaption[100];
            LoadString(hinst, IDS_HELP_CAPTION, szCaption, countof(szCaption));
            CHAR szBuffer[1024];
            LoadString(hinst, IDS_HELP_PROXY, szBuffer, countof(szBuffer));
            MessageBox(hWnd, szBuffer, szCaption, MB_OK | MB_ICONINFORMATION);
            break;
        }
        case IDC_EDITPASS:
        {   
            bool doshow = true;
            CHAR proxyentry[64];
            if (gProxyNr > 1)
                sprintf_s(proxyentry, sizeof(proxyentry), "proxy%d", gProxyNr);
            else
                strlcpy(proxyentry, "proxy", sizeof(proxyentry)-1);

            strlcat(proxyentry, "$$pass", sizeof(proxyentry)-1);

            int rc = CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_LOAD_PASSWORD, proxyentry, ConnectData->proxypassword, countof(ConnectData->proxypassword)-1);
            if (rc == FS_FILE_OK || rc == FS_FILE_READERROR) {
                LPCSTR txt = (rc == FS_FILE_OK) ? gConnectResults->proxypassword : "";
                SetDlgItemText(hWnd, IDC_PROXYPASSWORD, txt);
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
    hr = 0;
fin:
    if (ConnectData)
        free(ConnectData);
    return hr;
}

void fillProxyCombobox(HWND hWnd, int defproxynr)
{
    int hr = 0;
    tConnectSettings * connectData = NULL;
    SendDlgItemMessage(hWnd, IDC_PROXYCOMBO, CB_RESETCONTENT, 0, 0);
    CHAR noproxy[100], addproxy[100], httpproxy[100], buf[256];
    LoadString(hinst, IDS_NO_PROXY,   noproxy,   countof(noproxy));
    LoadString(hinst, IDS_HTTP_PROXY, httpproxy, countof(httpproxy));
    LoadString(hinst, IDS_ADD_PROXY,  addproxy,  countof(addproxy));
    
    SendDlgItemMessage(hWnd, IDC_PROXYCOMBO, CB_ADDSTRING, 0, (LPARAM)&noproxy);
    
    connectData = (tConnectSettings *)calloc(1, sizeof(tConnectSettings));
    FIN_IF(!connectData, -1);

    int proxynr = 1;
    while (LoadProxySettingsFromNr(proxynr++, connectData)) {
        sprintf_s(buf, sizeof(buf), "%d: ", proxynr);
        switch (connectData->proxytype) {
        case sftp::Proxy::notused:
            strlcat(buf, noproxy, sizeof(buf)-1);
            break;
        case sftp::Proxy::http:
            strlcat(buf, httpproxy, sizeof(buf)-1);
            break;
        case sftp::Proxy::socks4:
            strlcat(buf, "SOCKS4a: ", sizeof(buf)-1);
            break;
        case sftp::Proxy::socks5:
            strlcat(buf, "SOCKS5: ", sizeof(buf)-1);
            break;
        }
        if (connectData->proxytype != sftp::Proxy::notused)
            strlcat(buf, connectData->proxyserver, sizeof(buf)-1);
        SendDlgItemMessage(hWnd, IDC_PROXYCOMBO, CB_ADDSTRING, 0, (LPARAM)buf);
    }
    SendDlgItemMessage(hWnd, IDC_PROXYCOMBO, CB_ADDSTRING, 0, (LPARAM)addproxy);
    if (defproxynr >= 0 && defproxynr <= proxynr)
        SendDlgItemMessage(hWnd, IDC_PROXYCOMBO, CB_SETCURSEL, defproxynr, 0);
fin:
    if (connectData)
        free(connectData);
}

bool DeleteLastProxy(int proxynrtodelete, LPCSTR ServerToSkip, LPSTR AppendToList, size_t maxlen)
{
    if (proxynrtodelete <= 1)
        return false;

    bool CanDelete = true;
    bool AlreadyAdded = false;
    char name[wdirtypemax];
    for (SERVERHANDLE hdl = FindFirstServer(name, sizeof(name)-1); hdl; hdl = FindNextServer(hdl, name, sizeof(name)-1)) {
        if (_stricmp(name, ServerToSkip) != 0) {
            int proxynr = GetPrivateProfileInt(name, "proxynr", 1, gIniFileName);
            if (proxynr == proxynrtodelete) {
                CanDelete = false;
                if (AlreadyAdded)
                    strlcat(AppendToList, ",", maxlen);
                strlcat(AppendToList, name, maxlen);
                AlreadyAdded = true;
            }
        }
    }
    if (CanDelete) {
        char proxyentry[64];
        sprintf_s(proxyentry, sizeof(proxyentry), "proxy%d", proxynrtodelete);
        WritePrivateProfileString(proxyentry, NULL, NULL, gIniFileName);
    }
    return CanDelete;
}

static int ConnectDlgCommand(HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam) noexcept;

// SR: 09.07.2005
INT_PTR WINAPI ConnectDlgProc(HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam)
{
    int hr = 0;
    char modbuf[32], strbuf[MAX_PATH];

    switch (Message) {
    case WM_INITDIALOG: {
        SendDlgItemMessage(hWnd, IDC_DEFAULTCOMBO, CB_SETCURSEL, 0, 0);
        serverfieldchangedbyuser = false;

        LoadStr(strbuf, IDS_AUTO);
        SendDlgItemMessage(hWnd, IDC_UTF8, CB_ADDSTRING, 0, (LPARAM)&strbuf);
        for (int i = IDS_UTF8; i <= IDS_OTHER; i++) {
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
            case 1:  CheckRadioButton(hWnd, IDC_PROTOAUTO, IDC_PROTOV6, IDC_PROTOV4); break;   /* FIXME: magic number! */
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

            int cbline = 0;
            switch (gConnectResults->utf8names) {
            case -1: cbline = 0; break;  // auto-detect     /* FIXME: magic number! */
            case  1: cbline = 1; break;
            default:
                cbline = 0;
                int cp = gConnectResults->codepage;
                for (int i = 0; i < countof(codepagelist); i++)
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

        g_focusset = IDC_CONNECTTO;
        if (strcmp(gDisplayName, s_quickconnect) != 0) {
            if (gConnectResults->server[0] == 0)
                g_focusset = IDC_CONNECTTO;
            else if (gConnectResults->user[0] == 0)
                g_focusset = IDC_USERNAME;
            else
                g_focusset = IDC_PASSWORD;
        }            

        // trying to center the About dialog
        SetDialogPosToCenter(hWnd);

        // SR: 11.07.2005
        serverfieldchangedbyuser = false;

        FIN(1);
        break;
    }
    case WM_SHOWWINDOW: {
        if (g_focusset)
            SetFocus(GetDlgItem(hWnd, g_focusset));
        break;
    }
    case WM_COMMAND: {
        hr = ConnectDlgCommand(hWnd, Message, wParam, lParam);
        FIN(hr);
    }
    }
    hr = 0;
fin:
    return hr;
}

static int ConnectDlgCommand(HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam) noexcept
{
    int hr = 0;
    char modbuf[32], strbuf[MAX_PATH];

    switch (LOWORD(wParam)) {
    case IDOK: {
        GetDlgItemText(hWnd, IDC_CONNECTTO, gConnectResults->server, sizeof(gConnectResults->server)-1);
        GetDlgItemText(hWnd, IDC_USERNAME, gConnectResults->user, sizeof(gConnectResults->user)-1);
        GetDlgItemText(hWnd, IDC_PASSWORD, gConnectResults->password, sizeof(gConnectResults->password)-1);
        if (IsDlgButtonChecked(hWnd, IDC_PROTOV4))
            gConnectResults->protocoltype = 1;      /* FIXME: magic number! */
        else if (IsDlgButtonChecked(hWnd, IDC_PROTOV6))
            gConnectResults->protocoltype = 2;
        else
            gConnectResults->protocoltype = 0;

        GetDlgItemText(hWnd, IDC_PUBKEY, gConnectResults->pubkeyfile, sizeof(gConnectResults->pubkeyfile)-1);
        GetDlgItemText(hWnd, IDC_PRIVKEY, gConnectResults->privkeyfile, sizeof(gConnectResults->privkeyfile)-1);
        gConnectResults->useagent = IsDlgButtonChecked(hWnd, IDC_USEAGENT) == BST_CHECKED;
        gConnectResults->detailedlog = IsDlgButtonChecked(hWnd, IDC_DETAILED_LOG) == BST_CHECKED;
        gConnectResults->compressed = IsDlgButtonChecked(hWnd, IDC_COMPRESS) == BST_CHECKED;
        gConnectResults->scpfordata = IsDlgButtonChecked(hWnd, IDC_SCP_DATA) == BST_CHECKED;
        gConnectResults->scponly = IsDlgButtonChecked(hWnd, IDC_SCP_ALL) == BST_CHECKED;

        gConnectResults->keepAliveIntervalSeconds = 0;
        if (IsDlgButtonChecked(hWnd, IDC_KEEP_ALIVE)) {
            GetDlgItemText(hWnd, IDC_KEEP_ALIVE_SECONDS, modbuf, sizeof(modbuf)-1);
            gConnectResults->keepAliveIntervalSeconds = atoi(modbuf);
        }

        int cp = 0;
        int cbline = (char)SendDlgItemMessage(hWnd, IDC_UTF8, CB_GETCURSEL, 0, 0);
        switch (cbline) {
        case 0: gConnectResults->utf8names = -1; break;  // auto-detect
        case 1: gConnectResults->utf8names = 1; break;   /* FIXME: magic number! */
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
            gConnectResults->filemod = 0644;      /* FIXME: magic number! */
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
                CHAR szEncryptedPassword[MAX_PATH];
                if (!IsWindowVisible(GetDlgItem(hWnd, IDC_EDITPASS))) {
                    if (gConnectResults->password[0] == 0) {
                        WritePrivateProfileString(gDisplayName, "password", NULL, gIniFileName);
                    } else if (CryptProc && IsDlgButtonChecked(hWnd, IDC_CRYPTPASS)) {
                        bool ok = CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_SAVE_PASSWORD, gDisplayName, gConnectResults->password, 0) == FS_FILE_OK;
                        WritePrivateProfileString(gDisplayName, "password", ok? "!" : NULL, gIniFileName);
                        CryptCheckPass = true;
                    } else {
                        EncryptString(gConnectResults->password, szEncryptedPassword, countof(szEncryptedPassword));
                        WritePrivateProfileString(gDisplayName, "password", szEncryptedPassword, gIniFileName);
                    }
                }
            }
        }
        gConnectResults->customport = 0;  // will be set later
        EndDialog(hWnd, IDOK);
        FIN(1);
    }
    case IDCANCEL:
    {
        // free serial number structures associated with each client certificate combo item
        int iCount = (int)SendDlgItemMessage(hWnd, IDC_CBO_CC, CB_GETCOUNT, (WPARAM)0, (LPARAM)0);

        EndDialog(hWnd, IDCANCEL);
        FIN(1);
    }
    case IDC_EDITPASS:
    {   
        int err = CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_LOAD_PASSWORD, gDisplayName, gConnectResults->password, countof(gConnectResults->password)-1);
        if (err == FS_FILE_OK || err == FS_FILE_READERROR) {
            LPCSTR txt = (err == FS_FILE_OK) ? gConnectResults->password : "";
            SetDlgItemText(hWnd, IDC_PASSWORD, txt);
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
        CHAR szCaption[100];
        LoadString(hinst,  IDS_HELP_CAPTION, szCaption, countof(szCaption));
        CHAR szBuffer[1024];
        LoadString(hinst,  IDS_HELP_CERT, szBuffer, countof(szBuffer));
        MessageBox(hWnd, szBuffer, szCaption, MB_OK | MB_ICONINFORMATION);
        break;
    }
    case IDC_PASSWORDHELP:
    {
        CHAR szCaption[100];
        LoadString(hinst, IDS_HELP_CAPTION, szCaption, countof(szCaption));
        CHAR szBuffer[1024];
        LoadString(hinst, IDS_HELP_PASSWORD, szBuffer, countof(szBuffer));
        MessageBox(hWnd, szBuffer, szCaption, MB_OK | MB_ICONINFORMATION);
        break;
    }
    case IDC_UTF8HELP: 
    {
        CHAR szCaption[100];
        LoadString(hinst, IDS_HELP_CAPTION, szCaption, countof(szCaption));
        CHAR szBuffer[1024];
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
            CHAR errorstr[1024];
            LoadString(hinst, IDS_ERROR_INUSE, errorstr, sizeof(errorstr));
            strlcat(errorstr, "\n", sizeof(errorstr)-1);
            if (DeleteLastProxy(proxynr, gConnectResults->DisplayName, errorstr, sizeof(errorstr)-1)) {
                int proxynr = (int)SendDlgItemMessage(hWnd, IDC_PROXYCOMBO, CB_GETCURSEL, 0, 0);
                fillProxyCombobox(hWnd, proxynr);
            } else {
                MessageBox(hWnd, errorstr, "SFTP", MB_ICONSTOP);   
            }
        } else
            MessageBeep(MB_ICONSTOP);   /* FIXME: ???????? */
        break;
    }
    hr = 0;
fin:
    return hr;
}

bool ShowConnectDialog(pConnectSettings ConnectSettings, LPCSTR DisplayName, LPCSTR inifilename)
{
    gConnectResults = ConnectSettings;
    gDisplayName = DisplayName;
    gIniFileName = inifilename;
    LoadServerSettings(DisplayName, ConnectSettings);

    if (ConnectSettings->dialogforconnection && ConnectSettings->server[0]) {
        if (ConnectSettings->user[0] == 0 || ConnectSettings->password[0])  // no username or password saved
            if (ConnectSettings->proxyuser[0] == 0 || ConnectSettings->proxypassword[0])  // no proxy auth required or proxy pass saved
                return true;
        char title[256];
        // A proxy user name was given, but no proxy password -> ask for proxy password
        if (ConnectSettings->proxyuser[0] != 0 && ConnectSettings->proxypassword[0] == 0) {  // no proxy auth required
            LoadString(hinst, IDS_PROXY_PASS_TITLE, title, countof(title));
            strlcat(title, ConnectSettings->proxyuser, sizeof(title)-1);
            BOOL rc = RequestProc(PluginNumber, RT_PasswordFirewall, title, title, ConnectSettings->proxypassword, countof(ConnectSettings->proxypassword) - 1);
            if (!rc)
                return false;
        }
        return true;
    }

    INT_PTR rc = DialogBox(hinst, MAKEINTRESOURCE(IDD_WEBDAV), GetActiveWindow(), ConnectDlgProc);
    return (rc == IDOK);
}

#ifndef HWND_MESSAGE
#define HWND_MESSAGE ((HWND)(-3))
#endif

SERVERID SftpConnectToServer(LPCSTR DisplayName, LPCSTR inifilename, LPCSTR overridepass)
{
    int hr = -1;
    tConnectSettings * ConnectSettings = (tConnectSettings *)calloc(1, sizeof(tConnectSettings));
    FIN_IF(!ConnectSettings, -1);
    ConnectSettings->dialogforconnection = true;

    // Get connection settings here
    if (!ShowConnectDialog(ConnectSettings, DisplayName, inifilename))
        FIN(-1);

    if (overridepass)
        strlcpy(gConnectResults->password, overridepass, sizeof(gConnectResults->password)-1);
    if (ConnectSettings->useagent || gConnectResults->password[0] == 0) {
        ConnectSettings->passSaveMode = sftp::PassSaveMode::empty;
    } else {
        ConnectSettings->passSaveMode = sftp::PassSaveMode::plain;
    }
    if (CryptProc && strcmp(gConnectResults->password, "\001") == 0) {
        ConnectSettings->passSaveMode = sftp::PassSaveMode::crypt;
        int rc = CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_LOAD_PASSWORD, gDisplayName, gConnectResults->password, countof(gConnectResults->password) - 1);
        if (rc != FS_FILE_OK) {
            MessageBox(GetActiveWindow(), "Failed to load password!", "Error", MB_ICONSTOP);
            FIN(-2);
        }
    }
    if (CryptProc && strcmp(gConnectResults->proxypassword, "\001") == 0) {
        CHAR proxyentry[64];
        if (gConnectResults->proxynr > 1)
            sprintf_s(proxyentry, sizeof(proxyentry), "proxy%d", gConnectResults->proxynr);
        else
            strlcpy(proxyentry, "proxy", sizeof(proxyentry)-1);

        strlcat(proxyentry, "$$pass", sizeof(proxyentry)-1);
        int rc = CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_LOAD_PASSWORD, proxyentry, gConnectResults->proxypassword, countof(gConnectResults->proxypassword) - 1);
        if (rc != FS_FILE_OK) {
            MessageBox(GetActiveWindow(), "Failed to load proxy password!", "Error", MB_ICONSTOP);
            FIN(-3);
        }
    }
    // Clear proxy user and pass if proxy type is set to 0!
    if (ConnectSettings->proxytype == sftp::Proxy::notused) {
        ConnectSettings->proxyuser[0] = 0;
        ConnectSettings->proxypassword[0] = 0;
    }
    // split server name into server/path
    ReplaceBackslashBySlash(ConnectSettings->server);
    // Remove trailing sftp://
    if (_strnicmp(ConnectSettings->server, "sftp://", 7) == 0)
        memmove(ConnectSettings->server, ConnectSettings->server + 7, strlen(ConnectSettings->server) - 6);

    char* p = strchr(ConnectSettings->server, '/');
    ConnectSettings->lastactivepath[0] = 0;
    if (p) {
        awlcopy(ConnectSettings->lastactivepath, p, countof(ConnectSettings->lastactivepath)-1);
        p[0] = 0;
        // remove trailing backslash,  also in case of root!
    }
    // look for address and port
    p = strchr(ConnectSettings->server, ':');
    if (!ParseAddress(ConnectSettings->server, &ConnectSettings->server[0], &ConnectSettings->customport, 22)) {
        MessageBox(GetActiveWindow(), "Invalid server address.", "SFTP Error", MB_ICONSTOP);
        FIN(-4);
    }

    if (ProgressProc(PluginNumber, DisplayName, "temp", 0))
        FIN(-5);

    if (SftpConnect(ConnectSettings) != SFTP_OK)
        FIN(-6);

    // This will show ftp toolbar
    char connbuf[MAX_PATH];
    strlcpy(connbuf, "CONNECT \\", sizeof(connbuf)-1);
    strlcat(connbuf, DisplayName, sizeof(connbuf)-1);
    LogProc(PluginNumber, MSGTYPE_CONNECT, connbuf);

    if (ConnectSettings->keepAliveIntervalSeconds > 0) {
        if (ConnectSettings->hWndKeepAlive == NULL) {
            // only needed in non-blocking mode
            LPCSTR wndName = "SFTPPlug keep alive window";
            ConnectSettings->hWndKeepAlive = ::CreateWindowA("Static", wndName, WS_CHILD, 0, 0, 0, 0, HWND_MESSAGE, NULL, NULL, NULL);
            if (ConnectSettings->hWndKeepAlive) {
                UINT_PTR nIDEvent = (UINT_PTR)ConnectSettings;
                UINT uElapse = ConnectSettings->keepAliveIntervalSeconds * 1000;
                ::SetTimer(ConnectSettings->hWndKeepAlive, nIDEvent, uElapse, TimerProc);
            }
        }
        libssh2_keepalive_config(ConnectSettings->session, 0, ConnectSettings->keepAliveIntervalSeconds);
    }
    hr = 0;

fin:
    if (hr >= 0)
        return (SERVERID)ConnectSettings;

    if (ConnectSettings)
        free(ConnectSettings);
    return NULL;
}

bool SftpConfigureServer(LPCSTR DisplayName, LPCSTR inifilename)
{
    int hr = 0;
    tConnectSettings * ConnectSettings = (tConnectSettings *)calloc(1, sizeof(tConnectSettings));
    FIN_IF(!ConnectSettings, -1);
    ConnectSettings->dialogforconnection = false;
    hr = ShowConnectDialog(ConnectSettings, DisplayName, inifilename) ? 0 : -1;
fin:
    if (ConnectSettings)
        free(ConnectSettings);
    return (hr < 0) ? false : true;
}

int SftpCloseConnection(SERVERID serverid)
{
    int rc;
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (!ConnectSettings)
        return SFTP_FAILED;

    SYSTICKS starttime = get_sys_ticks();
    bool doabort = false;
    if (ConnectSettings->sftpsession) {
        do {
            rc = libssh2_sftp_shutdown(ConnectSettings->sftpsession);
            if (EscapePressed())
                doabort = true;
            if (doabort && get_ticks_between(starttime) > 2000)   /* FIXME: magic number! */
                break;
            if (get_ticks_between(starttime) > 5000)    /* FIXME: magic number! */
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
            if (doabort && get_ticks_between(starttime) > 2000)   /* FIXME: magic number! */
                break;
            if (get_ticks_between(starttime) > 5000)    /* FIXME: magic number! */
                break;
            if (rc == LIBSSH2_ERROR_EAGAIN)
                IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
        } while (rc == LIBSSH2_ERROR_EAGAIN);
        while (1) {
            int rc = libssh2_session_free(ConnectSettings->session);
            if (rc == 0)
                break;
            Sleep(50);
        }
        ConnectSettings->session = NULL;
    }
    if (ConnectSettings->sock != INVALID_SOCKET) {
        closesocket(ConnectSettings->sock); 
        ConnectSettings->sock = INVALID_SOCKET;
    }
    if (ConnectSettings->hWndKeepAlive) {
        ::DestroyWindow(ConnectSettings->hWndKeepAlive);
        ConnectSettings->hWndKeepAlive = NULL;
    }
    return SFTP_FAILED;
}

bool ReconnectSFTPChannelIfNeeded(pConnectSettings ConnectSettings)
{
    if (ConnectSettings->scponly)
        return true;   // not needed
    if (ConnectSettings->neednewchannel || ConnectSettings->sftpsession == NULL) {
        ConnectSettings->neednewchannel = false;
        SYSTICKS starttime = get_sys_ticks();
        int loop = 0;
        if (ConnectSettings->sftpsession) {
            int rc;
            do {
                rc = libssh2_sftp_shutdown(ConnectSettings->sftpsession);
            } while (rc == LIBSSH2_ERROR_EAGAIN && get_ticks_between(starttime) < 2000);    /* FIXME: magic number! */
        }
        if (ConnectSettings->session) {
            do {
                ConnectSettings->sftpsession = NULL;
                if (ProgressLoop("Reconnect SFTP channel", 0, 100, &loop, &starttime))
                    break;
                ConnectSettings->sftpsession = libssh2_sftp_init(ConnectSettings->session);
                if (!ConnectSettings->sftpsession)
                    if (libssh2_session_last_errno(ConnectSettings->session) != LIBSSH2_ERROR_EAGAIN)
                        break;
            } while (!ConnectSettings->sftpsession);
        }
        // try to reconnect the entire connection!
        if (!ConnectSettings->sftpsession) {
            ShowStatus("Connection lost, trying to reconnect!");
            SftpCloseConnection(ConnectSettings);
            Sleep(1000);
            SftpConnect(ConnectSettings);
        }
        ConnectSettings->neednewchannel = ConnectSettings->sftpsession == NULL;
    }
    return !ConnectSettings->neednewchannel;
}

__forceinline
bool IsNeedQuotes(LPCSTR str)
{
    return strchr(str, ' ') || strchr(str, '(') || strchr(str, ')');
}

__forceinline
bool IsNeedQuotesW(LPCWSTR str)
{
    return wcschr(str, ' ') || wcschr(str, '(') || wcschr(str, ')');
}

int SftpFindFirstFileW(SERVERID serverid, LPCWSTR remotedir, LPVOID * davdataptr)
{
    int hr = -1;
    LIBSSH2_CHANNEL * channel = NULL;
    LIBSSH2_SFTP_HANDLE * dirhandle = NULL;
    char dirname[wdirtypemax];
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    LoadStr(dirname, IDS_GET_DIR);
    walcopy(dirname + strlen(dirname), remotedir, sizeof(dirname) - strlen(dirname) - 1);
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
        channel = ConnectChannel(ConnectSettings->session);
        if (!channel) {
            ShowStatus("no channel");
            FIN(-2);
        }
        char commandbuf[wdirtypemax+100];
        commandbuf[0] = 0;
        int trycustom = ConnectSettings->trycustomlistcommand;
        if (trycustom >= 1)
            strcpy(commandbuf, "export LC_ALL=C\n");

        int lencmd0 = strlen(commandbuf);
        strlcat(commandbuf, "ls -la ", sizeof(commandbuf)-1);
        int lencmd1 = strlen(commandbuf);
        if (trycustom == 2)
            strlcat(commandbuf, "--time-style=\"+>>%Y%m%d_%H%M%S\" ", sizeof(commandbuf)-1);
        int lencmd2 = strlen(commandbuf);

        bool needquotes = IsNeedQuotes(dirname);
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
                ShowStatus("send command failed");
                FIN(-4);
            }
            // check whether the command was understood or not
            int rc = 0;
            rcerr = 0;
            do {
                errorbuf[0] = 0;
                rc = libssh2_channel_read(channel, errorbuf, 1);
                rcerr = libssh2_channel_read_stderr(channel, errorbuf, countof(errorbuf)-1);
                if (rcerr > 0) {
                    errorbuf[rcerr] = 0;
                    if (ConnectSettings->detailedlog)
                        ShowStatus(errorbuf);
                }
            } while ((rc == 0 || rc == LIBSSH2_ERROR_EAGAIN) && (rcerr == 0 || rcerr == LIBSSH2_ERROR_EAGAIN));
            if (rcerr > 0 && i > 0) {
                DisconnectShell(channel);
                channel = ConnectChannel(ConnectSettings->session);
                if (!channel) {
                    ShowStatus("no channel");
                    FIN(-5);
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
        FIN_IF(!scpd, -7);
        scpd->channel = channel;
        scpd->msgbuf[0] = 0;
        scpd->errbuf[0] = 0;

        *davdataptr = scpd;
        FIN(0);
    }

    if (!ReconnectSFTPChannelIfNeeded(ConnectSettings))
        FIN(-10);
    
    /* Request a dir listing via SFTP */
    ConnectSettings->findstarttime = get_sys_ticks();
    SYSTICKS aborttime = -1;
    int retrycount = 3;   /* FIXME: magic number! */
    do {
        dirhandle = libssh2_sftp_opendir(ConnectSettings->sftpsession, dirname);
        if (dirhandle)
            break;

        int err = libssh2_session_last_errno(ConnectSettings->session);
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
                FIN(-11);
        } else
            IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!

        Sleep(50);
        int delta = get_ticks_between(ConnectSettings->findstarttime);
        if (delta > 2000 && aborttime == -1) {          /* FIXME: magic numbers! */
            if (ProgressProc(PluginNumber, dirname, "temp", (delta / 200) % 100))
                aborttime = get_sys_ticks() + 2000;  // give it 2 seconds to finish properly!   /* FIXME: magic number! */
        }
        delta = get_ticks_between(aborttime);
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
        FIN(-12);
    }
    *davdataptr = dirhandle;
    FIN(0);

fin:
    if (hr && channel)
        DisconnectShell(channel);

    wcslcpy(ConnectSettings->lastactivepath, remotedir, countof(ConnectSettings->lastactivepath)-1);
    return (hr == 0) ? SFTP_OK : SFTP_FAILED;
}

int SftpFindNextFileW(SERVERID serverid, LPVOID davdataptr, LPWIN32_FIND_DATAW FindData) noexcept
{
    int hr = -1;
    char name[512]; 
    WCHAR namew[MAX_PATH];
    char completeline[2048];
    WCHAR completelinew[2048];
    LIBSSH2_SFTP_ATTRIBUTES file;
    FILETIME datetime;
    DWORD attr = 0;
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    LIBSSH2_SFTP_HANDLE * dirhandle = (LIBSSH2_SFTP_HANDLE*)davdataptr;
    FIN_IF(!dirhandle, -1);

    completeline[0] = 0;
    name[0] = 0;
    namew[0] = 0;
    SYSTICKS aborttime = -1;
    bool data_readed = false;

    if (ConnectSettings->scponly) {
        SCP_DATA* scpd = (SCP_DATA*)davdataptr;
        LIBSSH2_CHANNEL * channel = scpd->channel;
        FIN_IF(!channel, -2);
        while (ReadChannelLine(channel, completeline, sizeof(completeline)-1, scpd->msgbuf, sizeof(scpd->msgbuf)-1, scpd->errbuf, sizeof(scpd->errbuf)-1)) {
            StripEscapeSequences(completeline);
            CopyStringA2W(ConnectSettings, completeline, completelinew, _countof(completelinew));

            if (ReadDirLineUNIX(completelinew, namew, countof(namew)-1, (PINT64)&file.filesize, &datetime, &attr, &file.permissions, 0)) {
                file.flags = LIBSSH2_SFTP_ATTR_SIZE | LIBSSH2_SFTP_ATTR_PERMISSIONS;
                data_readed = true;
                break;
            }
        }
        FIN_IF(!data_readed, -3);
    } else {
        while (1) {
            int rc = libssh2_sftp_readdir_ex(dirhandle, name, sizeof(name), completeline, sizeof(completeline), &file);
            if (rc > 0) {
                data_readed = true;
                break;
            }
            if (rc != LIBSSH2_ERROR_EAGAIN)
                break;
            int delta = get_ticks_between(ConnectSettings->findstarttime);
            if (delta > 2000 && aborttime == -1) {              /* FIXME: magic numbers! */
                if (ProgressProc(PluginNumber, "dir", "temp", (delta / 200) % 100))
                    aborttime = get_sys_ticks() + 2000;  // give it 2 seconds to finish properly!  /* FIXME: magic number! */
            }
            delta = get_ticks_between(aborttime);
            if (aborttime != -1 && delta > 0) {
                ConnectSettings->neednewchannel = true;
                break;
            }
            IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
        }
        FIN_IF(!data_readed, -5);
    }

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
        ConvUnixTimeToFileTime(&FindData->ftLastWriteTime, file.mtime);
    }

    if (file.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) {
        FindData->dwFileAttributes |= FS_ATTR_UNIXMODE;
        FindData->dwReserved0 = file.permissions & 0xFFFF;  // attributes and format mask
    }
    hr = 0;

fin:
    return (hr == 0) ? SFTP_OK : SFTP_FAILED;
}

int SftpFindClose(SERVERID serverid, LPVOID davdataptr)
{
    if (!davdataptr)
        return SFTP_FAILED;
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    SYSTICKS aborttime = -1;
    if (ConnectSettings->scponly) {
        SCP_DATA* scpd = (SCP_DATA*)davdataptr;
        LIBSSH2_CHANNEL *channel = scpd->channel;
        CloseRemote(serverid, NULL, channel, true, 100);
        return SFTP_OK;
    }
    LIBSSH2_SFTP_HANDLE * dirhandle = (LIBSSH2_SFTP_HANDLE*)davdataptr;
    while (LIBSSH2_ERROR_EAGAIN == libssh2_sftp_closedir(dirhandle)) {
        int delta = get_ticks_between(ConnectSettings->findstarttime);
        if (delta > 2000 && aborttime == -1) {         /* FIXME: magic numbers! */
            if (ProgressProc(PluginNumber, "close dir", "temp", (delta / 200) % 100))
                aborttime = get_sys_ticks() + 2000;  // give it 2 seconds to finish properly!
        }
        delta = get_ticks_between(aborttime);
        if (aborttime != -1 && delta > 0) {
            ConnectSettings->neednewchannel = true;
            break;
        }
        IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
    }
    return SFTP_OK;
}

int SftpCreateDirectoryW(SERVERID serverid, LPCWSTR Path)
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
        LIBSSH2_CHANNEL * channel = ConnectChannel(ConnectSettings->session);
        strlcpy(commandbuf, "mkdir ", sizeof(commandbuf)-1);
        bool needquotes = IsNeedQuotes(dirname);
        if (needquotes)
            strlcat(commandbuf, "\"", sizeof(commandbuf)-3);
        strlcat(commandbuf, dirname, sizeof(commandbuf)-2);
        if (needquotes)
            strlcat(commandbuf, "\"", sizeof(commandbuf)-1);
        bool ok = GetChannelCommandReply(ConnectSettings->session, channel, commandbuf);
        DisconnectShell(channel);
        return ok ? SFTP_OK : SFTP_FAILED;
    }

    SYSTICKS starttime = get_sys_ticks();
    SYSTICKS aborttime = -1;
    do {
        rc = libssh2_sftp_mkdir(ConnectSettings->sftpsession, dirname, ConnectSettings->dirmod);
        if (rc == 0)
            break;
        Sleep(50);
        int delta = get_ticks_between(starttime);
        if (delta > 2000 && aborttime == -1) {      /* FIXME: magic number! */
            if (EscapePressed())                // ProgressProc not working in this function!
                aborttime = get_sys_ticks() + 2000;  // give it 2 seconds to finish properly!
        }
        delta = get_ticks_between(aborttime);
        if (aborttime != -1 && delta > 0) {
            ConnectSettings->neednewchannel = true;
            break;
        }
        if (rc == LIBSSH2_ERROR_EAGAIN)
            IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
    } while (rc == LIBSSH2_ERROR_EAGAIN);

    if (rc) {
        char* errmsg;
        int errmsg_len;
        LoadStr(dirname, IDS_ERR_MK_DIR);
        libssh2_session_last_error(ConnectSettings->session, &errmsg, &errmsg_len, false);
        strlcat(dirname, errmsg, sizeof(dirname)-1);
        ShowStatus(dirname);
        return SFTP_FAILED;
    }
    // Set mod again,  because some servers don't seem to set it automatically
    if (ConnectSettings->dirmod != 0755) {      /* FIXME: magic number! */
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
}

int SftpRenameMoveFileW(SERVERID serverid, LPCWSTR OldName, LPCWSTR NewName, bool Move, bool Overwrite, bool isdir)
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
            bool needquotes2 = IsNeedQuotesW(NewName2W);
            if (needquotes2)
                wcslcat(cmdname, L"\"", countof(cmdname)-1);
            wcslcat(cmdname, NewName2W, countof(cmdname)-1);
            if (needquotes2)
                wcslcat(cmdname, L"\"", countof(cmdname)-1);
            if (SftpQuoteCommand2W(serverid, NULL, cmdname, NULL, 0) == 0) {  // file found!
                //int err = libssh2_session_last_errno(ConnectSettings->session);
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

            if (rc == 0) {    // found!
                //int err = libssh2_session_last_errno(ConnectSettings->session);
                return SFTP_EXISTS;
            }
            if (rc == LIBSSH2_ERROR_EAGAIN) {
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

    if (Move && ConnectSettings->scponly) {
        WCHAR cmdname[2*wdirtypemax];
        // note: SftpQuoteCommand2 already converts from Ansi to UTF-8!!!
        wcslcpy(OldName2W, OldName, countof(OldName2W)-1);
        ReplaceBackslashBySlashW(OldName2W);
        wcslcpy(NewName2W, NewName, countof(NewName2W)-1);
        ReplaceBackslashBySlashW(NewName2W);

        wcslcpy(cmdname, Move ? L"mv " : L"cp ", countof(cmdname)-1);
        bool needquotes1 = IsNeedQuotesW(OldName2W);
        bool needquotes2 = IsNeedQuotesW(NewName2W);
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
        if (SftpQuoteCommand2W(serverid, NULL, cmdname, NULL, 0) == 0)
            return SFTP_OK;
        return SFTP_FAILED;
    }

    do {
        rc = libssh2_sftp_rename(ConnectSettings->sftpsession, OldName2, NewName2);
        if (EscapePressed()) {
            ConnectSettings->neednewchannel = true;
            break;
        }
        if (rc == LIBSSH2_ERROR_EAGAIN)
            IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
    } while (rc == LIBSSH2_ERROR_EAGAIN);

    if (rc) {
        char* errmsg;
        int errmsg_len;
        LoadStr(abuf, IDS_ERR_RENAME);
        libssh2_session_last_error(ConnectSettings->session, &errmsg, &errmsg_len, false);
        strlcat(abuf, errmsg, sizeof(buf)-1);
        ShowStatus(abuf);
    }
    return (rc == 0) ? SFTP_OK : SFTP_FAILED;
}

static int GetPercent(INT64 offset, INT64 filesize)
{
    if (!filesize)
        return 0;
    int percent = (int)((offset * 100) / filesize);
    if (percent < 0)
        return 0;
    if (percent > 100)
        return 100;
    return percent;
}

int CheckInputOrTimeout(SERVERID serverid, bool timeout, SYSTICKS starttime, int percent)
{
    if (timeout) {
        if (get_ticks_between(starttime) > 5000 && UpdatePercentBar(serverid, percent)) {   /* FIXME: magic number!, UpdatePercentBar == FS_TASK_ABORTED */
            return SFTP_ABORT;
        }
        if (get_ticks_between(starttime) > 10000) {
            return SFTP_FAILED;
        }
        return SFTP_OK;
    }
    if (EscapePressed()) {
        return SFTP_ABORT;
    }
    return SFTP_OK;
}

int CloseRemote(SERVERID serverid, LIBSSH2_SFTP_HANDLE * remotefilesftp, LIBSSH2_CHANNEL * remotefilescp, bool timeout, int percent) noexcept
{
    int retval = SFTP_OK;
    SYSTICKS starttime = get_sys_ticks();
    if (remotefilesftp) {
        while (LIBSSH2_ERROR_EAGAIN == libssh2_sftp_close(remotefilesftp)) {
            retval = CheckInputOrTimeout(serverid, timeout, starttime, percent);
            if (retval != SFTP_OK)
                break;
        }
        remotefilesftp = NULL;    /* FIXME: useless action */
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
        remotefilescp = NULL;    /* FIXME: useless action */
    }
    return retval;
}

#define RECV_BLOCK_SIZE 32768

static int ConvertCrToCrLf(LPSTR data, size_t len, bool * pLastWasCr)
{
    bool LastWasCr = *pLastWasCr;   // don't convert 0d0a->0d0d0a!
    char data2[RECV_BLOCK_SIZE];
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
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
    return (int)j;
}

bool SftpDetermineTransferModeW(LPCWSTR RemoteName)  // true if text mode
{
    if (Global_TransferMode == 'A')
        return true;
    if (Global_TransferMode == 'I')
        return false;
    // mode 'auto'
    LPCWSTR p = wcsrchr(RemoteName, '/');
    if (!p)
        p = wcsrchr(RemoteName, '\\');
    p = (p == NULL) ? RemoteName : p + 1;
    return MultiFileMatchW(Global_TextTypes, p);
}

int SftpDownloadFileW(SERVERID serverid, LPCWSTR RemoteName, LPCWSTR LocalName, bool alwaysoverwrite, INT64 filesize, LPFILETIME ft, bool Resume)
{   
    int hr = SFTP_FAILED;
    LIBSSH2_SFTP_HANDLE * remotefilesftp = NULL;
    HANDLE localfile = NULL;
    LPSTR data = NULL;
    char filename[wdirtypemax];
    INT64 sizeloaded = 0;
    INT64 resumepos = 0;
    LIBSSH2_CHANNEL * remotefilescp = NULL;
    libssh2_struct_stat fileinfoscp;
    INT64 scpremain = 0;

    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    FIN_IF(!ConnectSettings, SFTP_FAILED);

    bool LastWasCr = false;
    char abuf[MAX_PATH];
    WCHAR msgbuf[wdirtypemax];
    WCHAR *pend;
    
    bool scpdata = ConnectSettings->scpfordata;

    if (scpdata && Resume && !ConnectSettings->scponly)    // resume not possible with scp!
        scpdata = false;

    if (scpdata && filesize >= INT_MAX) { // scp supports max 2 GB
        // libssh2 version >= 1.7.0 supports file size > 2 GB (for downloading)
        // But SCP on server side needs to be 64bit
        if (ConnectSettings->scpserver64bit != 1 && !ConnectSettings->scpserver64bittemporary) {
            if (ConnectSettings->scponly) {
                char errorstr[256];
                LoadStr(errorstr, IDS_NO_2GB_SUPPORT);
                if (!RequestProc(PluginNumber, RT_MsgYesNo, "SFTP Error", errorstr, NULL, 0))
                    FIN(SFTP_ABORT);
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
    bool TextMode = (ConnectSettings->unixlinebreaks == 1) && SftpDetermineTransferModeW(RemoteName);

    FIN_IF(TextMode && Resume, SFTP_FAILED);

    if (!ReconnectSFTPChannelIfNeeded(ConnectSettings))
        FIN(SFTP_FAILED);

    if (scpdata) {
        do {
            remotefilescp = libssh2_scp_recv2(ConnectSettings->session, filename, &fileinfoscp);
            if (EscapePressed()) {
                ConnectSettings->neednewchannel = true;
                break;
            }
        } while (remotefilescp == 0 && libssh2_session_last_errno(ConnectSettings->session) == LIBSSH2_ERROR_EAGAIN);
        if (remotefilescp == 0) {
            scpremain = fileinfoscp.st_size;
        } else {
            scpdata = false;
            SftpLogLastError("SCP download error: ", libssh2_session_last_errno(ConnectSettings->session));
            // Note: It seems that scp sometimes fails to get file names with non-English characters!
            bool hasnonenglish = false;
            for (size_t i = 0; i < wcslen(RemoteName); i++) {
                if (RemoteName[i] >= 128) {
                    hasnonenglish = true;
                    break;
                }
            }
            FIN_IF(!hasnonenglish, SFTP_READFAILED);
        }
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
        FIN_IF(!remotefilesftp, SFTP_READFAILED);
    }

    DWORD dwShareMode = FILE_SHARE_READ | FILE_SHARE_WRITE;
    DWORD dwFlags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN;
    DWORD dwDispos = alwaysoverwrite ? CREATE_ALWAYS : CREATE_NEW;
    if (Resume)
        dwDispos = OPEN_EXISTING;

    localfile = CreateFileW(LocalName, GENERIC_WRITE, dwShareMode, NULL, dwDispos, dwFlags, NULL);
    localfile = (localfile == INVALID_HANDLE_VALUE) ? NULL : localfile;
    if (!localfile) {
        DWORD err = GetLastError();
        FIN_IF(err == ERROR_ACCESS_DENIED, SFTP_EXISTS);
        FIN_IF(err == ERROR_SHARING_VIOLATION, SFTP_EXISTS);
        FIN(SFTP_WRITEFAILED);
    }
    if (Resume) {    // resume not possible with scp!
        BOOL x = GetFileSizeEx(localfile, (PLARGE_INTEGER)&sizeloaded);
        FIN_IF(!x, SFTP_WRITEFAILED);
        FIN_IF(sizeloaded > filesize, SFTP_WRITEFAILED);
        FIN_IF(sizeloaded == filesize, SFTP_OK);
        UINT64 offset = 0;
        x = SetFilePointerEx(localfile, *(PLARGE_INTEGER)&offset, NULL, FILE_BEGIN);
        FIN_IF(!x, SFTP_WRITEFAILED);
        resumepos = sizeloaded;
        if (sizeloaded > 0) {   // seek!
            libssh2_sftp_seek64(remotefilesftp, (libssh2_uint64_t)sizeloaded);
            // Better check whether seek was successful!
            UINT64 tell64 = libssh2_sftp_tell64(remotefilesftp);
            FIN_IF(tell64 != (libssh2_uint64_t)sizeloaded, SFTP_READFAILED);
        }
    }

    ProgressProcT(PluginNumber, pend, LocalName, 0);

    const size_t base_sftp_read_size = 30000;               /* FIXME: magic number! (libssh2 MAX_SFTP_READ_SIZE) */
    const size_t min_read_size = base_sftp_read_size * 2;   /* FIXME: magic number! */
    const size_t max_read_size = base_sftp_read_size * 64;  /* FIXME: magic number! */

    data = (LPSTR)malloc(max_read_size);    /* FIXME: transfer pointer to pConnectSettings struct */
    FIN_IF(!data, SFTP_FAILED);

    int len = 0;
    int maxblocksize = min_read_size;
    if (TextMode)
        maxblocksize = base_sftp_read_size / 2;  // in worst case,  we have all line breaks (0A)
    /* FIXME: ConvertCrToCrLf has limit data size! */
    if (scpdata)
        maxblocksize = (TextMode) ? RECV_BLOCK_SIZE / 2 : RECV_BLOCK_SIZE;

    hr = SFTP_OK;
    SYSTICKS aborttime = -1;
    SYSTICKS starttime = get_sys_ticks();
    bool read_interrupted = false;
    do {
        if (scpdata) {
            if (scpremain <= 0)
                break;
            // Note: We must limit the receive buffer so we don't
            // read beyond the length of the file,  otherwise we will get 1 byte too much!
            len = libssh2_channel_read(remotefilescp, data, (size_t)min(scpremain, maxblocksize));
            if (len > 0)
                scpremain -= len;
        } else {
            len = libssh2_sftp_read(remotefilesftp, data, maxblocksize);
        }
        if (len > 0) {
            if (TextMode && sizeloaded == 0) {   // test first block if it's binary
                for (int i = 0; i < len; i++) {
                    if (data[i] == 0) {
                        TextMode = false;
                        break;
                    }
                }
            }
            sizeloaded += len;    // the unconverted size!
            if (TextMode)
                len = ConvertCrToCrLf(data, len, &LastWasCr);

            DWORD written;
            if (!WriteFile(localfile, data, len, &written, NULL) || (int)written != len) {
                hr = SFTP_WRITEFAILED;
                break;
            }
            if (!scpdata && !TextMode) {
                if (read_interrupted) {
                    if (maxblocksize / 2 >= min_read_size)
                        maxblocksize /= 2;
                } else {
                    if (maxblocksize * 2 <= max_read_size)
                        maxblocksize *= 2;
                }
            }
            read_interrupted = false;
        } else {
            read_interrupted = true;
        }
        // Always,  for aborting!
        if (UpdatePercentBar(serverid, GetPercent(sizeloaded, filesize))) {
            aborttime = get_sys_ticks() + 2000;  // give it 2 seconds to finish properly!    /* FIXME: magic number! */
            hr = SFTP_ABORT;
        }
        if (len == LIBSSH2_ERROR_EAGAIN) {
            IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
            len = 1;
        } else {
            if (len < 0)
                SftpLogLastError("Download read error: ", len);
            if (aborttime != -1)
                break;
        }
        // if there is no data until the abort time is reached,  abort anyway
        // this can corrupt the sftp channel,  so discard it on the next read
        int delta = get_ticks_between(aborttime);
        if (aborttime != -1 && delta > 0) {
            ConnectSettings->neednewchannel = true;
            break;
        }
    } while (len > 0);

    if (filesize > 300*1000*1000)
        LogMsg("Download speed = %I64d KiB/s", (sizeloaded * 1000) / (get_ticks_between(starttime) * 1024));

    if (len < 0)
        hr = SFTP_READFAILED;

fin:
    if (localfile) {
        SetFileTime(localfile, NULL, NULL, ft);
        CloseHandle(localfile);
    }
    if (remotefilesftp || remotefilescp) {
        bool timeout = data ? true : false;
        int persent = data ? GetPercent(sizeloaded, filesize) : 0;
        int hr2 = CloseRemote(serverid, remotefilesftp, remotefilescp, timeout, persent);
        if (hr2 != SFTP_OK) {
            ConnectSettings->neednewchannel = true;
            if (hr == SFTP_OK)
                hr = hr2;
        }
    }
    // Auto-resume if read failed in the middle, and we downloaded at least one byte since the last call
    if (!ConnectSettings->scponly)
        if (hr != SFTP_ABORT && hr != SFTP_WRITEFAILED)
            if (sizeloaded < filesize && sizeloaded > resumepos)
                hr = SFTP_PARTIAL;

    if (data)
        free(data);
    return hr;
}

#define SEND_BLOCK_SIZE 16384

static int ConvertCrLfToCr(LPSTR data, size_t len)  // simply remove all <CR> characters!
{
    char data2[SEND_BLOCK_SIZE];
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (data[i] != 0x0d)
            data2[j++] = data[i];
    }
    memcpy(data, &data2, j);
    return (int)j;
}

static INT64 GetTextModeFileSize(HANDLE localfile, bool entirefile)
{
    char data[SEND_BLOCK_SIZE];
    INT64 filesize = 0;
    size_t len = 0;
    while (ReadFile(localfile, &data, (DWORD)sizeof(data), (PDWORD)&len, NULL) && len > 0) {
        size_t numcrs = 0;
        for (size_t i = 0; i < len; i++) {
            if (data[i] == 0) {
                filesize = -1;       // binary -> do not convert!
                break;
            }
            if (data[i] == 0x0d)
                numcrs++;
        }
        if (filesize == -1 || !entirefile) // just check first block for 0 characters
            break;
        filesize += len - numcrs;
    }
    SetFilePointer(localfile, 0, NULL, FILE_BEGIN);
    return filesize;
}

static size_t GetTextUploadResumePos(HANDLE localfile, size_t resumepos)
{
    char data[SEND_BLOCK_SIZE];
    size_t localfilesize = 0;
    size_t convertedfilesize = 0;
    size_t len = 0;
    while (ReadFile(localfile, &data, (DWORD)sizeof(data), (PDWORD)&len, NULL) && len > 0) {
        size_t numcrs = 0;
        for (size_t i = 0; i < len; i++) {
            localfilesize++;
            if (data[i] != 0x0d)
                convertedfilesize++;
            if (convertedfilesize >= resumepos) {
                if (convertedfilesize > resumepos)
                    localfilesize = (size_t)(-1);
                SetFilePointer(localfile, 0, NULL, FILE_BEGIN);
                return localfilesize;
            }
        }
    }
    SetFilePointer(localfile, 0, NULL, FILE_BEGIN);
    return (size_t)(-1);
}

int SftpUploadFileW(SERVERID serverid, LPCWSTR LocalName, LPCWSTR RemoteName, bool Resume, bool setattr)
{
    int hr = SFTP_FAILED;
    LIBSSH2_SFTP_HANDLE * remotefilesftp = NULL;
    LIBSSH2_CHANNEL * remotefilescp = NULL;
    HANDLE localfile = NULL;
    LPSTR data = NULL;

    char thename[wdirtypemax];    // remote name in server encoding
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    FIN_IF(!ConnectSettings, SFTP_FAILED);

    CopyStringW2A(ConnectSettings, RemoteName, thename, _countof(thename));
    FIN_IF(ConnectSettings->utf8names == 0 && strchr(thename, '?'), SFTP_WRITEFAILED);  // invalid remote name
    ReplaceBackslashBySlash(thename);

    bool TextMode = (ConnectSettings->unixlinebreaks == 1) && SftpDetermineTransferModeW(LocalName);

    bool scpdata = ConnectSettings->scpfordata;

    if (scpdata && Resume)    // resume not possible with scp!
        scpdata = false;
    
    if (!ReconnectSFTPChannelIfNeeded(ConnectSettings))
        FIN(SFTP_FAILED);

    hr = SFTP_WRITEFAILED;

    char abuf[MAX_PATH];
    WCHAR msgbuf[wdirtypemax];
    LoadStr(abuf, IDS_UPLOAD);
    awlcopy(msgbuf, abuf, wdirtypemax-1);

    DWORD dwShareMode = FILE_SHARE_READ | FILE_SHARE_WRITE;
    DWORD dwFlags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN;
    DWORD dwDispos = OPEN_EXISTING;

    localfile = CreateFileW(LocalName, GENERIC_READ, dwShareMode, NULL, dwDispos, dwFlags, NULL);
    localfile = (localfile == INVALID_HANDLE_VALUE) ? NULL : localfile;
    if (!localfile) {
        wcslcat(msgbuf, RemoteName, countof(msgbuf)-1);
        ReplaceBackslashBySlashW(msgbuf);
        ShowStatusW(msgbuf);
        LogProc(PluginNumber, MSGTYPE_IMPORTANTERROR, "Error opening local file!");
        FIN(SFTP_READFAILED);
    }
    INT64 sizeloaded = 0;
    INT64 filesize = 0;
    BOOL x = GetFileSizeEx(localfile, (PLARGE_INTEGER)&filesize);
    FIN_IF(!x, SFTP_READFAILED);

    if (scpdata && filesize >= INT_MAX) {  // scp supports max 2 GB
        // libssh2 version >= 1.2.6 supports file size > 2 GB
        // But SCP on server side needs to be 64bit
        if (ConnectSettings->scpserver64bit != 1 && !ConnectSettings->scpserver64bittemporary) {
            char errorstr[256];
            LoadStr(errorstr, IDS_NO_2GB_SUPPORT);
            if (!RequestProc(PluginNumber, RT_MsgYesNo, "SFTP Error", errorstr, NULL, 0)) {
                FIN_IF(ConnectSettings->scponly, SFTP_ABORT);
                scpdata = false; // fallback to SFTP
            } else {
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
        if (TextMode) {
            INT64 filesize2 = GetTextModeFileSize(localfile, true);
            if (filesize2 == -1)
                TextMode = false;
            else
                filesize = filesize2;
        }
        FILETIME ft;
        LONG mtime = 0;
        // the filemod is only set when also setting the timestamps.
        // we must not set it when overwriting, though!
        // when using SFTP commands, we can set the mode afterwards with the timestamp
        if (ConnectSettings->scponly && setattr) {
            if (GetFileTime(localfile, NULL, NULL, &ft)) {
                mtime = GetUnixTime(&ft);
            }
        }
        do {
            remotefilescp = libssh2_scp_send64(ConnectSettings->session, thename, ConnectSettings->filemod, (libssh2_uint64_t)filesize, mtime, 0);
            if (EscapePressed()) {
                ConnectSettings->neednewchannel = true;
                break;
            }
        } while (remotefilescp == 0 && libssh2_session_last_errno(ConnectSettings->session) == LIBSSH2_ERROR_EAGAIN);
        if (!remotefilescp) {
            SftpLogLastError("SCP upload error: ", libssh2_session_last_errno(ConnectSettings->session));
        }
        FIN_IF(!remotefilescp, SFTP_WRITEFAILED);
    } else {
        if (TextMode && -1 == GetTextModeFileSize(localfile, false))
            TextMode = false;
        do {
            ULONG flags = Resume ? LIBSSH2_FXF_WRITE : LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC;
            LONG mode = 0644;  /* FIXME: magic number! */
            remotefilesftp = libssh2_sftp_open(ConnectSettings->sftpsession, thename, flags, mode);   // ConnectSettings->filemod is ignored!!!
            if (EscapePressed()) {
                ConnectSettings->neednewchannel = true;
                break;
            }
            if (remotefilesftp == 0)
                IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
        } while (remotefilesftp == 0 && libssh2_session_last_errno(ConnectSettings->session) == LIBSSH2_ERROR_EAGAIN);
        FIN_IF(!remotefilesftp, SFTP_WRITEFAILED);
    }

    if (Resume) {   // seek!
        int rc;
        UINT64 resumepos = 0;
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
            resumepos = attr.filesize;
            libssh2_sftp_seek64(remotefilesftp, resumepos);
            FIN_IF(TextMode && resumepos >= INT_MAX, SFTP_WRITEFAILED);
            // Better check whether seek was successful!
            UINT64 tell64 = libssh2_sftp_tell64(remotefilesftp);
            FIN_IF(tell64 != resumepos, SFTP_WRITEFAILED);
            if (Resume && TextMode) {
                resumepos = GetTextUploadResumePos(localfile, (size_t)resumepos);
                FIN_IF(resumepos == (size_t)(-1), SFTP_WRITEFAILED);
            }
            BOOL x = SetFilePointerEx(localfile, *(PLARGE_INTEGER)&resumepos, NULL, FILE_BEGIN);
            FIN_IF(!x, SFTP_WRITEFAILED);
            sizeloaded = resumepos;
        } else {
            Resume = false;
        }            
    }

    const size_t MAX_SFTP_OUTGOING_SIZE = 30000;     /* Look libssh2 MAX_SFTP_OUTGOING_SIZE */
    size_t data_size = MAX_SFTP_OUTGOING_SIZE * 32;
    data = (LPSTR)malloc(data_size);    /* FIXME: transfer pointer to pConnectSettings struct */
    FIN_IF(!data, SFTP_FAILED);
    if (TextMode) {
        data_size = scpdata ? SEND_BLOCK_SIZE : MAX_SFTP_OUTGOING_SIZE / 2;
    }
    SYSTICKS starttime = get_sys_ticks();
    ssize_t len = 0;
    hr = SFTP_OK;

    while (ReadFile(localfile, data, (DWORD)data_size, (PDWORD)&len, NULL) && len > 0) {
        ssize_t written;
        ssize_t dataread = len;
        LPSTR pdata = data;
        if (TextMode)
            len = ConvertCrLfToCr(data, len);
        do {
            if (scpdata)
                written = libssh2_channel_write(remotefilescp, pdata, len);
            else
                written = libssh2_sftp_write(remotefilesftp, pdata, len);

            if (written >= 0) {
                if (written > len) {  // libssh2_channel_write sometiomes returns values > len!
                    hr = SFTP_WRITEFAILED;
                    written = -1;
                    break;
                }
                pdata += written;
                len -= written;
                if (len == 0)
                    sizeloaded += dataread;  // not the converted size!
            }
            else if (written != LIBSSH2_ERROR_EAGAIN) { // error?
                SftpLogLastError("Upload write error: ", libssh2_session_last_errno(ConnectSettings->session));
                len = 0;
            }
            else {
                if (!IsSocketWritable(ConnectSettings->sock))  // sleep to avoid 100% CPU!
                    Sleep(10);
            }

            if (UpdatePercentBar(serverid, GetPercent(sizeloaded, filesize))) {
                // graceful abort if last reply was EAGAIN
                SYSTICKS abort_time = get_sys_ticks();
                while (written == LIBSSH2_ERROR_EAGAIN) {
                    if (scpdata)
                        written = libssh2_channel_write(remotefilescp, pdata, len);
                    else
                        written = libssh2_sftp_write(remotefilesftp, pdata, len);

                    if (get_ticks_between(abort_time) > 5000)   /* FIXME: magic number! */
                        break;
                    IsSocketWritable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
                }
                written = -1;
                hr = SFTP_ABORT;
                break;
            }
        } while (written == LIBSSH2_ERROR_EAGAIN || len > 0);

        if (written < 0) {
            if (hr != SFTP_ABORT)
                hr = SFTP_WRITEFAILED;
            break;
        }
    }

    if (filesize > 300*1000*1000)
        LogMsg("Upload speed = %I64d KiB/s", (sizeloaded * 1000) / (get_ticks_between(starttime) * 1024));

    FILETIME ft;
    if (hr == SFTP_OK && GetFileTime(localfile, NULL, NULL, &ft)) {
        if (ConnectSettings->scponly) {
            SftpSetDateTimeW(ConnectSettings, RemoteName, &ft);
        } else {
            LIBSSH2_SFTP_ATTRIBUTES attr;
            // set modification time ONLY if target didn't exist yet!!!
            memset(&attr, 0, sizeof(attr));
            attr.flags = LIBSSH2_SFTP_ATTR_ACMODTIME | (setattr ? LIBSSH2_SFTP_ATTR_PERMISSIONS : 0);
            if (GetFileTime(localfile, NULL, NULL, &ft)) {
                attr.mtime = GetUnixTime(&ft);
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
        }
    }

fin:
    if (localfile)
        CloseHandle(localfile);

    if (remotefilesftp || remotefilescp) {
        bool timeout = data ? true : false;
        int persent = data ? GetPercent(sizeloaded, filesize) : 0;
        int hr2 = CloseRemote(serverid, remotefilesftp, remotefilescp, timeout, persent);
        if (hr2 != SFTP_OK) {
            ConnectSettings->neednewchannel = true;
            if (hr == SFTP_OK)
                hr = hr2;
        }
    }

    if (data)
        free(data);
    return hr;
}

int SftpDeleteFileW(SERVERID serverid, LPCWSTR RemoteName, bool isdir)
{
    int hr = SFTP_FAILED;
    LIBSSH2_CHANNEL * channel = NULL;
    char dirname[wdirtypemax], abuf[wdirtypemax];
    WCHAR buf[wdirtypemax];
    int rc;

    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    FIN_IF(!ConnectSettings, SFTP_FAILED);

    CopyStringW2A(ConnectSettings, RemoteName, dirname, _countof(dirname));
    ReplaceBackslashBySlash(dirname);
    FIN_IF(strcmp(dirname, "/~") == 0, SFTP_FAILED);    // go to home dir special link

    LoadStr(abuf, IDS_DELETE);
    awlcopy(buf, abuf, countof(buf)-1);
    wcslcat(buf, RemoteName, sizeof(buf)-1);
    ShowStatusW(buf);

    if (ConnectSettings->scponly) {
        char commandbuf[wdirtypemax + 8];
        channel = ConnectChannel(ConnectSettings->session);
        FIN_IF(!channel, SFTP_FAILED);
        if (isdir)
            strlcpy(commandbuf, "rmdir ", sizeof(commandbuf)-1);
        else
            strlcpy(commandbuf, "rm ", sizeof(commandbuf)-1);

        bool needquotes = IsNeedQuotes(dirname);
        if (needquotes)
            strlcat(commandbuf, "\"", sizeof(commandbuf)-3);
        strlcat(commandbuf, dirname, sizeof(commandbuf)-2);
        if (needquotes)
            strlcat(commandbuf, "\"", sizeof(commandbuf)-1);
        bool ok = GetChannelCommandReply(ConnectSettings->session, channel, commandbuf);
        FIN_IF(!ok, SFTP_FAILED);
        FIN(SFTP_OK);
    }

    SYSTICKS starttime = get_sys_ticks();
    SYSTICKS aborttime = -1;
    do {
        if (isdir)
            rc = libssh2_sftp_rmdir(ConnectSettings->sftpsession, dirname);
        else
            rc = libssh2_sftp_unlink(ConnectSettings->sftpsession, dirname);

        int delta = get_ticks_between(starttime);
        if (delta > 2000 && aborttime == -1) {       /* FIXME: magic numbers! */
            if (ProgressProcT(PluginNumber, buf, L"delete", (delta / 200) % 100))
                aborttime = get_sys_ticks() + 2000;   // give it 2 seconds to finish properly!  /* FIXME: magic number! */
        }
        delta = get_ticks_between(aborttime);
        if (aborttime != -1 && delta > 0) {
            ConnectSettings->neednewchannel = true;
            break;
        }
        if (rc == LIBSSH2_ERROR_EAGAIN)
            IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
    } while (rc == LIBSSH2_ERROR_EAGAIN);

    hr = (rc == 0) ? SFTP_OK : SFTP_FAILED;

fin:
    if (ConnectSettings->scponly) {
        if (channel)
            DisconnectShell(channel);
    } else {
        if (rc != SFTP_OK) {
            char* errmsg;
            int errmsg_len;
            LoadStr(abuf, IDS_ERR_DELETE);
            libssh2_session_last_error(ConnectSettings->session, &errmsg, &errmsg_len, false);
            awlcopy(buf, abuf, countof(buf)-1);
            awlcopy(buf + wcslen(buf), errmsg, countof(buf) - wcslen(buf) - 1);
            wcslcat(buf, L" ", countof(buf)-1);
            wcslcat(buf, RemoteName, countof(buf)-1);
            ShowStatusW(buf);
        }
    }
    return hr;
}

int SftpSetAttr(SERVERID serverid, LPCSTR RemoteName, int NewAttr)
{
    return SFTP_FAILED;
}

int SftpSetDateTimeW(SERVERID serverid, LPCWSTR RemoteName, LPFILETIME LastWriteTime)
{
    int hr = SFTP_FAILED;
    LIBSSH2_CHANNEL * channel = NULL;

    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    FIN_IF(!ConnectSettings, SFTP_FAILED);

    int rc = 0;
    WCHAR msgbuf[wdirtypemax];
    char filename[wdirtypemax];

    CopyStringW2A(ConnectSettings, RemoteName, filename, _countof(filename));
    ReplaceBackslashBySlash(filename);

    wcslcpy(msgbuf, L"Set date/time for: ", countof(msgbuf)-1);
    wcslcat(msgbuf, RemoteName, countof(msgbuf)-1);
    ReplaceBackslashBySlashW(msgbuf);
    ShowStatusW(msgbuf);

    // touch -t 201501311530.21 test.py
    if (ConnectSettings->scponly) {
        SYSTEMTIME tdt = {0};
        FILETIME lft;
        char commandbuf[wdirtypemax + 32];
        channel = ConnectChannel(ConnectSettings->session);
        FIN_IF(!channel, SFTP_FAILED);
        FileTimeToLocalFileTime(LastWriteTime, &lft);
        FileTimeToSystemTime(&lft, &tdt);
        sprintf_s(commandbuf, sizeof(commandbuf), "touch -t %04d%02d%02d%02d%02d.%02d ",
            tdt.wYear, tdt.wMonth, tdt.wDay, tdt.wHour, tdt.wMinute, tdt.wSecond);
        bool needquotes = IsNeedQuotes(filename);
        if (needquotes)
            strlcat(commandbuf, "\"", sizeof(commandbuf)-3);
        strlcat(commandbuf, filename, sizeof(commandbuf)-2);
        if (needquotes)
            strlcat(commandbuf, "\"", sizeof(commandbuf)-1);
        bool ok = GetChannelCommandReply(ConnectSettings->session, channel, commandbuf);
        FIN_IF(!ok, SFTP_FAILED);
        FIN(SFTP_OK);
    }

    LIBSSH2_SFTP_ATTRIBUTES attr;
    attr.flags = LIBSSH2_SFTP_ATTR_ACMODTIME;
    attr.mtime = GetUnixTime(LastWriteTime);
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

    hr = (rc == 0) ? SFTP_OK : SFTP_FAILED;

fin:
    if (ConnectSettings->scponly) {
        if (channel)
            DisconnectShell(channel);
    }
    return hr;
}

bool SftpChmodW(SERVERID serverid, LPCWSTR RemoteName, LPCWSTR chmod)
{
    int hr = SFTP_FAILED;
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    FIN_IF(!ConnectSettings, SFTP_FAILED);

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
    attr.permissions = (chmod[0]-'0')*8*8 + (chmod[1]-'0')*8 + (chmod[2]-'0');   /* FIXME: make special function! */
    // 4 digits? -> use command line because libssh2_sftp_setstat fails to set extended attributes!
    // also when not using SFTP subsystem
    if (ConnectSettings->scponly || (chmod[3] >= '0' && chmod[3] <= '9')) {
        char reply[wdirtypemax];
        wcslcpy(msgbuf, L"chmod ", countof(msgbuf)-1);
        wcslcat(msgbuf, chmod, countof(msgbuf));
        wcslcat(msgbuf, L" ", countof(msgbuf));
        bool needquotes = IsNeedQuotesW(RemoteName);
        if (needquotes)
            wcslcat(msgbuf, L"\"", countof(msgbuf)-1);
        wcslcat(msgbuf, RemoteName, countof(msgbuf)-2);
        ReplaceBackslashBySlashW(msgbuf);
        if (needquotes)
            wcslcat(msgbuf, L"\"", countof(msgbuf)-1);
        reply[0] = 0;
        int rc = SftpQuoteCommand2W(serverid, NULL, msgbuf, reply, sizeof(reply) - 1);
        FIN_IF(rc < 0, SFTP_FAILED);
        /* FIXME: `rc` can be 1 or 0 */
        FIN(SFTP_OK);
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

    hr = (rc == 0) ? SFTP_OK : SFTP_FAILED;

fin:
    return (hr == SFTP_OK) ? true : false;
}

bool SftpLinkFolderTargetW(SERVERID serverid, LPWSTR RemoteName, size_t maxlen)
{
    int hr = SFTP_FAILED;
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    FIN_IF(!ConnectSettings, SFTP_FAILED);

    int rc = 0;
    WCHAR msgbuf[wdirtypemax];
    char filename[wdirtypemax];
    CopyStringW2A(ConnectSettings, RemoteName, filename, _countof(filename));
    ReplaceBackslashBySlash(filename);
    bool needquotes = IsNeedQuotes(filename);

    wcslcpy(msgbuf, L"Follow link: ", _countof(msgbuf));
    wcslcat(msgbuf, RemoteName, _countof(msgbuf));
    ReplaceBackslashBySlashW(msgbuf);
    ShowStatusW(msgbuf);

    if (strcmp(filename, "/~") == 0 || strcmp(filename, "/home/~") == 0) {   // go to home dir special link
        char ReturnedName[wdirtypemax];
        WCHAR cmdname[MAX_PATH];
        wcslcpy(cmdname, L"echo $HOME", countof(cmdname)-1);
        ReturnedName[0] = 0;
        int rc = SftpQuoteCommand2W(ConnectSettings, NULL, cmdname, ReturnedName, wdirtypemax - 1);
        if (rc == 0 && ReturnedName[0] == '/') {
            LPSTR p = strchr(ReturnedName, '\r');
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
        FIN(SFTP_OK);
    }

    char linktarget[wdirtypemax];
    linktarget[0] = 0;
    if (!ConnectSettings->scponly) {
        // first check whether the link really points to a directory:
        LIBSSH2_SFTP_ATTRIBUTES attr;
        int rc = -1;
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

        FIN_IF(rc != 0, SFTP_FAILED);   // path not found
        FIN_IF((attr.permissions & S_IFMT) != S_IFDIR, SFTP_FAILED);

        do {
            rc = libssh2_sftp_readlink(ConnectSettings->sftpsession, filename, linktarget, sizeof(linktarget)-2);
            if (EscapePressed()) {
                ConnectSettings->neednewchannel = true;
                break;
            }
            if (rc == LIBSSH2_ERROR_EAGAIN)
                IsSocketReadable(ConnectSettings->sock);  // sleep to avoid 100% CPU!
        } while (rc == LIBSSH2_ERROR_EAGAIN);

        FIN_IF(rc <= 0, SFTP_FAILED);   // it returns the length of the link target!
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
        bool isadir = false;
        int rc = SftpQuoteCommand2W(ConnectSettings, NULL, cmdname, ReturnedName, countof(ReturnedName) - 1);
        if (rc == 0) {
            _strlwr(ReturnedName);
            LPSTR p = strstr(ReturnedName, "size:");
            if (p) {
                LPSTR p2 = strchr(p,'\r');
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
        FIN_IF(!isadir, SFTP_FAILED);

        wcslcpy(cmdname, L"export LC_ALL=C\nreadlink -f ", countof(cmdname)-1);
        if (needquotes)
            wcslcat(cmdname, L"\"",countof(cmdname)-1);
        wcslcat(cmdname, RemoteName, countof(cmdname)-1);
        if (needquotes)
            wcslcat(cmdname, L"\"", countof(cmdname)-1);
        ReplaceBackslashBySlashW(cmdname);
        linktarget[0] = 0;     /* FIXME: nonsense ...... */
        rc = SftpQuoteCommand2W(ConnectSettings, NULL, cmdname, linktarget, _countof(linktarget) - 1);
        FIN_IF(rc != 0, SFTP_FAILED);
    }

    FIN_IF(linktarget[0] == 0, SFTP_FAILED);

    WCHAR linktargetW[wdirtypemax];
    CopyStringA2W(ConnectSettings, linktarget, linktargetW, _countof(linktargetW));
    ShowStatusW(L"Link target:");
    ShowStatusW(linktargetW);
    // handle the case of relative links!
    if (linktargetW[0] != '/') {
        ReplaceSlashByBackslashW(RemoteName);
        LPWSTR p = wcsrchr(RemoteName, '\\');
        if (p)     // cut off the name of the link itself!
            p[0] = 0;
        wcslcat(RemoteName, L"\\", maxlen);
        wcslcat(RemoteName, linktargetW, maxlen);
    } else {
        wcslcpy(RemoteName, linktargetW, maxlen);
    }
    hr = SFTP_OK;

fin:
    return (hr == SFTP_OK) ? true : false;
}

__forceinline
static bool isnumeric(char ch)
{
    return (ch >= '0' && ch <= '9');
}

void StripEscapeSequences(LPSTR msgbuf) noexcept
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
            continue;
        }
        if (pin[0] == '\\' && isnumeric(pin[1]) && isnumeric(pin[2]) && isnumeric(pin[3])) {
            // special characters are encoded in octal: \123
            char nrbuf[4];
            strlcpy(nrbuf, pin + 1, 3);
            *pout++ = (char)strtol(nrbuf, NULL, 8);
            pin += 4;
            continue;
        }
        *pout++ = *pin++;
    }
    *pout = 0;
}

void DisconnectShell(LIBSSH2_CHANNEL * channel) noexcept
{
    while (libssh2_channel_free(channel) == LIBSSH2_ERROR_EAGAIN) {
        if (EscapePressed())
            break;            /* FIXME: need to think of something better */
        //IsSocketReadable(ConnectSettings->sock);
    }
}

LIBSSH2_CHANNEL * ConnectChannel(LIBSSH2_SESSION * session) noexcept
{
    LIBSSH2_CHANNEL * channel = NULL;
    SYSTICKS starttime = get_sys_ticks();

    if (!session)
        return NULL;

    do {
        channel = libssh2_channel_open_session(session);
        if (!channel && get_ticks_between(starttime) > 1000)   /* FIXME: magic number! */
            if (EscapePressed())
                break;
    } while (!channel && libssh2_session_last_errno(session) == LIBSSH2_ERROR_EAGAIN);

    if (channel) {
        libssh2_channel_set_blocking(channel, 0);
        return channel;
    }

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
            _itoa(err, numbuf, 10);
            strlcat(errmsg, ": Error code ", sizeof(errmsg)-1);
            strlcat(errmsg, numbuf, sizeof(errmsg)-1);
            break;
    }
    ShowStatus(errmsg);
    return NULL;
}

bool SendChannelCommandNoEof(LIBSSH2_SESSION * session, LIBSSH2_CHANNEL * channel, LPCSTR command) noexcept
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

bool SendChannelCommand(LIBSSH2_SESSION * session, LIBSSH2_CHANNEL * channel, LPCSTR command) noexcept
{
    bool ret = SendChannelCommandNoEof(session, channel, command);
    while (libssh2_channel_send_eof(channel) == LIBSSH2_ERROR_EAGAIN) {
        if (EscapePressed())
            break;
    }
    return ret;
}

bool GetChannelCommandReply(LIBSSH2_SESSION * session, LIBSSH2_CHANNEL * channel, LPCSTR command) noexcept
{
    bool hasstderr = false;
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
    int status = libssh2_channel_get_exit_status(channel);
    return (status == 0) && !hasstderr;
}

static bool onlylinebreaks(LPCSTR msgbuf)
{
    while (*msgbuf) {
        if (*msgbuf != '\r' && *msgbuf != '\n')
            return false;
        msgbuf++;
    }
    return true;
}

bool ReadChannelLine(LIBSSH2_CHANNEL * channel, LPSTR line, size_t linelen, LPSTR msgbuf, size_t msgbuflen, LPSTR errbuf, size_t errbuflen)
{
    int rc, rcerr;
    SYSTICKS startdatatime = get_sys_ticks();
    SYSTICKS lastdatatime = startdatatime;
    bool endreceived = false;
    bool detectingcrlf = true;
    while (1) {
        // we need to read from both,  otherwise eof will not become true!
        size_t prevlen = strlen(msgbuf);
        size_t remain = msgbuflen - prevlen;
        size_t remainerr = errbuflen - strlen(errbuf);
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
            lastdatatime = get_sys_ticks();
            if (rc >= 0)
                p[rc] = 0;
            char* p1 = strchr(msgbuf, '\n');
            if (p1) {
                *p1++ = 0;
                size_t len = strlen(msgbuf);
                if (len && msgbuf[len - 1] == '\r') {
                    if (detectingcrlf && global_detectcrlf == -1)
                        global_detectcrlf = 1;
                    msgbuf[len - 1] = 0;
                } else if (detectingcrlf && global_detectcrlf == -1) {
                    global_detectcrlf = 0;
                }
                strlcpy(line, msgbuf, linelen);
                StripEscapeSequences(line);
                char* p0 = msgbuf;
                memmove(p0, p1, strlen(p1) + 1);
                return true;
            }
        }
        if (rc == LIBSSH2_ERROR_EAGAIN) {
            Sleep(50);
            SYSTICKS thisdatatime = get_sys_ticks();
            if (thisdatatime - lastdatatime < 1000 || thisdatatime - startdatatime < 5000)       /* FIXME: magic number! */
                continue;
        }
        if (endreceived && rc <= 0 && rc != LIBSSH2_ERROR_EAGAIN) {
            if (msgbuf[0] == 0 || onlylinebreaks(msgbuf))
                return false;

            if (detectingcrlf) {   // only append it once - do not use this appended to detect!
                detectingcrlf = false;
                strlcat(msgbuf, "\r\n", sizeof(msgbuf)-1);
            }
        }
    }
    return false;
}

void SftpSetTransferModeW(LPCWSTR mode)
{
    Global_TransferMode = (size_t)CharUpperW((LPWSTR)mode[0]) & 0xFF;
    if (Global_TransferMode == 'X')
        wcslcpy(Global_TextTypes, mode + 1, countof(Global_TextTypes)-1);
}

// returns -1 for error,  >=0 is the return value of the called function
int SftpQuoteCommand2(SERVERID serverid, LPCSTR remotedir, LPCSTR cmd, LPSTR reply, size_t replylen)
{
    int hr = -1;
    LIBSSH2_CHANNEL * channel = NULL;

    if (reply && replylen)
        reply[0] = 0;

    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    FIN_IF(!ConnectSettings, -1);

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
    FIN_IF(!channel, -1);

    // first set the current directory!
    if (remotedir) {
        strlcpy(msgbuf, "cd ", sizeof(msgbuf));
        bool needquotes = IsNeedQuotes(dirname);
        if (needquotes)
            strlcat(msgbuf, "\"", sizeof(msgbuf)-1);
        strlcat(msgbuf, dirname, sizeof(msgbuf)-2);
        if (needquotes)
            strlcat(msgbuf, "\"", sizeof(msgbuf)-1);
        strlcat(msgbuf, " && ", sizeof(msgbuf)-2);
    } else {
        msgbuf[0] = 0;
    }
    // then send the actual command!
    strlcat(msgbuf, cmdname, sizeof(msgbuf)-2);

    if (!SendChannelCommand(ConnectSettings->session, channel, msgbuf))
        FIN(-1);

    char errbuf[2048];
    msgbuf[0] = 0;
    errbuf[0] = 0;
    while (ReadChannelLine(channel, line, sizeof(line)-1, msgbuf, sizeof(msgbuf)-1, errbuf, sizeof(errbuf)-1)) {
        StripEscapeSequences(line);
        if (reply) {
            if (reply[0])
                strlcat(reply, "\r\n", replylen-1);
            strlcat(reply, line, replylen-1);
        } else {
            ShowStatus(line);
        }
    }

    int rc = libssh2_channel_get_exit_status(channel);
    FIN_IF(rc == 0, 0);  // OK
    hr = (rc < 0) ? 1 : rc;

    // read stderr
    LogMsg("Function return code: %d", rc);
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

fin:
    if (channel)
        DisconnectShell(channel);

    return hr;
}

// returns -1 for error, >=0 is the return value of the called function
int SftpQuoteCommand2W(SERVERID serverid, LPCWSTR remotedir, LPCWSTR cmd, LPSTR reply, size_t replylen)
{
    int hr = -1;
    LIBSSH2_CHANNEL * channel = NULL;

    if (reply && replylen)
        reply[0] = 0;

    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    FIN_IF(!ConnectSettings, -1);

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
    FIN_IF(!channel, -1);

    // first set the current directory!
    if (remotedir) {
        strlcpy(msgbuf, "cd ", sizeof(msgbuf)-1);
        bool needquotes = IsNeedQuotes(dirname);
        if (needquotes)
            strlcat(msgbuf, "\"", sizeof(msgbuf)-1);
        strlcat(msgbuf, dirname, sizeof(msgbuf)-3);
        if (needquotes)
            strlcat(msgbuf, "\"", sizeof(msgbuf)-1);
        strlcat(msgbuf, " && ", sizeof(msgbuf)-3);
    } else {
        msgbuf[0] = 0;
    }
    // then send the actual command!
    strlcat(msgbuf, cmdname, sizeof(msgbuf)-3);

    if (!SendChannelCommand(ConnectSettings->session, channel, msgbuf))
        FIN(-1);

    char errbuf[2048];
    msgbuf[0] = 0;
    errbuf[0] = 0;
    SYSTICKS starttime = get_sys_ticks();
    SYSTICKS lasttime = starttime;
    int loop = 0;
    while (ReadChannelLine(channel, line, sizeof(line)-1, msgbuf, sizeof(msgbuf)-1, errbuf, sizeof(errbuf)-1)) {
        StripEscapeSequences(line);
        if (reply) {
            if (reply[0])
                strlcat(reply, "\r\n", replylen);
            strlcat(reply, line, replylen);
        } else {
            CopyStringA2W(ConnectSettings, line, wline, countof(wline), false);
            ShowStatusW(wline);
        }
        if (get_ticks_between(starttime) > 2000)   /* FIXME: magic number! */
            if (ProgressLoop("QUOTE", 0, 100, &loop, &lasttime))
                break;
    }

    int rc = libssh2_channel_get_exit_status(channel);
    FIN_IF(rc == 0, 0);  // OK
    hr = (rc < 0) ? 1 : rc;

    // read stderr
    LogMsg("Function return code: %d", rc);
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

fin:
    if (channel)
        DisconnectShell(channel);

    return hr;
}

bool SftpQuoteCommand(SERVERID serverid, LPCSTR remotedir, LPCSTR cmd)
{
    int rc = SftpQuoteCommand2(serverid, remotedir, cmd, NULL, 0);
    return rc >= 0;
}

LPSTR FindStatString(LPSTR searchin, LPSTR searchfor, LPSTR deletedchar)
{
    deletedchar[0] = 0;
    LPSTR p = strstr(searchin, searchfor);
    if (p) {
        LPSTR p2;
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

static LPWSTR FindStatStringW(LPWSTR searchin, LPWSTR searchfor, LPWSTR deletedchar)
{
    deletedchar[0] = 0;
    LPWSTR p = wcsstr(searchin, searchfor);
    if (p) {
        LPWSTR p2;
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
bool g_command_ls;

INT_PTR WINAPI PropDlgProc(HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam)
{
    char *p, *p2;

    switch (Message) {
    case WM_INITDIALOG: {
        char ch;
        WCHAR chw, *wp;
        HDC dc = GetDC(hWnd);
        int height = -MulDiv(8, GetDeviceCaps(dc, LOGPIXELSY), 72);
        LPCSTR faceName = "Courier New";
        DWORD family = FIXED_PITCH | FF_DONTCARE;
        HFONT fixedfont = CreateFontA(height, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, family, faceName);
        ReleaseDC(hWnd, dc);
        if (fixedfont)
            SendDlgItemMessage(hWnd, IDC_PROP_RAWSTAT, WM_SETFONT, (WPARAM)fixedfont, true);

        SetDlgItemTextW(hWnd, IDC_PROP_RAWSTAT, g_statreplyW);

        if (!g_command_ls) {
            WCHAR *wp;
            wp = FindStatStringW(g_statreplyW, L"File:", &chw);
            if (wp) {
                SetDlgItemTextW(hWnd, IDC_PROP_NAME, wp);
                wp[wcslen(wp)] = chw;
            }
            p = FindStatString(g_statreplyA, "Size:", &ch);
            if (p) {
                SetDlgItemTextA(hWnd, IDC_PROP_SIZE, p);
                p[strlen(p)] = ch;
            }
            p = FindStatString(g_statreplyA, "Access:", &ch);
            if (p) {
                SetDlgItemTextA(hWnd, IDC_PROP_PERMISSIONS, p);
                p[strlen(p)] = ch;
            }
            p = FindStatString(g_statreplyA, "Uid:", &ch);
            if (p) {
                SetDlgItemTextA(hWnd, IDC_PROP_OWNER, p);
                p[strlen(p)] = ch;
            }
            p = FindStatString(g_statreplyA, "Gid:", &ch);
            if (p) {
                SetDlgItemTextA(hWnd, IDC_PROP_GROUP, p);
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
                    sscanf(p, "%hd %hd %hd %hd %hd %hd %hd %d", 
                        &tdt.wYear, &tdt.wMonth, &tdt.wDay, &tdt.wHour, 
                        &tdt.wMinute, &tdt.wSecond, &tdt.wMilliseconds, &timezone);
                    tzhours = labs(timezone) / 100;
                    tzminutes = labs(timezone) - 100*tzhours;
                    SystemTimeToFileTime(&tdt, &ft);
                    INT64 tm = *(PINT64)&ft;
                    INT64 delta = (INT64)WINDOWS_TICK * 60 * (tzminutes + 60 * tzhours);
                    tm = (timezone > 0) ? tm - delta : tm + delta;
                    SetInt64ToFileTime(&ft, tm);
                    FileTimeToLocalFileTime(&ft, &lft);
                    FileTimeToSystemTime(&lft, &tdt);
                    char buf[128];
                    sprintf_s(buf, sizeof(buf), "%d-%02d-%02d %02d:%02d:%02d (local)",
                        tdt.wYear, tdt.wMonth, tdt.wDay, tdt.wHour, tdt.wMinute, tdt.wSecond);
                    SetDlgItemText(hWnd, IDC_PROP_MODIFIED, buf);
                } else {
                    SetDlgItemText(hWnd, IDC_PROP_MODIFIED, p);
                }
            }
        } else {  // g_command_ls
            char abuf[wdirtypemax];
            wp = wcsrchr(g_filenameW, '/');
            wp = (wp == NULL) ? g_filenameW : wp + 1;
            walcopy(abuf, wp, sizeof(abuf)-1);
            SetDlgItemTextW(hWnd, IDC_PROP_NAME, g_filenameW);
            walcopy(abuf, g_filenameW, sizeof(abuf)-1);
            p = strstr(g_statreplyA, abuf);
            if (!p) {
                walcopy(abuf, wp, sizeof(abuf)-1);
                p = strstr(g_statreplyA, abuf);
            }
            if (p && p > g_statreplyA) {
                *p-- = 0;
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
                SetDlgItemTextA(hWnd, IDC_PROP_MODIFIED, p2);
                p[1] = 0;
                while (p > g_statreplyA && p[0] >= '0' && p[0] <= '9')
                    p--;  // find size
                if (p[0] == ' ')
                    p++;
                SetDlgItemTextA(hWnd, IDC_PROP_SIZE, p);

                if (p > g_statreplyA) {
                    p--;
                    while (p > g_statreplyA && p[0] == ' ')
                        p--;
                    p[1] = 0;
                    while (p > g_statreplyA && p[0] != ' ')
                        p--; //group
                    p2 = p;
                    if (p2[0] == ' ') p2++;
                    SetDlgItemTextA(hWnd, IDC_PROP_GROUP, p2);
                    while (p > g_statreplyA && p[0] == ' ')
                        p--;
                    p[1] = 0;
                    while (p > g_statreplyA && p[0]!=' ')
                        p--; //group
                    if (p[0] == ' ') p++;
                    SetDlgItemTextA(hWnd, IDC_PROP_OWNER, p);
                }
                // permissions
                p = strchr(g_statreplyA, ' ');
                if (p) {
                    p[0] = 0;
                    SetDlgItemTextA(hWnd, IDC_PROP_PERMISSIONS, g_statreplyA);
                }
            }
        }
        // trying to center the About dialog
        SetDialogPosToCenter(hWnd);
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

void SftpShowPropertiesW(SERVERID serverid, LPCWSTR remotename)
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
    bool needquotes = IsNeedQuotesW(filename);
    if (needquotes)
        wcslcat(cmdname, L"\"", countof(cmdname)-1);
    wcslcat(cmdname, filename, countof(cmdname)-1);
    if (needquotes)
        wcslcat(cmdname, L"\"", countof(cmdname)-1);
    replyA[0] = 0;
    replyW[0] = 0;
    g_statreplyA = NULL;
    g_statreplyW = NULL;
    int rc = SftpQuoteCommand2W(serverid, NULL, cmdname, replyA, sizeof(replyA) - 1);
    if (rc >= 0) {
        CopyStringA2W(ConnectSettings, replyA, replyW, _countof(replyW));
        walcopy(replyA, replyW, sizeof(replyA)-1);
        g_command_ls = false;
        g_statreplyA = replyA;
        g_statreplyW = replyW;
    }

    bool statworked = (g_statreplyW != NULL);
    if (statworked) {
        WCHAR chw = 0;
        LPWSTR wp = FindStatStringW(g_statreplyW, L"File:", &chw);
        if (wp)
            wp[wcslen(wp)] = chw;
        else 
            statworked = false;
    }
    if (!statworked) {  // stat failed -> try "ls -la filename"
        wcslcpy(replyW, cmdname + 5, countof(replyW)-1);
        wcslcpy(cmdname, L"ls -la ", countof(cmdname)-1);
        wcslcat(cmdname, replyW, wdirtypemax-1);
        int rc = SftpQuoteCommand2W(serverid, NULL, cmdname, replyA, sizeof(replyA) - 1);
        if (rc >= 0) {
            g_command_ls = true;
            CopyStringA2W(ConnectSettings, replyA, replyW, _countof(replyW));
            walcopy(replyA, replyW, sizeof(replyA)-1);
            g_statreplyA = replyA;
            g_statreplyW = replyW;
        }
    }

    if (g_statreplyA) {
        g_filenameW = filename;
        DialogBoxW(hinst, MAKEINTRESOURCEW(IDD_PROPERTIES), GetActiveWindow(), PropDlgProc);
    }
}

void SftpGetLastActivePathW(SERVERID serverid, LPWSTR RelativePath, size_t maxlen)
{
    RelativePath[0] = 0;
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (ConnectSettings) {
        wcslcpy(RelativePath, ConnectSettings->lastactivepath, maxlen);
    }
}

bool SftpSupportsResume(SERVERID serverid)
{
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    if (!ConnectSettings)
        return false;
    return !ConnectSettings->scponly;
}

__forceinline
static bool IsHexChar(char ch)
{
    return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
}

static bool CheckChecksumSupport(LPCSTR buf, LPCSTR type, size_t hashlen)
{
    LPCSTR p = strstr(buf, type);
    if (p) {
        p += strlen(type);
        while (p[0] && !IsHexChar(p[0])) p++;
        LPCSTR pend = p;
        while (IsHexChar(pend[0])) pend++;
        if ((pend - p) == hashlen)
            return true;
    }
    return false;
}


/* returned bit mask FS_CHK_XXXX */
int SftpServerSupportsChecksumsW(SERVERID serverid, LPCWSTR RemoteName)
{
    int hr = 0;
    LIBSSH2_CHANNEL * channel = NULL;
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    FIN_IF(!ConnectSettings, 0);

    ShowStatusW(L"Check whether the server supports checksum functions...");
    
    channel = ConnectChannel(ConnectSettings->session);
    FIN_IF(!channel, 0);
    LPCSTR cmd = "echo md5\nmd5sum\necho sha1\nsha1sum\necho sha256\nsha256sum\necho sha512\nsha512sum\n";
    if (!SendChannelCommand(ConnectSettings->session, channel, cmd))
        FIN(0);

    char buf[4096];
    char errbuf[1024];
    int buflen = 0;
    while (!libssh2_channel_eof(channel)) {
        int len = libssh2_channel_read(channel, buf + buflen, (int)sizeof(buf) - buflen - 1);
        if (len > 0)
            buflen += len;
        if (!libssh2_channel_eof(channel))
            libssh2_channel_read_stderr(channel, errbuf, sizeof(errbuf)-1); // ignore errors
        if (EscapePressed())
            break;
    }
    hr = 0;
    buf[buflen] = 0;
    // Analyse result: It should return
    // d41d8cd98f00b204e9800998ecf8427e  -
    // da39a3ee5e6b4b0d3255bfef95601890afd80709  -
    // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  -
    if (CheckChecksumSupport(buf, "md5", 32))
        hr |= FS_CHK_MD5;
    if (CheckChecksumSupport(buf, "sha1", 40))
        hr |= FS_CHK_SHA1;
    if (CheckChecksumSupport(buf, "sha256", 64))
        hr |= FS_CHK_SHA256;
    if (CheckChecksumSupport(buf, "sha512", 128))
        hr |= FS_CHK_SHA512;

fin:
    if (channel)
        DisconnectShell(channel);
    return hr;
}

HANDLE SftpStartFileChecksumW(int ChecksumType, SERVERID serverid, LPCWSTR RemoteName)
{
    int hr = SFTP_FAILED;
    LIBSSH2_CHANNEL * channel = NULL;
    pConnectSettings ConnectSettings = (pConnectSettings)serverid;
    FIN_IF(!ConnectSettings, SFTP_FAILED);

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
        FIN(SFTP_FAILED);
    }

    bool needquotes = IsNeedQuotes(filename);
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

    channel = ConnectChannel(ConnectSettings->session);
    FIN_IF(!channel, SFTP_FAILED);

    // Request VT102 terminal, so character 3 works as abort!
    int rc;
    do {
        rc = libssh2_channel_request_pty_ex(channel, "vt102", 5, "", 0, 80, 40, 640, 480);
    } while (rc == LIBSSH2_ERROR_EAGAIN);

    if (!SendChannelCommandNoEof(ConnectSettings->session, channel, commandbuf))
        FIN(SFTP_FAILED);

    hr = SFTP_OK;

fin:
    if (hr != SFTP_OK) {
        if (channel)
            DisconnectShell(channel);
        return NULL;
    }
    return (HANDLE)channel;
}


int SftpGetFileChecksumResultW(bool WantResult, HANDLE ChecksumHandle, SERVERID serverid, LPSTR checksum, size_t maxlen)
{
    int hr = 0;
    LIBSSH2_CHANNEL * channel = (LIBSSH2_CHANNEL*)ChecksumHandle;
    FIN_IF(!channel, 0);
    char buf[2048];

    if (WantResult) {
        char errbuf[1024];
        int buflen = 0;
        while (!libssh2_channel_eof(channel)) {
            int len2 = libssh2_channel_read(channel, buf + buflen, sizeof(buf) - buflen - 1);
            if (len2 <= 0)
                break;
            buflen += len2;
            if (!libssh2_channel_eof(channel))
                libssh2_channel_read_stderr(channel, errbuf, sizeof(errbuf)-1); // ignore errors
            if (EscapePressed())
                break;
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
            FIN(len);
        }
        if (libssh2_channel_eof(channel))
            FIN(FS_CHK_ERR_FAIL);

        FIN(FS_CHK_ERR_BUSY);    // didn't receive the checksum yet!
    }

    if (!libssh2_channel_eof(channel)) {
        buf[0] = 3;
        while (libssh2_channel_write_ex(channel, 0, buf, 1) == LIBSSH2_ERROR_EAGAIN) { // Ctrl+C!
            if (EscapePressed())
                break;
        }
    }
    hr = 0;

fin:
    if (channel)
        DisconnectShell(channel);
    return hr;
}

VOID CALLBACK TimerProc(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime) noexcept
{
    if (uMsg == WM_TIMER) {
        ::KillTimer(hwnd, idEvent);
        if (idEvent > USHRT_MAX) {
            pConnectSettings ConnectSettings = (pConnectSettings)idEvent;
            LogMsg("KEEP-ALIVE \\%s", ConnectSettings->DisplayName);
            int iRet = 0;
            libssh2_keepalive_send(ConnectSettings->session, &iRet);
            int elapse = (iRet > 0) ? iRet : ConnectSettings->keepAliveIntervalSeconds;
            ::SetTimer(hwnd, idEvent, elapse * 1000, TimerProc);
        }
    }
}

