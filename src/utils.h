#pragma once

// Helper functions
BOOL ConvertIsoDateToDateTime(char* pdatetimefield, FILETIME *ft);
BOOL CreateIsoDateString(FILETIME *ft, char* buf); //yyyymmddhhmmss
char* strlcpy(char* p, const char* p2, int maxlen);
char* strlcat(char* p, const char* p2, int maxlen);
WCHAR* wcslcpy2(WCHAR* p,const WCHAR* p2,int maxlen);
WORD Crc16CalcBlock(char* p, int len, WORD crc16);
LPTSTR strcatbackslash(LPTSTR thedir);
LPTSTR strlcatforwardslash(LPTSTR thedir, int maxlen);
char* strlcatbackslash(char* thedir, int maxlen);
WCHAR* wcslcatbackslash(WCHAR* thedir, int maxlen);
void cutlastbackslash(char* thedir);
char* ReplaceBackslashBySlash(char* thedir);
WCHAR* ReplaceBackslashBySlashW(WCHAR* thedir);
char* ReplaceSlashByBackslash(char* thedir);
WCHAR* ReplaceSlashByBackslashW(WCHAR* thedir);
char* FormValidUrl(char* url, int maxlen, BOOL sendurlasunicode);
BOOL UnixTimeToLocalTime(long* mtime, LPFILETIME ft);
void MimeEncode(char* inputstr, char* outputstr, int maxlen);
int MimeDecode(char* inputstr, int srclen, char* outputstr, int maxlen);
void ReplaceEnvVars(char* buf, int buflen);
void ReplaceSubString(char* buf, const char* fromstr, const char* tostr, int maxlen);
BOOL ParseAddress(char* serverstring, char* addr,  unsigned short* port, int defport);
BOOL IsNumericIPv6(char* addr);
bool MultiFileMatchW(WCHAR* wild, WCHAR* name);


#ifndef countof
#define countof(array) (sizeof(array)/sizeof(array[0]))
#endif

#define LoadStr(s, i) LoadString(hinst, (i), (s), countof(s)-1)

#ifndef _itoa_s
#define _itoa_s(nr,buf,sz,rdx) (_itoa(nr,buf,rdx))
#endif
