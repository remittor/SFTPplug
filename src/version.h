#pragma once

#define WFX_VER_MAJOR     3
#define WFX_VER_MINOR     0

#define WFX_VER_GET_STR(num)  WFX_VER_GET_STR2(num)
#define WFX_VER_GET_STR2(num) #num

#define WFX_INTERNAL_NAME "sftpplug"
#define WFX_DESCRIPTION   "SFTP-plugin"
#define WFX_VERSION       WFX_VER_GET_STR(WFX_VER_MAJOR) "." WFX_VER_GET_STR(WFX_VER_MINOR)
#define WFX_RC_VERSION    WFX_VER_MAJOR, WFX_VER_MINOR, 0, 0

#define WFX_COPYRIGHT     "\xA9 2008-2021 Christian Ghisler"      // A9 for (c)
#define WFX_COMPANY_NAME  "Ghisler Software GmbH"
#define WFX_SOURCES       "https://github.com/remittor/SFTPplug"
#define WFX_LICENSE       "https://github.com/remittor/SFTPplug/blob/master/License.txt"

#ifdef WFX_DEBUG
#define WFX_FILE_DESC     WFX_DESCRIPTION " (DEBUG)"
#else
#define WFX_FILE_DESC     WFX_DESCRIPTION
#endif

#ifdef _WIN64
#define WFX_ORIG_FILENAME WFX_INTERNAL_NAME ".wfx64"
#else
#define WFX_ORIG_FILENAME WFX_INTERNAL_NAME ".wfx"
#endif

