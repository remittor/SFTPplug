#pragma once

#define falink   0x0040   // Flag for link, equ FILE_ATTRIBUTE_DEVICE

#define FLAG_HAVE_LONGDATETYPE   0x0001

bool ReadDirLineUNIX(LPWSTR lpStr, LPWSTR name, int maxlen, PINT64 sizefile, LPFILETIME datetime, PDWORD attr, PDWORD UnixAttr, int flags);

