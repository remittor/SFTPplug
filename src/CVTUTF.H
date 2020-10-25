/* ================================================================ */
/*
File: ConvertUTF.h
Author: Mark E. Davis
 * Copyright 1994-1999 IBM Corp.. All rights reserved.
 * 
 * IBM Corp. grants the user a nonexclusive right and license to use, execute,
 * display, modify, and prepare and/or have prepared derivative works of the
 * code, including but not limited to creating software products which
 * incorporate the code or derivative works thereof.
 * 
 * IBM Corp. grants the user a right and license to reproduce and distribute
 * the code as long as this entire copyright notice is reproduced in the code
 * or reproduction.
 * 
 * The code is provided AS-IS, and IBM Corp. disclaims all warranties,
 * either express or implied, including, but not limited to implied
 * warranties of merchantability and fitness for a particular purpose.
 * In no event will IBM Corp. be liable for any damages whatsoever (including,
 * without limitation, damages for loss of business profits, business
 * interruption, loss of business information, or other pecuniary
 * loss) arising out of the use or inability to use this code, even
 * if IBM Corp. has been advised of the possibility of such damages.
 * Because some states do not allow the exclusion or limitation of
 * liability for consequential or incidental damages, the above
 * limitation may not apply to you.
*/
/* ================================================================ */

#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================ */
/*  The following 4 definitions are compiler-specific.
  I would use wchar_t for UCS2/UTF16, except that the C standard
  does not guarantee that it has at least 16 bits, so wchar_t is
  no less portable than unsigned short!
*/

typedef unsigned long   UCS4;
typedef unsigned short  UCS2;
typedef unsigned short  UTF16;
typedef unsigned char   UTF8;

/* ================================================================ */
/*  Each of these routines converts the text between *sourceStart and 
sourceEnd, putting the result into the buffer between *targetStart and
targetEnd. Note: the end pointers are *after* the last item: e.g. 
*(sourceEnd - 1) is the last item.

  The return result indicates whether the conversion was successful,
and if not, whether the problem was in the source or target buffers.

  After the conversion, *sourceStart and *targetStart are both
updated to point to the end of last text successfully converted in
the respective buffers.
*/

#define CVT_OK                0   /* conversion successful */
#define CVT_sourceExhausted (-1)  /* partial character in source, but hit end */
#define CVT_targetExhausted (-2)  /* insuff. room in target for conversion */


int ConvertUCS4toUTF16 (UCS4** sourceStart, const UCS4* sourceEnd, UTF16** targetStart, const UTF16* targetEnd);

int ConvertUTF16toUCS4 (UTF16** sourceStart, UTF16* sourceEnd, UCS4** targetStart, const UCS4* targetEnd);

int ConvertUTF16toUTF8 (UTF16** sourceStart, const UTF16* sourceEnd, UTF8** targetStart, const UTF8* targetEnd);

int ConvertUTF8toUTF16 (UTF8** sourceStart, UTF8* sourceEnd, UTF16** targetStart, const UTF16* targetEnd);

int ConvertUCS4toUTF8 (UCS4** sourceStart, const UCS4* sourceEnd, UTF8** targetStart, const UTF8* targetEnd);

int ConvertUTF8toUCS4 (UTF8** sourceStart, UTF8* sourceEnd, UCS4** targetStart, const UCS4* targetEnd);

#ifdef __cplusplus
}
#endif

