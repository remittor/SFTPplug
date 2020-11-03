#pragma once

/* Define to 1 if you have the `EVP_aes_128_ctr' function. */
#define HAVE_EVP_AES_128_CTR 1

/* Define if you have the bcrypt library. */
#undef HAVE_LIBBCRYPT

/* Define if you have the crypt32 library. */
#undef HAVE_LIBCRYPT32

/* to make a symbol visible */
#define LIBSSH2_API

/* Enable clearing of memory before being freed */
#undef LIBSSH2_CLEAR_MEMORY

/* Enable "none" cipher -- NOT RECOMMENDED */
#undef LIBSSH2_CRYPT_NONE

/* Enable newer diffie-hellman-group-exchange-sha1 syntax */
#define LIBSSH2_DH_GEX_NEW 1

/* Compile in zlib support */
#undef LIBSSH2_HAVE_ZLIB

/* Enable "none" MAC -- NOT RECOMMENDED */
#undef LIBSSH2_MAC_NONE

/* Use OpenSSL */
#define LIBSSH2_OPENSSL

/* Use Windows CNG */
#undef LIBSSH2_WINCNG
