/*
    This file is part of tgl-library

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

    Copyright Ben Wiederhake 2015
*/

#ifndef __TGL_CRYPTO_RSA_PEM_H__
#define __TGL_CRYPTO_RSA_PEM_H__

#include "tgl_crypto_bn.h"

#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <cstdio> /* FILE */
#include <cstring>

typedef RSA TGLC_rsa;

#if OPENSSL_VERSION_NUMBER < 0x10100000L

static inline int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
   /* If the fields n and e in r are NULL, the corresponding input
    * parameters MUST be non-NULL for n and e.  d may be
    * left NULL (in case only the public key is used).
    */
   if ((r->n == NULL && n == NULL) || (r->e == NULL && e == NULL))
       return 0;

   if (n != NULL) {
       BN_free(r->n);
       r->n = n;
   }
   if (e != NULL) {
       BN_free(r->e);
       r->e = e;
   }
   if (d != NULL) {
       BN_free(r->d);
       r->d = d;
   }

   return 1;
}

static inline void RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
  if (n != NULL)
    *n = r->n;
  if (e != NULL)
    *e = r->e;
  if (d != NULL)
    *d = r->d;
}

#endif

inline static TGLC_rsa* TGLC_rsa_new(unsigned long e, int n_bytes, const unsigned char* n)
{
    RSA* ret = RSA_new();
    ret->e = TGLC_bn_new();
    TGLC_bn_set_word(ret->e, e);
    RSA_set0_key(ret, TGLC_bn_bin2bn(n, n_bytes, nullptr), ret->e, nullptr);
    return ret;
}

inline static const TGLC_bn* TGLC_rsa_n(const TGLC_rsa* key)
{
    const TGLC_bn *n;
    RSA_get0_key(key, &n, nullptr, nullptr);
    return n;
}

inline static const TGLC_bn* TGLC_rsa_e(const TGLC_rsa* key)
{
    const TGLC_bn *e;
    RSA_get0_key(key, nullptr, &e, nullptr);
    return e;
}

inline static void TGLC_rsa_free(TGLC_rsa* key)
{
    RSA_free(key);
}

inline static TGLC_rsa* TGLC_pem_read_RSAPublicKey(const char* pem)
{
    BIO* bufio = BIO_new_mem_buf(const_cast<char*>(pem), strlen(pem));
    RSA* res = PEM_read_bio_RSAPublicKey(bufio, nullptr, 0, nullptr);
    BIO_free(bufio);
    return res;
}

#endif
