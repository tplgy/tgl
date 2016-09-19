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

typedef RSA TGLC_rsa;

inline static TGLC_rsa* TGLC_rsa_new(unsigned long e, int n_bytes, const unsigned char* n)
{
    RSA* ret = RSA_new();
    ret->e = TGLC_bn_new();
    TGLC_bn_set_word(ret->e, e);
    ret->n = TGLC_bn_bin2bn(n, n_bytes, nullptr);
    return ret;
}

inline static TGLC_bn* TGLC_rsa_n(const TGLC_rsa* key)
{
    return key->n;
}

inline static TGLC_bn* TGLC_rsa_e(const TGLC_rsa* key)
{
    return key->e;
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
