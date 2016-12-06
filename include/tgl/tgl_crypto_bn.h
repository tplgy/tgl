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

#ifndef __TGL_CRYPTO_BN_H__
#define __TGL_CRYPTO_BN_H__

#include <openssl/bn.h>

#include <cassert>
#include <ostream>

typedef BN_CTX TGLC_bn_ctx;
typedef BIGNUM TGLC_bn;

inline static TGLC_bn_ctx* TGLC_bn_ctx_new(void)
{
    return BN_CTX_new();
}

inline static void TGLC_bn_ctx_free(TGLC_bn_ctx* ctx)
{
    BN_CTX_free(ctx);
}

inline static TGLC_bn* TGLC_bn_new(void)
{
    return BN_new();
}

inline static void TGLC_bn_free(TGLC_bn* bn)
{
    BN_free(bn);
}

inline static void TGLC_bn_clear_free(TGLC_bn* bn)
{
    BN_clear_free(bn);
}

inline static int TGLC_bn_cmp(const TGLC_bn* a, const TGLC_bn* b)
{
    return BN_cmp(a, b);
}

inline static int TGLC_bn_is_prime(const TGLC_bn* bn, int checks, void(*callback)(int, int, void *), TGLC_bn_ctx* ctx, void* cb_arg)
{
    return BN_is_prime(bn, checks, callback, ctx, cb_arg);
}

inline static int TGLC_bn_bn2bin(const TGLC_bn* bn, unsigned char* to)
{
    return BN_bn2bin(bn, to);
}

inline static TGLC_bn* TGLC_bn_bin2bn(const unsigned char* s, int len, TGLC_bn* ret)
{
    return BN_bin2bn(s, len, ret);
}

inline static int TGLC_bn_set_word(TGLC_bn* bn, unsigned long w)
{
    return BN_set_word(bn, w);
}

inline static unsigned long TGLC_bn_get_word(const TGLC_bn* bn)
{
    return BN_get_word(bn);
}

inline static int TGLC_bn_num_bits(const TGLC_bn* bn)
{
    return BN_num_bits(bn);
}

inline static void TGLC_bn_sub(TGLC_bn* r, const TGLC_bn* a, const TGLC_bn* b)
{
    int res = BN_sub(r, a, b);
    (void)res;
    assert(res);
}

inline static int TGLC_bn_div(TGLC_bn* dv, TGLC_bn* rem, const TGLC_bn* a, const TGLC_bn* d, TGLC_bn_ctx* ctx)
{
    return BN_div(dv, rem, a, d, ctx);
}

inline static int TGLC_bn_mod_exp(TGLC_bn* r, const TGLC_bn* a, const TGLC_bn* p, const TGLC_bn* m, TGLC_bn_ctx* ctx)
{
    return BN_mod_exp(r, a, p, m, ctx);
}

inline static std::ostream& operator<<(std::ostream& os, const TGLC_bn& bn)
{
    char* hex = BN_bn2hex(&bn);
    os << hex;
    free(hex);
    return os;
}

inline static int TGLC_bn_num_bytes(const TGLC_bn* bn)
{
    return (TGLC_bn_num_bits(bn) + 7) / 8;
}

inline static int TGLC_bn_mod(TGLC_bn* rem, const TGLC_bn* m, const TGLC_bn* d, TGLC_bn_ctx* ctx)
{
    return TGLC_bn_div(nullptr, rem, m, d, ctx);
}

struct TGLC_bn_deleter {
    void operator()(TGLC_bn* bn)
    {
        TGLC_bn_free(bn);
    }
};

struct TGLC_bn_clear_deleter {
    void operator()(TGLC_bn* bn)
    {
        TGLC_bn_clear_free(bn);
    }
};

struct TGLC_bn_ctx_deleter {
    void operator()(TGLC_bn_ctx* ctx)
    {
        TGLC_bn_ctx_free(ctx);
    }
};

#endif
