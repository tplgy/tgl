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

    Copyright Nikolay Durov, Andrey Lopatin 2012-2013
              Vitaly Valtman 2013-2015
    Copyright Topology LP 2016
*/

#include "mtproto_common.h"

#include "auto/auto.h"
#include "crypto/crypto_rand.h"
#include "crypto/crypto_sha.h"
#include "tgl/tgl_log.h"
#include "tools.h"

#include <assert.h>
#include <memory>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#ifdef WIN32
#include <winsock2.h>
#else
#include <netdb.h>
#endif

#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach.h>
#endif

#include <errno.h>

#ifndef O_BINARY
#define O_BINARY 0
#endif

namespace {

#ifndef WIN32
static int get_random_bytes(unsigned char* buf, int n)
{
    int r = 0, h = open("/dev/random", O_RDONLY | O_NONBLOCK);
    if (h >= 0) {
        r = read(h, buf, n);
        if (r > 0) {
            TGL_DEBUG("added " << r << " bytes of real entropy to secure random numbers seed");
        } else {
            r = 0;
        }
        close(h);
    }

    if (r < n) {
        h = open("/dev/urandom", O_RDONLY);
        if (h < 0) {
            return r;
        }
        int s = read(h, buf + r, n - r);
        close(h);
        if (s > 0) {
            r += s;
        }
    }

    if (r >= (int) sizeof(long)) {
        *(long *)buf ^= lrand48();
        srand48(*(long *)buf);
    }

    return r;
}
#else
static HCRYPTPROV hCryptoServiceProvider = 0;
static int get_random_bytes(unsigned char* buf, int n)
{
    if (hCryptoServiceProvider == 0) {
        /* Crypto init */
        CryptAcquireContextA(&hCryptoServiceProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    }

    if (!CryptGenRandom(hCryptoServiceProvider, n, buf)) {
        return -1;
    }

    return n;
}
#endif

/* RDTSC */
#if defined(__i386__)
#define HAVE_RDTSC
static __inline__ uint64_t rdtsc(void)
{
    uint64_t x;
    __asm__ volatile("rdtsc" : "=A" (x));
    return x;
}
#elif defined(__x86_64__)
#define HAVE_RDTSC
static __inline__ uint64_t rdtsc(void)
{
    uint32_t hi, lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t) lo) | (((uint64_t) hi) << 32);
}
#endif

}

namespace tgl {
namespace impl {

void tgl_prng_seed(const char* password_filename, int password_length)
{
    double t = tgl_get_system_time();
    TGLC_rand_add(&t, sizeof(t), 4.0);
#ifdef HAVE_RDTSC
    uint64_t r = rdtsc();
    TGLC_rand_add(&r, 8, 4.0);
#endif
    unsigned short p = getpid();
    TGLC_rand_add(&p, sizeof(p), 0.0);
#ifndef WIN32
    p = getppid();
    TGLC_rand_add(&p, sizeof(p), 0.0);
#endif
    unsigned char rb[32];
    int s = get_random_bytes(rb, 32);
    if (s > 0) {
        TGLC_rand_add(rb, s, s);
    }
    memset(rb, 0, sizeof(rb));
    if (password_filename && password_length > 0) {
        int fd = open(password_filename, O_RDONLY | O_BINARY);
        if (fd < 0) {
            TGL_WARNING("Warning: fail to open password file - \"" << password_filename << "\", " << strerror(errno) << ".");
        } else {
            unsigned char* a = static_cast<unsigned char*>(calloc(1, password_length));
            int l = read(fd, a, password_length);
            if (l < 0) {
                TGL_WARNING("Warning: fail to read password file - \"" << password_filename << "\", " << strerror(errno) << ".");
            } else {
                TGL_DEBUG("read " << l << " bytes from password file.");
                TGLC_rand_add(a, l, l);
            }
            close(fd);
            tgl_secure_free(a, password_length);
        }
    }
}

int tgl_serialize_bignum(const TGLC_bn* b, char* buffer, int maxlen)
{
    int itslen = TGLC_bn_num_bytes(b);
    int reqlen;
    if (itslen < 254) {
        reqlen = itslen + 1;
    } else {
        reqlen = itslen + 4;
    }
    int newlen = (reqlen + 3) & -4;
    int pad = newlen - reqlen;
    reqlen = newlen;
    if (reqlen > maxlen) {
        return -reqlen;
    }
    if (itslen < 254) {
        *buffer++ = itslen;
    } else {
        *(int *)buffer = (itslen << 8) + 0xfe;
        buffer += 4;
    }
    int l = TGLC_bn_bn2bin(b, reinterpret_cast<unsigned char*>(buffer));
    assert(l == itslen);
    buffer += l;
    while (pad --> 0) {
        *buffer++ = 0;
    }
    return reqlen;
}

// get last 8 bytes of SHA1 of RSA key's n and e
int64_t tgl_do_compute_rsa_key_fingerprint(const TGLC_rsa* key)
{
    unsigned char sha[20];
    memset(sha, 0, sizeof(sha));

    std::unique_ptr<char[]> temp_buffer(new char[4096]);
    memset(temp_buffer.get(), 0, 4096);

    assert(TGLC_rsa_n(key) && TGLC_rsa_e(key));
    int l1 = tgl_serialize_bignum(TGLC_rsa_n(key), temp_buffer.get(), 4096);
    assert(l1 > 0);
    int l2 = tgl_serialize_bignum(TGLC_rsa_e(key), temp_buffer.get() + l1, 4096 - l1);
    assert(l2 > 0 && l1 + l2 <= 4096);
    TGLC_sha1((unsigned char *)temp_buffer.get(), l1 + l2, sha);
    int64_t fingerprint;
    memcpy(&fingerprint, sha + 12, 8);
    return fingerprint;
}

ssize_t tgl_fetch_bignum(tgl_in_buffer* in, TGLC_bn* x)
{
    ssize_t l = prefetch_strlen(in);
    if (l < 0) {
        return l;
    }
    const char* str = fetch_str(in, l);
    auto result = TGLC_bn_bin2bn(reinterpret_cast<const unsigned char*>(str), l, x);
    TGL_ASSERT_UNUSED(result, result == x);
    return l;
}

int tgl_pad_rsa_encrypt(const char* from, int from_len, char* to, int size, TGLC_bn_ctx* ctx, const TGLC_bn* N, const TGLC_bn* E)
{
    int pad = (255000 - from_len - 32) % 255 + 32;
    int chunks = (from_len + pad) / 255;
    if (!to) {
        return chunks * 256;
    }

    int bits = TGLC_bn_num_bits(N);
    TGL_ASSERT_UNUSED(bits, bits >= 2041 && bits <= 2048);
    assert(from_len > 0 && from_len <= 2550);
    assert(size >= chunks * 256);
    auto result = TGLC_rand_pseudo_bytes(reinterpret_cast<unsigned char*>(const_cast<char*>(from)) + from_len, pad);
    TGL_ASSERT_UNUSED(result, result >= 0);
    std::unique_ptr<TGLC_bn, TGLC_bn_deleter> x(TGLC_bn_new());
    std::unique_ptr<TGLC_bn, TGLC_bn_deleter> y(TGLC_bn_new());
    assert(x);
    assert(y);
    for (int i = 0; i < chunks; i++) {
        TGLC_bn_bin2bn(reinterpret_cast<const unsigned char*>(from), 255, x.get());
        result = TGLC_bn_mod_exp(y.get(), x.get(), E, N, ctx);
        TGL_ASSERT_UNUSED(result, result == 1);
        unsigned l = 256 - TGLC_bn_num_bytes(y.get());
        assert(l <= 256);
        memset(to, 0, l);
        TGLC_bn_bn2bin(y.get(), reinterpret_cast<unsigned char*>(to) + l);
        from += 255;
        to += 256;
    }
    return chunks * 256;
}

int tgl_pad_rsa_decrypt(const char* from, int from_len, char* to, int size, TGLC_bn_ctx* ctx, const TGLC_bn* N, const TGLC_bn* D)
{
    if (from_len < 0 || from_len > 0x1000 || (from_len & 0xff)) {
        return -1;
    }
    int chunks = (from_len >> 8);
    int bits = TGLC_bn_num_bits(N);
    TGL_ASSERT_UNUSED(bits, bits >= 2041 && bits <= 2048);
    assert(size >= chunks * 255);
    std::unique_ptr<TGLC_bn, TGLC_bn_deleter> x(TGLC_bn_new());
    std::unique_ptr<TGLC_bn, TGLC_bn_deleter> y(TGLC_bn_new());
    assert(x.get());
    assert(y.get());
    for (int i = 0; i < chunks; i++) {
        TGLC_bn_bin2bn(reinterpret_cast<const unsigned char*>(from), 256, x.get());
        auto result = TGLC_bn_mod_exp(y.get(), x.get(), D, N, ctx);
        TGL_ASSERT_UNUSED(result, result == 1);
        int l = TGLC_bn_num_bytes(y.get());
        if (l > 255) {
            return -1;
        }
        assert(l >= 0 && l <= 255);
        memset(to, 0, 255 - l);
        TGLC_bn_bn2bin(y.get(), reinterpret_cast<unsigned char*>(to) + 255 - l);
        from += 256;
        to += 255;
    }
    return chunks * 255;
}

void tgl_init_aes_unauth(TGLC_aes_key* aes_key, unsigned char aes_iv[32],
        const unsigned char server_nonce[16], const unsigned char hidden_client_nonce[32], int encrypt)
{
    unsigned char buffer[64], hash[20];
    unsigned char aes_key_raw[32];
    memset(buffer, 0, sizeof(buffer));
    memset(hash, 0, sizeof(hash));
    memset(aes_key_raw, 0, sizeof(aes_key_raw));
    memset(aes_iv, 0, 32);

    memcpy(buffer, hidden_client_nonce, 32);
    memcpy(buffer + 32, server_nonce, 16);
    TGLC_sha1(buffer, 48, aes_key_raw);
    memcpy(buffer + 32, hidden_client_nonce, 32);
    TGLC_sha1(buffer, 64, aes_iv + 8);
    memcpy(buffer, server_nonce, 16);
    memcpy(buffer + 16, hidden_client_nonce, 32);
    TGLC_sha1(buffer, 48, hash);
    memcpy(aes_key_raw + 20, hash, 12);
    memcpy(aes_iv, hash + 12, 8);
    memcpy(aes_iv + 28, hidden_client_nonce, 4);
    if (encrypt) {
      TGLC_aes_set_encrypt_key(aes_key_raw, 32 * 8, aes_key);
    } else {
      TGLC_aes_set_decrypt_key(aes_key_raw, 32 * 8, aes_key);
    }
    memset(aes_key_raw, 0, sizeof(aes_key_raw));
}

void tgl_init_aes_auth(TGLC_aes_key* aes_key, unsigned char aes_iv[32],
        const unsigned char auth_key[192], const unsigned char msg_key[16], int encrypt)
{
    unsigned char buffer[48], hash[20];
    unsigned char aes_key_raw[32];
    memset(buffer, 0, sizeof(buffer));
    memset(hash, 0, sizeof(hash));
    memset(aes_key_raw, 0, sizeof(aes_key_raw));
    memset(aes_iv, 0, 32);

    memcpy(buffer, msg_key, 16);
    memcpy(buffer + 16, auth_key, 32);
    TGLC_sha1(buffer, 48, hash);
    memcpy(aes_key_raw, hash, 8);
    memcpy(aes_iv, hash + 8, 12);

    memcpy(buffer, auth_key + 32, 16);
    memcpy(buffer + 16, msg_key, 16);
    memcpy(buffer + 32, auth_key + 48, 16);
    TGLC_sha1(buffer, 48, hash);
    memcpy(aes_key_raw + 8, hash + 8, 12);
    memcpy(aes_iv + 12, hash, 8);

    memcpy(buffer, auth_key + 64, 32);
    memcpy(buffer + 32, msg_key, 16);
    TGLC_sha1(buffer, 48, hash);
    memcpy(aes_key_raw + 20, hash + 4, 12);
    memcpy(aes_iv + 20, hash + 16, 4);

    memcpy(buffer, msg_key, 16);
    memcpy(buffer + 16, auth_key + 96, 32);
    TGLC_sha1(buffer, 48, hash);
    memcpy(aes_iv + 24, hash, 8);

    if (encrypt) {
        TGLC_aes_set_encrypt_key(aes_key_raw, 32 * 8, aes_key);
    } else {
        TGLC_aes_set_decrypt_key(aes_key_raw, 32 * 8, aes_key);
    }
    memset(aes_key_raw, 0, sizeof(aes_key_raw));
}

int tgl_pad_aes_encrypt(const TGLC_aes_key* aes_key, unsigned char aes_iv[32],
        const unsigned char* from, int from_len, unsigned char* to, int size)
{
    int padded_size = (from_len + 15) & -16;
    if (!to) {
        return padded_size;
    }

    assert(from_len > 0 && padded_size <= size);
    if (from_len < padded_size) {
        auto result = TGLC_rand_pseudo_bytes(const_cast<unsigned char*>(from) + from_len, padded_size - from_len);
        TGL_ASSERT_UNUSED(result, result >= 0);
    }
    TGLC_aes_ige_encrypt(const_cast<unsigned char*>(from), to, padded_size, aes_key, aes_iv, 1);
    return padded_size;
}

int tgl_pad_aes_decrypt(const TGLC_aes_key* aes_key, unsigned char aes_iv[32],
        const unsigned char* from, int from_len, unsigned char* to, int size)
{
    if (from_len <= 0 || from_len > size || (from_len & 15)) {
        return -1;
    }
    TGLC_aes_ige_encrypt(const_cast<unsigned char*>(from), to, from_len, aes_key, aes_iv, 0);
    return from_len;
}

}
}
