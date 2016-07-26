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

    Copyright Vitaly Valtman 2013-2015
    Copyright Topology LP 2016
*/

#ifndef __TGL_SECRET_CHAT_H__
#define __TGL_SECRET_CHAT_H__

#include "crypto/bn.h"
#include "crypto/sha.h"
#include "tgl-layout.h"
#include "tgl_file_location.h"
#include "tgl_peer_id.h"

#include <algorithm>
#include <string.h>
#include <memory>
#include <vector>

enum tgl_secret_chat_state {
    sc_none,
    sc_waiting,
    sc_request,
    sc_ok,
    sc_deleted
};

enum tgl_secret_chat_exchange_state {
    tgl_sce_none,
    tgl_sce_requested,
    tgl_sce_accepted,
    tgl_sce_committed,
    tgl_sce_confirmed,
    tgl_sce_aborted
};

struct tgl_secret_chat {
    tgl_input_peer_t id;
    int64_t access_hash;
    int64_t temp_key_fingerprint;
    int64_t exchange_id;
    int64_t exchange_key_fingerprint;
    int32_t exchange_key[64];
    int32_t flags;
    int32_t user_id;
    int32_t admin_id;
    int32_t date;
    int32_t ttl;
    int32_t layer;
    int32_t in_seq_no;
    int32_t out_seq_no;
    int32_t last_in_seq_no;
    int32_t encr_root;
    int32_t encr_param_version;
    enum tgl_secret_chat_state state;
    enum tgl_secret_chat_exchange_state exchange_state;

    std::vector<unsigned char> g_key;

    TGLC_bn* encr_prime_bn()
    {
        return m_encr_prime_bn.get();
    }

    const std::vector<unsigned char>& encr_prime() const
    {
        return m_encr_prime;
    }

    void set_encr_prime(const unsigned char* prime, size_t length)
    {
        m_encr_prime.resize(length);
        m_encr_prime_bn.reset(TGLC_bn_new());
        std::copy(prime, prime + length, m_encr_prime.begin());
        TGLC_bn_bin2bn(m_encr_prime.data(), length, m_encr_prime_bn.get());
    }

    void set_key(const unsigned char* key)
    {
        TGLC_sha1(key, key_size(), m_key_sha);
        memcpy(m_key, key, key_size());
    }

    const unsigned char* key() const { return m_key; }
    int64_t key_fingerprint() const { return *reinterpret_cast<const int64_t*>(m_key_sha + 12); }
    const unsigned char* key_sha() const { return m_key_sha; }

    static size_t key_size() { return 256; }
    static size_t key_sha_size() { return 20; }

    tgl_secret_chat()
        : id()
        , access_hash(0)
        , temp_key_fingerprint(0)
        , exchange_id(0)
        , exchange_key_fingerprint(0)
        , flags(0)
        , user_id(0)
        , admin_id(0)
        , date(0)
        , ttl(0)
        , layer(0)
        , in_seq_no(0)
        , out_seq_no(0)
        , last_in_seq_no(0)
        , encr_root(0)
        , encr_param_version(0)
        , state(sc_none)
        , exchange_state(tgl_sce_none)
        , g_key()
        , m_encr_prime()
        , m_encr_prime_bn(nullptr)
    {
        memset(m_key, 0, sizeof(m_key));
        memset(m_key_sha, 0, sizeof(m_key_sha));
        memset(exchange_key, 0, sizeof(exchange_key));
    }

private:
    std::vector<unsigned char> m_encr_prime;
    std::unique_ptr<TGLC_bn, TGLC_bn_deleter> m_encr_prime_bn;
    unsigned char m_key[256];
    unsigned char m_key_sha[20];
};

#endif
