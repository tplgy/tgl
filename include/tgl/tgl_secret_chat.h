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

#include "tgl_file_location.h"
#include "tgl_peer_id.h"

#include <algorithm>
#include <cassert>
#include <memory>
#include <string>
#include <vector>

static constexpr int32_t TGL_ENCRYPTED_LAYER = 17;

enum class tgl_secret_chat_state {
    none = 0,
    waiting,
    request,
    ok,
    deleted,
};

enum class tgl_secret_chat_exchange_state {
    none = 0,
    requested,
    accepted,
    committed,
    confirmed,
    aborted,
};

inline static std::string to_string(tgl_secret_chat_state state)
{
    switch (state) {
    case tgl_secret_chat_state::none:
        return "none";
    case tgl_secret_chat_state::waiting:
        return "waiting";
    case tgl_secret_chat_state::request:
        return "request";
    case tgl_secret_chat_state::ok:
        return "ok";
    case tgl_secret_chat_state::deleted:
        return "deleted";
    default:
        assert(false);
        return "unknown secret chat status";
    }
}

inline static std::string to_string(tgl_secret_chat_exchange_state state)
{
    switch (state) {
    case tgl_secret_chat_exchange_state::none:
        return "none";
    case tgl_secret_chat_exchange_state::requested:
        return "requested";
    case tgl_secret_chat_exchange_state::accepted:
        return "accepted";
    case tgl_secret_chat_exchange_state::committed:
        return "committed";
    case tgl_secret_chat_exchange_state::confirmed:
        return "confirmed";
    case tgl_secret_chat_exchange_state::aborted:
        return "aborted";
    default:
        assert(false);
        return "unknown secret chat exchange state";
    }
}

inline static std::ostream& operator<<(std::ostream& os, tgl_secret_chat_state state)
{
    os << to_string(state);
    return os;
}

inline static std::ostream& operator<<(std::ostream& os, tgl_secret_chat_exchange_state state)
{
    os << to_string(state);
    return os;
}

struct tgl_bn;

struct tgl_secret_chat {
    tgl_input_peer_t id;
    int64_t access_hash;
    int64_t temp_key_fingerprint;
    int64_t exchange_id;
    int64_t exchange_key_fingerprint;
    int32_t exchange_key[64];
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
    tgl_secret_chat_state state;
    tgl_secret_chat_exchange_state exchange_state;
    int32_t device_id;

    std::vector<unsigned char> g_key;

    tgl_secret_chat();
    ~tgl_secret_chat();

    const tgl_bn* encr_prime_bn() const { return m_encr_prime_bn.get(); }

    const std::vector<unsigned char>& encr_prime() const
    {
        return m_encr_prime;
    }

    void set_encr_prime(const unsigned char* prime, size_t length);

    void set_key(const unsigned char* key);
    const unsigned char* key() const { return m_key; }
    const unsigned char* key_sha() const { return m_key_sha; }
    int64_t key_fingerprint() const
    {
        int64_t fingerprint;
        // Telegram secret chat key fingerprints are the last 64 bits of SHA1(key)
        memcpy(&fingerprint, m_key_sha + 12, 8);
        return fingerprint;
    }

    static size_t key_size() { return 256; }
    static size_t key_sha_size() { return 20; }

private:
    std::vector<unsigned char> m_encr_prime;
    std::unique_ptr<tgl_bn> m_encr_prime_bn;
    unsigned char m_key[256];
    unsigned char m_key_sha[20];
};

#endif
