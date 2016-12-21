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

#include "tgl_peer_id.h"

#include <cassert>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

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

class tgl_secret_chat_private_facet;
struct tgl_secret_chat_private;

class tgl_secret_chat {
public:
    tgl_secret_chat();
    tgl_secret_chat(int32_t chat_id, int64_t access_hash, int32_t user_id);
    tgl_secret_chat(int32_t chat_id, int64_t access_hash, int32_t user_id,
                    int32_t admin, int32_t date, int32_t ttl, int32_t layer,
                    int32_t in_seq_no, int32_t last_in_seq, int32_t out_seq_no,
                    int32_t encr_root, int32_t encr_param_version,
                    tgl_secret_chat_state state, tgl_secret_chat_exchange_state exchange_state,
                    int64_t exchange_id,
                    const unsigned char* key, size_t key_length,
                    const unsigned char* encr_prime, size_t encr_prime_length,
                    const unsigned char* g_key, size_t g_key_length,
                    const unsigned char* exchange_key, size_t exchange_key_length);
    ~tgl_secret_chat();

    const tgl_input_peer_t& id() const;
    int64_t exchange_id() const;
    int64_t exchange_key_fingerprint() const;
    int32_t user_id() const;
    int32_t admin_id() const; // creator
    int32_t date() const;
    int32_t ttl() const;
    int32_t layer() const;
    int32_t in_seq_no() const;
    int32_t out_seq_no() const;
    int32_t last_in_seq_no() const;
    int32_t encr_root() const;
    int32_t encr_param_version() const;
    tgl_secret_chat_state state() const;
    tgl_secret_chat_exchange_state exchange_state() const;
    const std::vector<unsigned char>& encr_prime() const;
    const std::vector<unsigned char>& g_key() const;

    const unsigned char* exchange_key() const;
    const unsigned char* key() const;
    const unsigned char* key_sha() const;
    int64_t key_fingerprint() const;

    static size_t key_size() { return 256; }
    static size_t key_sha_size() { return 20; }
    static size_t exchange_key_size() { return 256; }

    tgl_secret_chat_private_facet* private_facet();

private:
    friend class tgl_secret_chat_private_facet;
    std::unique_ptr<tgl_secret_chat_private> d;
};

#endif
