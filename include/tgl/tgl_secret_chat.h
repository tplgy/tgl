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
    Copyright Topology LP 2016-2017
*/

#pragma once

#include "tgl_peer_id.h"

#include <cassert>
#include <iostream>
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

class tgl_secret_chat
{
public:
    enum class qos { real_time, normal };
    virtual ~tgl_secret_chat() { }

    virtual qos quality_of_service() const = 0;
    virtual void set_quality_of_service(qos) = 0;

    virtual bool opaque_service_message_enabled() const = 0;
    virtual void set_opaque_service_message_enabled(bool b) = 0;

    virtual const tgl_input_peer_t& id() const = 0;
    virtual int64_t exchange_id() const = 0;
    virtual int64_t exchange_key_fingerprint() const = 0;
    virtual int32_t user_id() const = 0;
    virtual int32_t admin_id() const = 0; // creator
    virtual int32_t date() const = 0;
    virtual int32_t ttl() const = 0;
    virtual int32_t layer() const = 0;
    virtual int32_t in_seq_no() const = 0;
    virtual int32_t out_seq_no() const = 0;
    virtual int32_t last_in_seq_no() const = 0;
    virtual int32_t encr_root() const = 0;
    virtual int32_t encr_param_version() const = 0;
    virtual tgl_secret_chat_state state() const = 0;
    virtual tgl_secret_chat_exchange_state exchange_state() const = 0;
    virtual const std::vector<unsigned char>& encr_prime() const = 0;
    virtual const std::vector<unsigned char>& g_key() const = 0;

    virtual const unsigned char* exchange_key() const = 0;
    virtual const unsigned char* key() const = 0;
    virtual const unsigned char* key_sha() const = 0;
    virtual int64_t key_fingerprint() const = 0;

    static size_t key_size() { return 256; }
    static size_t key_sha_size() { return 20; }
    static size_t exchange_key_size() { return 256; }
};
