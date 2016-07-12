#pragma once

#include <cstdint>

enum class tgl_peer_type {
    unknown = 0,
    user = 1,
    chat = 2,
    geo_chat = 3,
    enc_chat = 4,
    channel = 5,
    temp_id = 100,
    random_id = 101
};

struct tgl_peer_id_t;

struct tgl_input_peer_t {
    tgl_peer_type peer_type;
    int32_t peer_id;
    int64_t access_hash;

    tgl_input_peer_t()
        : peer_type(tgl_peer_type::unknown), peer_id(0), access_hash(0)
    {}

    tgl_input_peer_t(tgl_peer_type peer_type, int32_t peer_id, int64_t access_hash)
        : peer_type(peer_type), peer_id(peer_id), access_hash(access_hash)
    {}

    static tgl_input_peer_t service_user()
    {
        // the hardcoded Telegram service user
        return tgl_input_peer_t(tgl_peer_type::user, 777000, 0);
    }

    static tgl_input_peer_t from_peer_id(const tgl_peer_id_t& id);
};

inline bool operator==(const tgl_input_peer_t& lhs, const tgl_input_peer_t& rhs)
{
    return lhs.peer_id == rhs.peer_id && lhs.peer_type == rhs.peer_type;
}

struct tgl_peer_id_t {
    tgl_peer_type peer_type;
    int32_t peer_id;

    tgl_peer_id_t()
        : peer_type(tgl_peer_type::unknown), peer_id(0)
    {}

    tgl_peer_id_t(tgl_peer_type peer_type, int32_t peer_id)
        : peer_type(peer_type), peer_id(peer_id)
    {}

    static tgl_peer_id_t from_input_peer(const tgl_input_peer_t& input_peer)
    {
        return tgl_peer_id_t(input_peer.peer_type, input_peer.peer_id);
    }
};

inline bool operator==(const tgl_peer_id_t& lhs, const tgl_peer_id_t& rhs)
{
    return lhs.peer_id == rhs.peer_id && lhs.peer_type == rhs.peer_type;
}

inline tgl_input_peer_t tgl_input_peer_t::from_peer_id(const tgl_peer_id_t& id)
{
    return tgl_input_peer_t(id.peer_type, id.peer_id, 0);
}
