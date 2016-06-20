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

struct tgl_peer_id_t {
    tgl_peer_type peer_type;
    int32_t peer_id;
    int64_t access_hash;
    tgl_peer_id_t() : peer_type(tgl_peer_type::unknown), peer_id(0), access_hash(0) {}
    tgl_peer_id_t(tgl_peer_type peer_type, int32_t peer_id, int64_t access_hash = 0)
        : peer_type(peer_type), peer_id(peer_id), access_hash(access_hash) {}
};

inline bool operator==(const tgl_peer_id_t& lhs, const tgl_peer_id_t& rhs)
{
    return lhs.peer_id == rhs.peer_id && lhs.peer_type == rhs.peer_type;
}

struct tgl_peer_id_user : public tgl_peer_id_t {
    tgl_peer_id_user(int32_t user_id) : tgl_peer_id_t(tgl_peer_type::user, user_id) {}
};

struct tgl_peer_id_chat : public tgl_peer_id_t {
    tgl_peer_id_chat(int32_t chat_id) : tgl_peer_id_t(tgl_peer_type::chat, chat_id) {}
};

struct tgl_peer_id_channel : public tgl_peer_id_t {
    tgl_peer_id_channel(int32_t channel_id) : tgl_peer_id_t(tgl_peer_type::channel, channel_id) {}
};

struct tgl_peer_id_enc_chat : public tgl_peer_id_t {
    tgl_peer_id_enc_chat(int32_t enc_chat_id) : tgl_peer_id_t(tgl_peer_type::enc_chat, enc_chat_id) {}
};
