#ifndef __TGL_MESSAGE_H__
#define __TGL_MESSAGE_H__

#include "tgl_message_action.h"
#include "tgl_message_entity.h"
#include "tgl_message_media.h"
#include "tgl_peer_id.h"

#include <cstdint>
#include <memory>
#include <vector>

struct tgl_message_reply_markup {
  int flags;
  std::vector<std::vector<std::string>> button_matrix;
  tgl_message_reply_markup(): flags(0) { }
};

typedef struct tgl_message_id {
    tgl_peer_type peer_type;
    unsigned peer_id;
    int64_t id;
    int64_t access_hash;
    tgl_message_id(): peer_type(tgl_peer_type::unknown), peer_id(0), id(0), access_hash(0) { }
    tgl_message_id(const tgl_peer_type& peer_type, unsigned peer_id, long long id, long long access_hash)
        : peer_type(peer_type), peer_id(peer_id), id(id), access_hash(access_hash) {}
} tgl_message_id_t;

struct tgl_message {
    int64_t server_id;
    int64_t random_id;
    int32_t flags;
    int32_t fwd_date;
    int32_t reply_id;
    int32_t date;
    struct tgl_message_id permanent_id;
    tgl_peer_id_t fwd_from_id;
    tgl_peer_id_t from_id;
    tgl_peer_id_t to_id;
    std::vector<std::shared_ptr<tgl_message_entity>> entities;
    std::shared_ptr<tgl_message_reply_markup> reply_markup;
    std::shared_ptr<tgl_message_action> action;
    std::shared_ptr<tgl_message_media> media;
    std::string message;
    tgl_message()
        : server_id(0)
        , random_id(0)
        , flags(0)
        , fwd_date(0)
        , reply_id(0)
        , date(0)
        , permanent_id()
        , fwd_from_id()
        , from_id()
        , to_id()
        , action(std::make_shared<tgl_message_action_none>())
        , media(std::make_shared<tgl_message_media_none>())
    { }
};

struct tgl_secret_message {
    std::shared_ptr<tgl_message> message;
    int32_t layer;
    int32_t in_seq_no;
    int32_t out_seq_no;

    tgl_secret_message()
        : layer(-1)
        , in_seq_no(-1)
        , out_seq_no(-1)
    { }

    tgl_secret_message(const std::shared_ptr<tgl_message>& message, int32_t layer, int32_t in_seq_no, int32_t out_seq_no)
        : message(message)
        , layer(layer)
        , in_seq_no(in_seq_no)
        , out_seq_no(out_seq_no)
    { }
};

#endif
