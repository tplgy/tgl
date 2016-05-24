#ifndef __TGL_MESSAGE_H__
#define __TGL_MESSAGE_H__

#include "tgl_message_action.h"
#include "tgl_message_entity.h"
#include "tgl_message_media.h"
#include "tgl_peer_id.h"

#include <memory>
#include <vector>

struct tgl_message_reply_markup {
  int flags;
  std::vector<std::vector<std::string>> button_matrix;
  tgl_message_reply_markup(): flags(0) { }
};

typedef struct tgl_message_id {
    unsigned peer_type;
    unsigned peer_id;
    long long id;
    long long access_hash;
    tgl_message_id(): peer_type(0), peer_id(0), id(0), access_hash(0) { }
} tgl_message_id_t;

struct tgl_message {
    long long server_id;
    long long random_id;
    struct tgl_message_id permanent_id;
    int flags;
    tgl_peer_id_t fwd_from_id;
    int fwd_date;
    int reply_id;
    tgl_peer_id_t from_id;
    tgl_peer_id_t to_id;
    int date;
    std::vector<std::shared_ptr<tgl_message_entity>> entities;
    std::shared_ptr<tgl_message_reply_markup> reply_markup;
    std::shared_ptr<tgl_message_action> action;
    std::shared_ptr<tgl_message_media> media;
    std::string message;
    tgl_message()
        : server_id(0)
        , random_id(0)
        , permanent_id()
        , flags(0)
        , fwd_from_id()
        , fwd_date(0)
        , reply_id(0)
        , from_id()
        , to_id()
        , date(0)
        , action(std::make_shared<tgl_message_action_none>())
        , media(std::make_shared<tgl_message_media_none>())
    { }
};

struct tgl_secret_message {
    std::shared_ptr<tgl_message> message;
    int layer;
    int in_seq_no;
    int out_seq_no;

    tgl_secret_message()
        : layer(-1)
        , in_seq_no(-1)
        , out_seq_no(-1)
    { }

    tgl_secret_message(const std::shared_ptr<tgl_message>& message, int layer, int in_seq_no, int out_seq_no)
        : message(message)
        , layer(layer)
        , in_seq_no(in_seq_no)
        , out_seq_no(out_seq_no)
    { }
};

#endif
