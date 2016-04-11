#ifndef __TGL_SECRET_CHAT_H__
#define  __TGL_SECRET_CHAT_H__

#include "tgl-layout.h"
#include "types/tgl_file_location.h"
#include <string.h>

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
    tgl_peer_id_t id;
    int flags;
    struct tgl_message *last;
    std::string print_name;
    std::string username;
    int structure_version;
    struct tgl_file_location photo_big;
    struct tgl_file_location photo_small;
    struct tgl_photo *photo;
    void *extra;
    int user_id;
    int admin_id;
    int date;
    int ttl;
    int layer;
    int in_seq_no;
    int out_seq_no;
    int last_in_seq_no;
    long long access_hash;
    std::vector<unsigned char> g_key;

    enum tgl_secret_chat_state state;
    int key[64];
    long long key_fingerprint;
    unsigned char first_key_sha[20];

    long long exchange_id;
    enum tgl_secret_chat_exchange_state exchange_state;
    int exchange_key[64];
    long long exchange_key_fingerprint;

    tgl_secret_chat()
        : id({0, 0, 0})
        , flags(0)
        , last(nullptr)
        , print_name()
        , username()
        , structure_version(0)
        , photo_big(no_file_location)
        , photo_small(no_file_location)
        , photo(nullptr)
        , extra(nullptr)
        , user_id(0)
        , admin_id(0)
        , date(0)
        , ttl(0)
        , layer(0)
        , in_seq_no(0)
        , out_seq_no(0)
        , last_in_seq_no(0)
        , access_hash(0)
        , g_key()
        , state(sc_none)
        , key_fingerprint(0)
        , exchange_id(0)
        , exchange_state(tgl_sce_none)
        , exchange_key_fingerprint(0)
    {
        memset(key, 0, sizeof(key));
        memset(first_key_sha, 0, sizeof(first_key_sha));
        memset(exchange_key, 0, sizeof(exchange_key));
    }
};

#endif
