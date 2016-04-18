#ifndef __TGL_USER_H__
#define __TGL_USER_H__

#include "tgl_file_location.h"
#include "tgl_peer_id.h"

#include <memory>
#include <string>

class tgl_timer;
struct tgl_message;

struct tgl_user_status {
    int online;
    int when;
    std::shared_ptr<tgl_timer> ev;
    tgl_user_status(): online(0), when(0) { }
};

struct tgl_user {
    tgl_peer_id_t id;
    int flags;
    long long access_hash;
    struct tgl_user_status status;
    tgl_user(): id({0, 0, 0}), flags(0) { }
};

#endif
