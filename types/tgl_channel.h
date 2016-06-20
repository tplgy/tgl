#ifndef __TGL_CHANNEL_H__
#define __TGL_CHANNEL_H__

#include <cstdint>
#include <string>

#include "types/tgl_chat.h"
#include "types/tgl_file_location.h"

struct tgl_channel: public tgl_chat {
    int64_t access_hash;
    int32_t participants_count;
    int32_t admins_count;
    int32_t kicked_count;
    int32_t pts;
    std::string about;

    tgl_channel()
        : access_hash(0)
        , participants_count(0)
        , admins_count(0)
        , kicked_count(0)
        , pts(0)
    { }
};

#endif
