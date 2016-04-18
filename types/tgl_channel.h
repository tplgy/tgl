#ifndef __TGL_CHANNEL_H__
#define __TGL_CHANNEL_H__

#include <string>

#include "types/tgl_chat.h"
#include "types/tgl_file_location.h"

struct tgl_channel: public tgl_chat {
    long long access_hash;
    std::string about;
    int participants_count;
    int admins_count;
    int kicked_count;
    int pts;

    tgl_channel()
        : access_hash(0)
        , participants_count(0)
        , admins_count(0)
        , kicked_count(0)
        , pts(0)
    { }
};

#endif
