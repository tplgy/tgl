#ifndef __TGL_CHAT_H__
#define __TGL_CHAT_H__

#include <cstdint>
#include <string>
#include <vector>

#include "tgl_file_location.h"
#include "tgl_peer_id.h"

struct tgl_chat_user {
    int32_t user_id;
    int32_t inviter_id;
    int32_t date;
    tgl_chat_user(): user_id(0), inviter_id(0), date(0) { }
};

struct tgl_chat {
    tgl_input_peer_t id;
    int32_t flags;
    //std::string print_title;
    std::string username;
    //int structure_version;
    tgl_file_location photo_big;
    tgl_file_location photo_small;
    //int last_read_in;
    //int last_read_out;
    //struct tgl_photo *photo;
    std::string title;
    //int users_num;
    //int user_list_version;
    //std::vector<std::shared_ptr<tgl_chat_user>> user_list;
    //int date;
    //int version;
    //int admin_id;
    tgl_chat(): flags(0) { }
};

#endif
