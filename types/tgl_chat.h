#ifndef __TGL_CHAT_H__
#define __TGL_CHAT_H__

#include <string>
#include <vector>

struct tgl_chat_user {
    int user_id;
    int inviter_id;
    int date;
};

struct tgl_chat {
    tgl_peer_id_t id;
    int flags;
    //std::string print_title;
    //std::string username;
    //int structure_version;
    tgl_file_location photo_big;
    tgl_file_location photo_small;
    //int last_read_in;
    //int last_read_out;
    //struct tgl_photo *photo;
    //std::string title;
    //int users_num;
    //int user_list_version;
    //std::vector<std::shared_ptr<tgl_chat_user>> user_list;
    //int date;
    //int version;
    //int admin_id;
};

#endif
