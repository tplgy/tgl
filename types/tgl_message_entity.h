#ifndef __TGL_MESSAGE_ENTITY_H__
#define __TGL_MESSAGE_ENTITY_H__

#include <string>

enum tgl_message_entity_type {
    tgl_message_entity_unknown,
    tgl_message_entity_mention,
    tgl_message_entity_hashtag,
    tgl_message_entity_bot_command,
    tgl_message_entity_url,
    tgl_message_entity_email,
    tgl_message_entity_bold,
    tgl_message_entity_italic,
    tgl_message_entity_code,
    tgl_message_entity_pre,
    tgl_message_entity_text_url
};

struct tgl_message_entity {
    enum tgl_message_entity_type type;
    int start;
    int length;
    std::string text_url;
    tgl_message_entity()
        : type(tgl_message_entity_unknown)
        , start(0)
        , length(0)
    { }
};

#endif
