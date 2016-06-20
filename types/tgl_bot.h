#ifndef __TGL_BOT_H__
#define __TGL_BOT_H__

#include <cstdint>
#include <string>
#include <vector>

struct tgl_bot_command {
    std::string command;
    std::string description;
};

struct tgl_bot_info {
    int32_t version;
    std::string share_text;
    std::string description;
    std::vector<std::shared_ptr<tgl_bot_command>> commands;
    tgl_bot_info(): version(0) { }
};

#endif
