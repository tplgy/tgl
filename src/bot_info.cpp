/*
    This file is part of tgl-library

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

    Copyright Vitaly Valtman 2013-2015
    Copyright Topology LP 2016-2017
*/

#include "bot_info.h"

#include "auto/auto.h"
#include "auto/auto_types.h"
#include "auto/constants.h"

namespace tgl {
namespace impl {

std::shared_ptr<tgl_bot_info> create_bot_info(const tl_ds_bot_info* DS_BI)
{
    if (!DS_BI || DS_BI->magic == CODE_bot_info_empty) {
        return nullptr;
    }

    std::shared_ptr<tgl_bot_info> bot = std::make_shared<tgl_bot_info>();
    bot->version = DS_LVAL(DS_BI->version);
    bot->share_text = DS_STDSTR(DS_BI->share_text);
    bot->description = DS_STDSTR(DS_BI->description);

    int commands_num = DS_LVAL(DS_BI->commands->cnt);
    bot->commands.resize(commands_num);
    for (int i = 0; i < commands_num; i++) {
        const tl_ds_bot_command* bot_command = DS_BI->commands->data[i];
        bot->commands[i] = std::make_shared<tgl_bot_command>();
        bot->commands[i]->command = DS_STDSTR(bot_command->command);
        bot->commands[i]->description = DS_STDSTR(bot_command->description);
    }
    return bot;
}

}
}

