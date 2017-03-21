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

    Copyright Topology LP 2016-2017
*/

#include "query_send_inline_query_to_bot.h"

namespace tgl {
namespace impl {

query_send_inline_query_to_bot::query_send_inline_query_to_bot(user_agent& ua,
        const std::function<void(bool, const std::string&)>& callback)
    : query(ua, "send inline query to bot", TYPE_TO_PARAM(messages_bot_results))
    , m_callback(callback)
{ }

void query_send_inline_query_to_bot::on_answer(void* D)
{
    if (m_callback) {
        std::string response;
        const tl_ds_messages_bot_results* bot_results = static_cast<const tl_ds_messages_bot_results*>(D);
        if (bot_results->results && DS_LVAL(bot_results->results->cnt) == 1
                && bot_results->results->data[0]->magic == CODE_bot_inline_result) {
            tl_ds_bot_inline_message* inline_message = bot_results->results->data[0]->send_message;
            if (inline_message && inline_message->magic == CODE_bot_inline_message_text) {
                response = DS_STDSTR(inline_message->message);
            }
        }
        m_callback(true, response);
    }
}

int query_send_inline_query_to_bot::on_error(int error_code, const std::string& error_string)
{
    TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
    if (m_callback) {
        m_callback(false, std::string());
    }
    return 0;
}

}
}
