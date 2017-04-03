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

#include "query_messages_send_message.h"

#include "message_entity.h"

namespace tgl {
namespace impl {

query_messages_send_message::query_messages_send_message(user_agent& ua, const std::shared_ptr<class message>& message,
        bool disable_preview,
        const std::function<void(bool, const std::shared_ptr<class message>&)>& callback)
    : query(ua, "send message", TYPE_TO_PARAM(updates))
    , m_message(message)
    , m_callback(callback)
{
    assert(message->to_id().peer_type != tgl_peer_type::enc_chat);

    out_i32(CODE_messages_send_message);

    uint32_t flags = (disable_preview ? 2 : 0) | (message->reply_id() ? 1 : 0) | (message->reply_markup() ? 4 : 0) | (message->entities().size() > 0 ? 8 : 0);
    if (message->from_id().peer_type == tgl_peer_type::channel) {
        flags |= 16;
    }
    out_i32(flags);
    out_input_peer(message->to_id());
    if (message->reply_id()) {
        out_i32(message->reply_id());
    }
    out_std_string(message->text());
    out_i64(message->id());

    if (message->reply_markup()) {
        if (!message->reply_markup()->button_matrix.empty()) {
            out_i32(CODE_reply_keyboard_markup);
            out_i32(message->reply_markup()->flags);
            out_i32(CODE_vector);
            out_i32(message->reply_markup()->button_matrix.size());
            for (size_t i = 0; i < message->reply_markup()->button_matrix.size(); ++i) {
                out_i32(CODE_keyboard_button_row);
                out_i32(CODE_vector);
                out_i32(message->reply_markup()->button_matrix[i].size());
                for (size_t j = 0; j < message->reply_markup()->button_matrix[i].size(); ++j) {
                    out_i32(CODE_keyboard_button);
                    out_std_string(message->reply_markup()->button_matrix[i][j]);
                }
            }
        } else {
            out_i32(CODE_reply_keyboard_hide);
        }
    }

    if (message->entities().size() > 0) {
        out_i32(CODE_vector);
        out_i32(message->entities().size());
        for (size_t i = 0; i < message->entities().size(); i++) {
            auto entity = message->entities()[i];
            serialize_message_entity(serializer().get(), entity.get());
        }
    }
}

void query_messages_send_message::on_answer(void* D)
{
    tl_ds_updates* DS_U = static_cast<tl_ds_updates*>(D);
    m_user_agent.updater().work_any_updates(DS_U, update_context(m_message));
    if (m_callback) {
        m_callback(true, m_message);
    }
}

int query_messages_send_message::on_error(int error_code, const std::string& error_string)
{
    TGL_ERROR("RPC_CALL_FAIL " <<  error_code << " " << error_string);
    m_message->set_pending(false).set_send_failed(true);

    if (m_callback) {
        m_callback(false, m_message);
    }

    m_user_agent.callback()->update_messages({m_message});
    return 0;
}

}
}
