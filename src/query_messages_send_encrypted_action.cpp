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

#include "query_messages_send_encrypted_action.h"

#include "secret_chat_encryptor.h"

void query_messages_send_encrypted_action::assemble()
{
    assert(m_message->action);

    secret_chat_encryptor encryptor(m_secret_chat, serializer());
    out_i32(CODE_messages_send_encrypted_service);
    out_i32(CODE_input_encrypted_chat);
    out_i32(m_secret_chat->id().peer_id);
    out_i64(m_secret_chat->id().access_hash);
    out_i64(m_message->permanent_id);
    encryptor.start();
    out_i32(CODE_decrypted_message_layer);
    out_random(15 + 4 * (tgl_random<int>() % 3));
    out_i32(TGL_ENCRYPTED_LAYER);
    out_i32(m_secret_chat->private_facet()->raw_in_seq_no());
    out_i32(m_secret_chat->private_facet()->raw_out_seq_no());
    out_i32(CODE_decrypted_message_service);
    out_i64(m_message->permanent_id);

    switch (m_message->action->type()) {
    case tgl_message_action_type::notify_layer:
        out_i32(CODE_decrypted_message_action_notify_layer);
        out_i32(std::static_pointer_cast<tgl_message_action_notify_layer>(m_message->action)->layer);
        break;
    case tgl_message_action_type::set_message_ttl:
        out_i32(CODE_decrypted_message_action_set_message_ttl);
        out_i32(std::static_pointer_cast<tgl_message_action_set_message_ttl>(m_message->action)->ttl);
        break;
    case tgl_message_action_type::request_key:
    {
        auto action = std::static_pointer_cast<tgl_message_action_request_key>(m_message->action);
        out_i32(CODE_decrypted_message_action_request_key);
        out_i64(action->exchange_id);
        out_string(reinterpret_cast<char*>(action->g_a.data()), 256);
        break;
    }
    case tgl_message_action_type::accept_key:
    {
        auto action = std::static_pointer_cast<tgl_message_action_accept_key>(m_message->action);
        out_i32(CODE_decrypted_message_action_accept_key);
        out_i64(action->exchange_id);
        out_string(reinterpret_cast<char*>(action->g_a.data()), 256);
        out_i64(action->key_fingerprint);
        break;
    }
    case tgl_message_action_type::commit_key:
    {
        auto action = std::static_pointer_cast<tgl_message_action_commit_key>(m_message->action);
        out_i32(CODE_decrypted_message_action_commit_key);
        out_i64(action->exchange_id);
        out_i64(action->key_fingerprint);
        break;
    }
    case tgl_message_action_type::abort_key:
    {
        auto action = std::static_pointer_cast<tgl_message_action_abort_key>(m_message->action);
        out_i32(CODE_decrypted_message_action_abort_key);
        out_i64(action->exchange_id);
        break;
    }
    case tgl_message_action_type::noop:
        out_i32(CODE_decrypted_message_action_noop);
        break;
    case tgl_message_action_type::resend:
    {
        auto action = std::static_pointer_cast<tgl_message_action_resend>(m_message->action);
        out_i32(CODE_decrypted_message_action_resend);
        out_i32(action->start_seq_no);
        out_i32(action->end_seq_no);
        break;
    }
    case tgl_message_action_type::delete_messages:
    {
        auto action = std::static_pointer_cast<tgl_message_action_delete_messages>(m_message->action);
        out_i32 (CODE_decrypted_message_action_delete_messages);
        out_i32(CODE_vector);
        out_i32(action->msg_ids.size());
        for (auto id : action->msg_ids) {
            out_i64(id);
        }
        break;
    }
    default:
        assert(false);
    }
    encryptor.end();
}
