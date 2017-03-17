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

#include "message.h"
#include "secret_chat.h"
#include "secret_chat_encryptor.h"

namespace tgl {
namespace impl {

query_messages_send_encrypted_action::query_messages_send_encrypted_action(
        const std::shared_ptr<secret_chat>& sc,
        const std::shared_ptr<tgl_unconfirmed_secret_message>& unconfirmed_message,
        const std::function<void(bool, const std::shared_ptr<message>&)>& callback) throw(std::runtime_error)
    : query_messages_send_encrypted_base("send encrypted action (reassembled)", sc, nullptr, callback, true)
{
    const auto& blobs = unconfirmed_message->blobs();
    if (unconfirmed_message->constructor_code() != CODE_messages_send_encrypted_service
            || blobs.size() != 1) {
        throw std::runtime_error("invalid message blob for query_messages_send_encrypted_action");
    }

    const std::string& layer_blob = blobs[0];
    if (layer_blob.size() % 4) {
        throw std::runtime_error("message blob for query_messages_send_encrypted_action don't align in 4 bytes boundary");
    }

    out_i32(CODE_messages_send_encrypted_service);
    out_i32(CODE_input_encrypted_chat);
    out_i32(m_secret_chat->id().peer_id);
    out_i64(m_secret_chat->id().access_hash);
    out_i64(unconfirmed_message->message_id());
    secret_chat_encryptor encryptor(m_secret_chat, serializer());
    encryptor.start();
    out_i32s(reinterpret_cast<const int32_t*>(layer_blob.data()), layer_blob.size() / 4);
    encryptor.end();

    construct_message(unconfirmed_message->message_id(), unconfirmed_message->date(), layer_blob);
}

void query_messages_send_encrypted_action::assemble()
{
    assert(m_message->action());

    out_i32(CODE_messages_send_encrypted_service);
    out_i32(CODE_input_encrypted_chat);
    out_i32(m_secret_chat->id().peer_id);
    out_i64(m_secret_chat->id().access_hash);
    out_i64(m_message->id());
    secret_chat_encryptor encryptor(m_secret_chat, serializer());
    encryptor.start();
    size_t start = begin_unconfirmed_message(CODE_messages_send_encrypted_service);
    out_i32(CODE_decrypted_message_layer);
    out_random(15 + 4 * (tgl_random<int>() % 3));
    out_i32(TGL_ENCRYPTED_LAYER);
    out_i32(m_secret_chat->raw_in_seq_no());
    out_i32(m_secret_chat->raw_out_seq_no());
    out_i32(CODE_decrypted_message_service);
    out_i64(m_message->id());

    switch (m_message->action()->type()) {
    case tgl_message_action_type::notify_layer:
        out_i32(CODE_decrypted_message_action_notify_layer);
        out_i32(std::static_pointer_cast<tgl_message_action_notify_layer>(m_message->action())->layer);
        break;
    case tgl_message_action_type::set_message_ttl:
        out_i32(CODE_decrypted_message_action_set_message_ttl);
        out_i32(std::static_pointer_cast<tgl_message_action_set_message_ttl>(m_message->action())->ttl);
        break;
    case tgl_message_action_type::request_key:
    {
        auto action = std::static_pointer_cast<tgl_message_action_request_key>(m_message->action());
        out_i32(CODE_decrypted_message_action_request_key);
        out_i64(action->exchange_id);
        out_string(reinterpret_cast<char*>(action->g_a.data()), 256);
        break;
    }
    case tgl_message_action_type::accept_key:
    {
        auto action = std::static_pointer_cast<tgl_message_action_accept_key>(m_message->action());
        out_i32(CODE_decrypted_message_action_accept_key);
        out_i64(action->exchange_id);
        out_string(reinterpret_cast<char*>(action->g_a.data()), 256);
        out_i64(action->key_fingerprint);
        break;
    }
    case tgl_message_action_type::commit_key:
    {
        auto action = std::static_pointer_cast<tgl_message_action_commit_key>(m_message->action());
        out_i32(CODE_decrypted_message_action_commit_key);
        out_i64(action->exchange_id);
        out_i64(action->key_fingerprint);
        break;
    }
    case tgl_message_action_type::abort_key:
    {
        auto action = std::static_pointer_cast<tgl_message_action_abort_key>(m_message->action());
        out_i32(CODE_decrypted_message_action_abort_key);
        out_i64(action->exchange_id);
        break;
    }
    case tgl_message_action_type::noop:
        out_i32(CODE_decrypted_message_action_noop);
        break;
    case tgl_message_action_type::resend:
    {
        auto action = std::static_pointer_cast<tgl_message_action_resend>(m_message->action());
        out_i32(CODE_decrypted_message_action_resend);
        out_i32(action->start_seq_no);
        out_i32(action->end_seq_no);
        break;
    }
    case tgl_message_action_type::delete_messages:
    {
        auto action = std::static_pointer_cast<tgl_message_action_delete_messages>(m_message->action());
        out_i32 (CODE_decrypted_message_action_delete_messages);
        out_i32(CODE_vector);
        out_i32(action->msg_ids.size());
        for (auto id : action->msg_ids) {
            out_i64(id);
        }
        break;
    }
    case tgl_message_action_type::opaque_message:
    {
        auto action = std::static_pointer_cast<tgl_message_action_opaque_message>(m_message->action());
        out_i32(CODE_decrypted_message_action_opaque_message);
        out_std_string(action->message);
        break;
    }
    default:
        assert(false);
    }
    append_blob_to_unconfirmed_message(start);
    encryptor.end();
    end_unconfirmed_message();
}

}
}
