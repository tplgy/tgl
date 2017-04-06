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

#include "query_messages_send_encrypted_message.h"

#include "message.h"
#include "secret_chat.h"
#include "secret_chat_encryptor.h"

namespace tgl {
namespace impl {

query_messages_send_encrypted_message::query_messages_send_encrypted_message(
        user_agent& ua,
        const std::shared_ptr<secret_chat>& sc,
        const std::shared_ptr<tgl_unconfirmed_secret_message>& unconfirmed_message,
        const std::function<void(bool, const std::shared_ptr<message>&)>& callback) throw(std::runtime_error)
    : query_messages_send_encrypted_base(ua, "send encrypted message (reassembled)", sc, nullptr, callback, true)
{
    if (sc->layer() < 17) {
        throw std::runtime_error("we shouldn't have tried to construct a query from unconfirmed message "
                "for the secret chat with layer less than 17");
    }

    const auto& blobs = unconfirmed_message->blobs();
    if (unconfirmed_message->constructor_code() != CODE_messages_send_encrypted
            || blobs.size() != 1) {
        throw std::runtime_error("invalid message blob for query_messages_send_encrypted_message");
    }

    const std::string& layer_blob = blobs[0];
    if (layer_blob.size() % 4) {
        throw std::runtime_error("message blob for query_messages_send_encrypted_message don't align in 4 bytes boundary");
    }

    out_i32(CODE_messages_send_encrypted);
    out_i32(CODE_input_encrypted_chat);
    out_i32(m_secret_chat->id().peer_id);
    out_i64(m_secret_chat->id().access_hash);
    out_i64(unconfirmed_message->message_id());
    secret_chat_encryptor encryptor(m_secret_chat, serializer());
    encryptor.start();
    out_i32s(reinterpret_cast<const int32_t*>(layer_blob.data()), layer_blob.size() / 4);
    encryptor.end();

    construct_message(unconfirmed_message->message_id(), unconfirmed_message->date(), layer_blob);
    m_user_agent.callback()->update_messages({m_message});
}

void query_messages_send_encrypted_message::assemble()
{
    int32_t layer = m_secret_chat->layer();

    out_i32(CODE_messages_send_encrypted);
    out_i32(CODE_input_encrypted_chat);
    out_i32(m_secret_chat->id().peer_id);
    out_i64(m_secret_chat->id().access_hash);
    out_i64(m_message->id());
    secret_chat_encryptor encryptor(m_secret_chat, serializer());
    encryptor.start();
    size_t start = 0;

    if (layer >= 17) {
        start = begin_unconfirmed_message(CODE_messages_send_encrypted);
        out_i32(CODE_decrypted_message_layer);
        out_random(15 + 4 * (tgl_random<int>() % 3));
        out_i32(layer);
        out_i32(m_secret_chat->raw_in_seq_no());
        out_i32(m_secret_chat->raw_out_seq_no());
    }

    if (layer >= 46 ) {
        out_i32(CODE_decrypted_message);
        out_i32(1 << 9);
        out_i64(m_message->id());
        out_i32(m_secret_chat->ttl());
    } else if (layer >= 17) {
        out_i32(CODE_decrypted_message_layer17);
        out_i64(m_message->id());
        out_i32(m_secret_chat->ttl());
    } else {
        out_i32(CODE_decrypted_message_layer8);
        out_i64(m_message->id());
        out_random(15 + 4 * (tgl_random<int>() % 3));
        if (layer < 8) {
            TGL_ERROR("invalid secret chat layer " << layer);
            assert(false);
        }
    }

    out_std_string(m_message->text());
    assert(m_message->media());
    switch (m_message->media()->type()) {
    case tgl_message_media_type::none:
        out_i32(CODE_decrypted_message_media_empty);
        break;
    case tgl_message_media_type::geo:
    {
        auto media = std::static_pointer_cast<tgl_message_media_geo>(m_message->media());
        out_i32(CODE_decrypted_message_media_geo_point);
        out_double(media->geo.latitude);
        out_double(media->geo.longitude);
        break;
    }
    default:
        assert(false);
    }
    if (layer >= 17) {
        append_blob_to_unconfirmed_message(start);
    }
    encryptor.end();
}

}
}
