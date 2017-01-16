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

#include "secret_chat_encryptor.h"

void query_messages_send_encrypted_message::assemble()
{
    secret_chat_encryptor encryptor(m_secret_chat, serializer());
    out_i32(CODE_messages_send_encrypted);
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
    out_i32(CODE_decrypted_message);
    out_i64(m_message->permanent_id);
    out_i32(m_secret_chat->ttl());
    out_std_string(m_message->message);

    assert(m_message->media);

    switch (m_message->media->type()) {
    case tgl_message_media_type::none:
        out_i32(CODE_decrypted_message_media_empty);
        break;
    case tgl_message_media_type::geo:
    {
        auto media = std::static_pointer_cast<tgl_message_media_geo>(m_message->media);
        out_i32(CODE_decrypted_message_media_geo_point);
        out_double(media->geo.latitude);
        out_double(media->geo.longitude);
        break;
    }
    default:
        assert(false);
    }
    encryptor.end();

    m_secret_chat->private_facet()->set_out_seq_no(m_secret_chat->out_seq_no() + 1);
    tgl_state::instance()->callback()->secret_chat_update(m_secret_chat);
}
