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

#include "query_messages_send_encrypted_file.h"

#include "secret_chat_encryptor.h"

query_messages_send_encrypted_file::query_messages_send_encrypted_file(
        const std::shared_ptr<tgl_secret_chat>& secret_chat,
        const std::shared_ptr<tgl_unconfirmed_secret_message>& unconfirmed_message,
        const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback) throw(std::runtime_error)
    : query_messages_send_encrypted_base("send encrypted file message (reassembled)", secret_chat, nullptr, callback, true)
{
    const auto& blobs = unconfirmed_message->blobs();
    if (unconfirmed_message->constructor_code() != CODE_messages_send_encrypted_file
            || blobs.size() != 2) {
        throw std::runtime_error("invalid message blobs for query_messages_send_encrypted_file");
    }

    const std::string& layer_blob = blobs[0];
    const std::string& input_file_info_blob = blobs[1];
    if ((layer_blob.size() % 4) || (input_file_info_blob.size() % 4)) {
        throw std::runtime_error("message blobs for query_messages_send_encrypted_file don't align in 4 bytes boundary");
    }

    out_i32(CODE_messages_send_encrypted_file);
    out_i32(CODE_input_encrypted_chat);
    out_i32(m_secret_chat->id().peer_id);
    out_i64(m_secret_chat->id().access_hash);
    out_i64(unconfirmed_message->message_id());
    secret_chat_encryptor encryptor(m_secret_chat, serializer());
    encryptor.start();
    out_i32s(reinterpret_cast<const int32_t*>(layer_blob.data()), layer_blob.size() / 4);
    encryptor.end();
    out_i32s(reinterpret_cast<const int32_t*>(input_file_info_blob.data()), input_file_info_blob.size() / 4);

    construct_message(unconfirmed_message->message_id(), unconfirmed_message->date(), layer_blob);
}
