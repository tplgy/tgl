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
    Copyright Topology LP 2016
*/

#ifndef __TGL_MESSAGE_H__
#define __TGL_MESSAGE_H__

#include "tgl_message_action.h"
#include "tgl_message_entity.h"
#include "tgl_message_media.h"
#include "tgl_peer_id.h"

#include <bitset>
#include <cstdint>
#include <memory>
#include <vector>

struct tgl_message_reply_markup {
    int flags;
    std::vector<std::vector<std::string>> button_matrix;
    tgl_message_reply_markup(): flags(0) { }
};

class tgl_secret_chat;
struct tl_ds_message_media;
struct tl_ds_message_action;
struct tl_ds_reply_markup;
struct tl_ds_decrypted_message_media;
struct tl_ds_decrypted_message_action;
struct tl_ds_encrypted_file;

struct tgl_message {
    int64_t server_id;
    int64_t random_id;
    int64_t fwd_date;
    int64_t date;
    int64_t permanent_id;
    int32_t reply_id;
    int32_t seq_no;
    tgl_peer_id_t fwd_from_id;
    tgl_peer_id_t from_id;
    tgl_input_peer_t to_id;
    std::vector<std::shared_ptr<tgl_message_entity>> entities;
    std::shared_ptr<tgl_message_reply_markup> reply_markup;
    std::shared_ptr<tgl_message_action> action;
    std::shared_ptr<tgl_message_media> media;
    std::string message;

    tgl_message();

    tgl_message(int64_t message_id,
            const tgl_peer_id_t& from_id,
            const tgl_input_peer_t& to_id,
            const tgl_peer_id_t* fwd_from_id,
            const int64_t* fwd_date,
            const int64_t* date,
            const std::string& message,
            const tl_ds_message_media* media,
            const tl_ds_message_action* action,
            int32_t reply_id,
            const tl_ds_reply_markup* reply_markup);

    tgl_message(const std::shared_ptr<tgl_secret_chat>& secret_chat,
            int64_t message_id,
            const tgl_peer_id_t& from_id,
            const int64_t* date,
            const std::string& message,
            const tl_ds_decrypted_message_media* media,
            const tl_ds_decrypted_message_action* action,
            const tl_ds_encrypted_file* file);

    bool is_unread() const { return m_flags[index_unread]; }
    bool is_outgoing() const { return m_flags[index_outgoing]; }
    bool is_mention() const { return m_flags[index_mention]; }
    bool is_pending() const { return m_flags[index_pending]; }
    bool is_service() const { return m_flags[index_service]; }
    bool is_send_failed() const { return m_flags[index_send_failed]; }
    bool is_history() const { return m_flags[index_history]; }

    tgl_message& set_unread(bool b) { m_flags[index_unread] = b; return *this; }
    tgl_message& set_outgoing(bool b) { m_flags[index_outgoing] = b; return *this; }
    tgl_message& set_mention(bool b) { m_flags[index_mention] = b; return *this; }
    tgl_message& set_pending(bool b) { m_flags[index_pending] = b; return *this; }
    tgl_message& set_service(bool b) { m_flags[index_service] = b; return *this; }
    tgl_message& set_send_failed(bool b) { m_flags[index_send_failed] = b; return *this; }
    tgl_message& set_history(bool b) { m_flags[index_history] = b; return *this; }

    void set_decrypted_message_media(const tl_ds_decrypted_message_media*);

private:
    static constexpr size_t index_unread = 0;
    static constexpr size_t index_outgoing = 1;
    static constexpr size_t index_mention = 2;
    static constexpr size_t index_pending = 3;
    static constexpr size_t index_service = 4;
    static constexpr size_t index_send_failed = 5;
    static constexpr size_t index_history = 6;
    std::bitset<32> m_flags;
};

#endif
