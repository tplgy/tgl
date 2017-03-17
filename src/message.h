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

#pragma once

#include "tgl/tgl_message.h"

#include <bitset>

class tgl_secret_chat;

namespace tgl {
namespace impl {

struct tl_ds_decrypted_message_media;
struct tl_ds_decrypted_message_action;
struct tl_ds_encrypted_file;
struct tl_ds_message;
struct tl_ds_message_media;
struct tl_ds_message_action;
struct tl_ds_reply_markup;
struct tl_ds_updates;
struct tl_ds_vector;

class message: public tgl_message
{
public:
    // Could return null.
    static std::shared_ptr<message> create(const tgl_peer_id_t& our_id, const tl_ds_message*);
    static std::shared_ptr<message> create_from_short_update(const tgl_peer_id_t& our_id, const tl_ds_updates*);
    static std::shared_ptr<message> create_chat_message_from_short_update(const tl_ds_updates*);

    message(int64_t message_id,
            const tgl_peer_id_t& from_id,
            const tgl_input_peer_t& to_id,
            const tgl_peer_id_t* forward_from_id,
            const int64_t* forward_date,
            const int64_t* date,
            const std::string& text,
            const tl_ds_message_media* media,
            const tl_ds_message_action* action,
            int32_t reply_id,
            const tl_ds_reply_markup* reply_markup);

    message(const std::shared_ptr<tgl_secret_chat>& secret_chat,
            int64_t message_id,
            const tgl_peer_id_t& from_id,
            const int64_t* date,
            const std::string& text,
            const tl_ds_decrypted_message_media* media,
            const tl_ds_decrypted_message_action* action,
            const tl_ds_encrypted_file* file);

    virtual int64_t id() const override { return m_id; }
    virtual int32_t reply_id() const override { return m_reply_id; }
    virtual int64_t forward_date() const override { return m_forward_date; }
    virtual int64_t date() const override { return m_date; }
    virtual int32_t sequence_number() const override { return m_sequence_number; }
    virtual const tgl_peer_id_t& forward_from_id() const override { return m_forward_from_id; }
    virtual const tgl_peer_id_t& from_id() const override { return m_from_id; }
    virtual const tgl_input_peer_t& to_id() const override { return m_to_id; }
    virtual const std::string text() const override { return m_text; }
    virtual const std::shared_ptr<tgl_message_media>& media() const override { return m_media; }
    virtual const std::shared_ptr<tgl_message_action>& action() const override { return m_action; }
    virtual const std::vector<std::shared_ptr<tgl_message_entity>>& entities() const override { return m_entities; }
    virtual const std::shared_ptr<tgl_message_reply_markup>& reply_markup() const override { return m_reply_markup; }
    virtual bool is_unread() const override { return m_flags[index_unread]; }
    virtual bool is_outgoing() const override { return m_flags[index_outgoing]; }
    virtual bool is_mention() const override { return m_flags[index_mention]; }
    virtual bool is_pending() const override { return m_flags[index_pending]; }
    virtual bool is_service() const override { return m_flags[index_service]; }
    virtual bool is_send_failed() const override { return m_flags[index_send_failed]; }
    virtual bool is_history() const override { return m_flags[index_history]; }

    message& set_unread(bool b) { m_flags[index_unread] = b; return *this; }
    message& set_outgoing(bool b) { m_flags[index_outgoing] = b; return *this; }
    message& set_mention(bool b) { m_flags[index_mention] = b; return *this; }
    message& set_pending(bool b) { m_flags[index_pending] = b; return *this; }
    message& set_service(bool b) { m_flags[index_service] = b; return *this; }
    message& set_send_failed(bool b) { m_flags[index_send_failed] = b; return *this; }
    message& set_history(bool b) { m_flags[index_history] = b; return *this; }

    void set_sequence_number(int32_t seq_no) { m_sequence_number = seq_no; }
    void set_decrypted_message_media(const tl_ds_decrypted_message_media*);
    void set_media(const std::shared_ptr<tgl_message_media>& media) { m_media = media; }
    void set_date(int64_t date) { m_date = date; }
    void update_entities(const tl_ds_vector*);

private:
    message();

private:
    static constexpr size_t index_unread = 0;
    static constexpr size_t index_outgoing = 1;
    static constexpr size_t index_mention = 2;
    static constexpr size_t index_pending = 3;
    static constexpr size_t index_service = 4;
    static constexpr size_t index_send_failed = 5;
    static constexpr size_t index_history = 6;

    int64_t m_id;
    int64_t m_forward_date;
    int64_t m_date;
    int32_t m_reply_id;
    int32_t m_sequence_number;
    tgl_peer_id_t m_forward_from_id;
    tgl_peer_id_t m_from_id;
    tgl_input_peer_t m_to_id;
    std::vector<std::shared_ptr<tgl_message_entity>> m_entities;
    std::shared_ptr<tgl_message_reply_markup> m_reply_markup;
    std::shared_ptr<tgl_message_action> m_action;
    std::shared_ptr<tgl_message_media> m_media;
    std::string m_text;
    std::bitset<32> m_flags;
};

}
}
