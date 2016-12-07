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

#ifndef __TGL_UPDATE_CALLBACK__
#define __TGL_UPDATE_CALLBACK__

#include "tgl.h"
#include "tgl_connection_status.h"
#include "tgl_message.h"
#include "tgl_secret_chat.h"
#include "tgl_typing_status.h"

#include <map>
#include <memory>

struct tgl_chat;
struct tgl_chat_participant;
struct tgl_channel;
struct tgl_channel_participant;
struct tgl_user_status;
struct tgl_user;

class tgl_update_callback {
public:
    virtual void qts_changed(int32_t new_value) = 0;
    virtual void pts_changed(int32_t new_value) = 0;
    virtual void date_changed(int64_t new_value) = 0;
    virtual void new_messages(const std::vector<std::shared_ptr<tgl_message>>& msgs) = 0;
    virtual void message_id_update(int64_t old_msg_id, int64_t new_msg_id, int32_t out_seq_no, const tgl_input_peer_t& peer) = 0;
    virtual void message_deleted(int64_t msg_id) = 0;
    virtual void messages_mark_read_in(tgl_peer_id_t peer, int msg_id) = 0;
    virtual void messages_mark_read_out(tgl_peer_id_t peer, int msg_id) = 0;
    virtual void get_values(enum tgl_value_type type, const char* prompt, int num_values,
            std::function<void(const void* answer)>) = 0;
    virtual void logged_in() = 0;
    virtual void logged_out(bool success) = 0;
    virtual void started() = 0;
    virtual void typing_status_changed(int user_id, int chat_id, tgl_peer_type chat_type, enum tgl_typing_status status) = 0;
    virtual void status_notification(int user_id, const tgl_user_status& status) = 0;
    virtual void user_registered(int user_id) = 0;
    virtual void new_authorization(const std::string& device, const std::string& location) = 0;
    virtual void new_user(const std::shared_ptr<tgl_user>& user) = 0;
    virtual void user_update(int32_t user_id, const std::map<tgl_user_update_type, std::string>& updates) = 0;
    virtual void user_deleted(int32_t id) = 0;
    virtual void avatar_update(int32_t peer_id, tgl_peer_type peer_type, const tgl_file_location &photo_small, const tgl_file_location &photo_big) = 0;
    virtual void chat_update(const std::shared_ptr<tgl_chat>& chat) = 0;
    virtual void chat_update_participants(int32_t chat_id, const std::vector<std::shared_ptr<tgl_chat_participant>>& participants) = 0;
    virtual void chat_update_notify_settings(int32_t chat_id, int32_t mute_until) = 0;
    virtual void chat_delete_user(int32_t chat_id, int user) = 0;
    virtual void channel_update_participants(int32_t channel_id, const std::vector<std::shared_ptr<tgl_channel_participant>>& participants) = 0;
    virtual void secret_chat_update(const std::shared_ptr<tgl_secret_chat>& secret_chat) = 0;
    virtual void channel_update(const std::shared_ptr<tgl_channel>& channel) = 0;
    virtual void channel_update_info(int32_t channel_id, const std::string& description, int32_t participants_count) = 0;
    virtual void channel_update_notify_settings(int32_t channel_id, int32_t mute_until) = 0;
    virtual void our_id(int32_t id) = 0;
    virtual void notification(const std::string& type, const std::string& message) = 0;
    virtual void user_status_update(struct tgl_user* U) = 0;
    virtual void dc_update(const std::shared_ptr<tgl_dc>& dc) = 0;
    virtual void change_active_dc(int new_dc_id) = 0;
    virtual void on_failed_login() = 0;
    virtual void connection_status_changed(tgl_connection_status status) = 0;
    virtual ~tgl_update_callback() { }
};

#endif
