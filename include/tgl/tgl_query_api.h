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

#include "tgl_channel.h"
#include "tgl_chat.h"
#include "tgl_message.h"
#include "tgl_privacy_rule.h"
#include "tgl_typing_status.h"
#include "tgl_user.h"

#include <functional>
#include <memory>
#include <string>
#include <vector>

class tgl_secret_chat;

class tgl_query_api {
public:
    virtual ~tgl_query_api() { }

    virtual void get_terms_of_service(const std::function<void(bool success, const std::string&)>& callback) = 0;

    // Registers the device for push notifications
    virtual void register_device(int32_t token_type, const std::string& token,
            const std::string& device_model,
            const std::string& system_version,
            const std::string& app_version,
            bool app_sandbox,
            const std::string& lang_code,
            const std::function<void(bool success)>& callback) = 0;

    virtual void unregister_device(int32_t token_type, const std::string& token,
            const std::function<void(bool success)>& callback) = 0;

    // Set password if there is no password: the API user will get tgl_update_callback::get_value() callback with tgl_value::new_password.
    // Change password if there is password: the API user will get tgl_update_callback::get_value() callback with tgl_value::current_and_new_password.
    // Turn off password if there is password: the API user will get tgl_update_callback::get_value() callback with tgl_value::current_and_new_password
    // and it is expected to pass the empty new password to turn password off.
    virtual void update_password_settings(const std::function<void(bool success)>& callback) = 0;

    // If 0 is passed as message_id this function returns a non-zero int64_t as message id.
    // Otherwise it uses the message_id passed in and returns it. The message id can be changed
    // by the server except for secret chats.
    virtual int64_t send_text_message(const tgl_input_peer_t& peer_id, const std::string& text, int64_t message_id = 0,
            int32_t reply_id = 0, bool disable_preview = false, bool post_as_channel_message = false,
            bool send_as_secret_chat_service_message = false,
            const std::function<void(bool success, const std::shared_ptr<tgl_message>& message)>& callback = nullptr) = 0;

    // Forward message *msg_id* to peer *id*
    // message can not be encrypted and peer can not be secret chat
    virtual void forward_message(const tgl_input_peer_t& from_id, const tgl_input_peer_t& to_id, int64_t message_id,
            const std::function<void(bool success, const std::shared_ptr<tgl_message>& M)>& callback) = 0;

    // Forward messages *ids* to peer *id*
    // messages can not be encrypted and peer can not be secret chat
    virtual void forward_messages(const tgl_input_peer_t& from_id, const tgl_input_peer_t& to_id, const std::vector<int64_t>& message_ids,
            bool post_as_channel_message, const std::function<void(bool success, const std::vector<std::shared_ptr<tgl_message>>& messages)>& callback) = 0;

    virtual void mark_message_read(const tgl_input_peer_t& id, int32_t max_id_or_time, const std::function<void(bool success)>& callback) = 0;

    // Sends contact to another user. This contact may be or may not be telegram user
    virtual void send_contact(const tgl_input_peer_t& id,
            const std::string& phone, const std::string& first_name, const std::string& last_name, int32_t reply_id,
            const std::function<void(bool success, const std::shared_ptr<tgl_message>& message)>& callback) = 0;

    // Sends media from message *msg_id* to another dialog
    // a bit different from forwarding message with media
    // secret message media can be forwarded to secret chats
    // and non-secret - to non-secret chats and users
    virtual void forward_media(const tgl_input_peer_t& to_id, int64_t message_id, bool post_as_channel_message,
            const std::function<void(bool success, const std::shared_ptr<tgl_message>& message)>& callback) = 0;

    // Sends location to chat *id*
    virtual void send_location(const tgl_input_peer_t& id, double latitude, double longitude, int32_t reply_id = 0, bool post_as_channel_message = false,
            const std::function<void(bool success, const std::shared_ptr<tgl_message>& message)>& callback = nullptr) = 0;

    // Sends broadcast (i.e. message to several users at once)
    virtual void send_broadcast(const std::vector<tgl_input_peer_t>& peers, const std::string& text,
            const std::function<void(bool success, const std::vector<std::shared_ptr<tgl_message>>& messages)>& callback) = 0;

    // Rename self account
    virtual void set_profile_name(const std::string& first_name, const std::string& last_name,
            const std::function<void(bool success)>& callback) = 0;

    // Check if username is valid
    virtual void check_username(const std::string& username, const std::function<void(int result)>& callback) = 0;

    // Sets self username
    virtual void set_username(const std::string& username, const std::function<void(bool success)>& callback) = 0;

    // Updates online/offline status
    virtual void update_status(bool online, const std::function<void(bool success)>& callback) = 0;

    // Exports card. This card can be later be used by another user to add you to dialog list.
    virtual void export_card(const std::function<void(bool success, const std::vector<int>& card)>& callback) = 0;

    // Sets chat title
    virtual void rename_chat(const tgl_input_peer_t& id, const std::string& new_title,
            const std::function<void(bool success)>& callback) = 0;

    // Requests full info about chat *id*.
    virtual void get_chat_info(int32_t id, const std::function<void(bool success)>& callback) = 0;

    virtual void get_channel_info(const tgl_input_peer_t& id, const std::function<void(bool success)>& callback) = 0;

    virtual void get_channel_participants(const tgl_input_peer_t& channel_id, int limit, int offset,
            tgl_channel_participant_type type, const std::function<void(bool success)>& callback) = 0;

    virtual void get_channel_participant_self(const tgl_input_peer_t& channel_id, const std::function<void(bool success)>& callback) = 0;

    // Adds user *id* to chat *chat_id*.
    // Sends *limit* last messages from this chat to user
    virtual void add_user_to_chat(const tgl_peer_id_t& chat_id, const tgl_input_peer_t& user_id, int32_t limit,
            const std::function<void(bool success)>& callback) = 0;

    // Deleted user *id* from chat *chat_id*.
    // You can do it if you are admin (=creator) of chat or if you invited this user or if it is yourself.
    virtual void delete_user_from_chat(int32_t chat_id, const tgl_input_peer_t& user_id,
            const std::function<void(bool success)>& callback) = 0;

    // Creates group chat with users ids.
    // There should be at least one user other then you in chat
    virtual void create_group_chat(const std::vector<tgl_input_peer_t>& user_ids, const std::string& chat_topic,
            const std::function<void(int32_t chat_id)>& callback) = 0;

    // Receives invitation link to this chat. Only chat admin can create one prevoius link invalidated, if existed.
    virtual void export_chat_link(const tgl_peer_id_t& id, const std::function<void(bool success, const std::string& link)>& callback) = 0;

    // Joins to chat by link (or hash of this link).
    virtual void import_chat_link(const std::string& link, const std::function<void(bool success)>& callback) = 0;

    // Requests full info about user *id*.
    // If *offline_mode* is set no actual query is sent
    virtual void get_user_info(const tgl_input_peer_t& id, const std::function<void(bool success, const std::shared_ptr<tgl_user>& user)>& callback) = 0;

    // Adds contacts to contact list by phone number.
    // The user will be named  *first_name* *last_name* in contact list.
    virtual void add_contacts(const std::vector<std::tuple<std::string, std::string, std::string>>& contacts,
            bool replace, const std::function<void(bool success, const std::vector<int32_t>& user_ids)>& callback) = 0;

    // Deletes user *id* from contact list
    virtual void delete_contact(const tgl_input_peer_t& id, const std::function<void(bool success)>& callback) = 0;

    // Imports card exported by another user
    virtual void import_card(int size, int* card, const std::function<void(bool success, const std::shared_ptr<tgl_user>& user)>& callback) = 0;

    // Blocks a user.
    virtual void block_user(const tgl_input_peer_t& id, const std::function<void(bool success)>& callback) = 0;

    // Unblocks blocked a user.
    virtual void unblock_user(const tgl_input_peer_t& id, const std::function<void(bool success)>& callback) = 0;

    // Gets blocked users
    virtual void get_blocked_users(const std::function<void(std::vector<int32_t>)>& callback) = 0;

    // Updates peer notification settings.
    virtual void update_notify_settings(const tgl_input_peer_t& peer_id,
            int32_t mute_until, const std::string& sound, bool show_previews, int32_t mask, const std::function<void(bool)>& callback) = 0;

    // Gets peer notification settings.
    virtual void get_notify_settings(const tgl_input_peer_t& peer_id,
            const std::function<void(bool, int32_t mute_until)>& callback) = 0;

    // Accepts secret chat request. It can fail if another device will be first to accept it
    virtual void accept_encr_chat_request(const std::shared_ptr<tgl_secret_chat>& secret_chat,
            const std::function<void(bool success, const std::shared_ptr<tgl_secret_chat>&)>& callback) = 0;

    // Sets ttl of secret chat
    virtual void set_secret_chat_ttl(const std::shared_ptr<tgl_secret_chat>& secret_chat, int32_t ttl) = 0;

    virtual void discard_secret_chat(const std::shared_ptr<tgl_secret_chat>& secret_chat,
            const std::function<void(bool success, const std::shared_ptr<tgl_secret_chat>&)>& callback) = 0;

    // Requests creation of secret chat with user id
    virtual void create_secret_chat(const tgl_input_peer_t& user_id, int32_t new_secret_chat_id,
            const std::function<void(bool success, const std::shared_ptr<tgl_secret_chat>& secret_chat)>& callback) = 0;

    // Receives all dialogs(except secret chats) from offset=*offset* with limit=*limit*.
    // Dialogs are sorted by last message received.
    // If limit is > 100 there is a (small) chance of one dialog received twice.
    virtual void get_dialog_list(int32_t limit, int32_t offset,
            const std::function<void(bool success,
                    const std::vector<tgl_peer_id_t>& peers,
                    const std::vector<int64_t>& last_msg_ids,
                    const std::vector<int32_t>& unread_count)>& callback) = 0;

    // Search for username
    virtual void search_contact(const std::string& username, int limit,
            const std::function<void(const std::vector<std::shared_ptr<tgl_user>>&,
                    const std::vector<std::shared_ptr<tgl_chat>>&)>& callback) = 0;

    // Resolves username
    virtual void resolve_username(const std::string& name, const std::function<void(bool success)>& callback) = 0;

    virtual void update_contact_list(const std::function<void(bool, const std::vector<std::shared_ptr<tgl_user>>&)>& callback) = 0;

    // Requests last *limit* from offset *offset* (offset = 0 means most recent) messages from dialog with peer id.
    // If offline_mode=1 then no actual query is sent.
    // Only locally cached messages returned.
    // Also marks messages from this chat as read.
    virtual void get_history(const tgl_input_peer_t& id, int32_t offset, int32_t limit,
            const std::function<void(bool success, const std::vector<std::shared_ptr<tgl_message>>& list)>& callback) = 0;

    // Sends typing event to chat.
    // Set status=tgl_typing_typing for default typing event.
    virtual void send_typing(const tgl_input_peer_t& id, enum tgl_typing_status status,
            const std::function<void(bool success)>& callback) = 0;

    // Search messages with ids *from* .. *to* in dialog id
    // id type of id is UNKNOWN uses global search (in all dialogs) instead
    // if *from* or *to* is means *from*=0 and *to*=+INF
    // return up to *limit* entries from offset=*offset*
    virtual void search_message(const tgl_input_peer_t& id, int32_t from, int32_t to, int32_t limit, int32_t offset, const std::string& query,
            const std::function<void(bool success, const std::vector<std::shared_ptr<tgl_message>>& messages)>& callback) = 0;

    virtual void delete_message(const tgl_input_peer_t& chat, int64_t message_id, const std::function<void(bool success)>& callback) = 0;

    // Gets message by *id*
    virtual void get_message(int64_t message_id,
            const std::function<void(bool success, const std::shared_ptr<tgl_message>& message)>& callback) = 0;

    virtual void start_bot(const tgl_input_peer_t& bot, const tgl_peer_id_t& chat, const std::string& name,
            const std::function<void(bool success)>& callback) = 0;

    virtual void set_phone_number(const std::string& phonenumber, const std::function<void(bool success)>& callback) = 0;

    virtual void get_privacy_rules(std::function<void(bool, const std::vector<std::pair<tgl_privacy_rule, const std::vector<int32_t>>>&)> callback) = 0;

    virtual void leave_channel(const tgl_input_peer_t& channel_id, const std::function<void(bool success)>& callback) = 0;

    virtual void delete_channel(const tgl_input_peer_t& channel_id, const std::function<void(bool success)>& callback) = 0;

    virtual void channel_invite_user(const tgl_input_peer_t& channel_id, const std::vector<tgl_input_peer_t>& user_ids,
            const std::function<void(bool success)>& callback) = 0;

    virtual void channel_delete_user(const tgl_input_peer_t& channel_id, const tgl_input_peer_t& user_id,
            const std::function<void(bool success)>& callback) = 0;

    virtual void channel_edit_title(const tgl_input_peer_t& channel_id, const std::string& title,
            const std::function<void(bool success)>& callback) = 0;

    virtual void create_channel(const std::string& topic, const std::string& about,
            bool broadcast, bool mega_group,
            const std::function<void(int32_t channel_id)>& callback) = 0;

    // Only support getting back one inline text message if any responded by the bot.
    // If the bot returns anything else than a inline text message the value of response
    // in the callback will be empty.
    virtual void send_inline_query_to_bot(const tgl_input_peer_t& bot, const std::string& query,
            const std::function<void(bool success, const std::string& response)>& callback) = 0;

    virtual void get_difference(bool sync_from_start, const std::function<void(bool success)>& callback) = 0;

    virtual void rename_channel(const tgl_input_peer_t& id, const std::string& name,
            const std::function<void(bool success)>& callback) = 0;

    virtual void join_channel(const tgl_input_peer_t& id, const std::function<void(bool success)>& callback) = 0;

    virtual void channel_set_about(const tgl_input_peer_t& id, const std::string& about,
            const std::function<void(bool success)>& callback) = 0;

    virtual void channel_set_username(const tgl_input_peer_t& id, const std::string& username,
            const std::function<void(bool success)>& callback) = 0;

    virtual void get_channel_difference(const tgl_input_peer_t& channel_id,
            const std::function<void(bool success)>& callback) = 0;

    virtual void export_channel_link(const tgl_input_peer_t& id,
            const std::function<void(bool success, const std::string& link)>& callback) = 0;

    virtual void upgrade_group(const tgl_peer_id_t& id, const std::function<void(bool success)>& callback) = 0;
    virtual void get_channels_dialog_list(int limit, int offset,
            const std::function<void(bool success,
                    const std::vector<tgl_peer_id_t>& peers,
                    const std::vector<int64_t>& last_msg_ids,
                    const std::vector<int>& unread_count)>& callback) = 0;
};
