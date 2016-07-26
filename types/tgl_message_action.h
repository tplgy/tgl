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

#ifndef __TGL_MESSAGE_ACTION_H__
#define __TGL_MESSAGE_ACTION_H__

#include "tgl_message_media.h"
#include "tgl_typing_status.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

enum tgl_message_action_type {
    tgl_message_action_type_none,
    tgl_message_action_type_geo_chat_create,
    tgl_message_action_type_geo_chat_checkin,
    tgl_message_action_type_chat_create,
    tgl_message_action_type_chat_edit_title,
    tgl_message_action_type_chat_edit_photo,
    tgl_message_action_type_chat_delete_photo,
    tgl_message_action_type_chat_add_users,
    tgl_message_action_type_chat_add_user_by_link,
    tgl_message_action_type_chat_delete_user,
    tgl_message_action_type_set_message_ttl,
    tgl_message_action_type_read_messages,
    tgl_message_action_type_delete_messages,
    tgl_message_action_type_screenshot_messages,
    tgl_message_action_type_flush_history,
    tgl_message_action_type_resend,
    tgl_message_action_type_notify_layer,
    tgl_message_action_type_typing,
    tgl_message_action_type_noop,
    tgl_message_action_type_commit_key,
    tgl_message_action_type_abort_key,
    tgl_message_action_type_request_key,
    tgl_message_action_type_accept_key,
    tgl_message_action_type_channel_create,
    tgl_message_action_type_chat_migrate_to,
    tgl_message_action_type_channel_migrate_from
};

struct tgl_message_action {
    virtual tgl_message_action_type type() = 0;
    virtual ~tgl_message_action() { }
};

struct tgl_message_action_chat_create: public tgl_message_action {
    virtual tgl_message_action_type type() override { return tgl_message_action_type_chat_create; }
    std::string title;
    std::vector<int32_t> users;
};

struct tgl_message_action_chat_edit_title: public tgl_message_action {
    virtual tgl_message_action_type type() override { return tgl_message_action_type_chat_edit_title; }
    std::string new_title;
};

struct tgl_message_action_chat_edit_photo: public tgl_message_action {
    tgl_message_action_chat_edit_photo() { }
    explicit tgl_message_action_chat_edit_photo(const std::shared_ptr<tgl_photo>& photo): photo(photo) { }
    virtual tgl_message_action_type type() override { return tgl_message_action_type_chat_edit_photo; }
    std::shared_ptr<tgl_photo> photo;
};

struct tgl_message_action_chat_delete_photo: public tgl_message_action {
    virtual tgl_message_action_type type() override { return tgl_message_action_type_chat_delete_photo; }
};

struct tgl_message_action_chat_add_users: public tgl_message_action {
    virtual tgl_message_action_type type() override { return tgl_message_action_type_chat_add_users; }
    std::vector<int32_t> users;
};

struct tgl_message_action_chat_delete_user: public tgl_message_action {
    tgl_message_action_chat_delete_user(): user_id(0) { }
    explicit tgl_message_action_chat_delete_user(int32_t user_id): user_id(user_id) { }
    virtual tgl_message_action_type type() override { return tgl_message_action_type_chat_delete_user; }
    int32_t user_id;
};

struct tgl_message_action_chat_add_user_by_link: public tgl_message_action {
    tgl_message_action_chat_add_user_by_link(): inviter_id(0) { }
    explicit tgl_message_action_chat_add_user_by_link(int32_t inviter_id): inviter_id(inviter_id) { }
    virtual tgl_message_action_type type() override { return tgl_message_action_type_chat_add_user_by_link; }
    int32_t inviter_id;
};

struct tgl_message_action_channel_create: public tgl_message_action {
    virtual tgl_message_action_type type() override { return tgl_message_action_type_channel_create; }
    std::string title;
};

struct tgl_message_action_chat_migrate_to: public tgl_message_action {
    virtual tgl_message_action_type type() override { return tgl_message_action_type_chat_migrate_to; }
};

struct tgl_message_action_channel_migrate_from: public tgl_message_action {
    virtual tgl_message_action_type type() override { return tgl_message_action_type_channel_migrate_from; }
    std::string title;
};

struct tgl_message_action_screenshot_messages: public tgl_message_action {
    tgl_message_action_screenshot_messages(): screenshot_count(0) { }
    explicit tgl_message_action_screenshot_messages(int32_t count): screenshot_count(count) { }
    virtual tgl_message_action_type type() override { return tgl_message_action_type_screenshot_messages; }
    int32_t screenshot_count;
};

struct tgl_message_action_notify_layer: public tgl_message_action {
    tgl_message_action_notify_layer(): layer(0) { }
    explicit tgl_message_action_notify_layer(int32_t l): layer(l) { }
    virtual tgl_message_action_type type() override { return tgl_message_action_type_notify_layer; }
    int32_t layer;
};

struct tgl_message_action_typing: public tgl_message_action {
    tgl_message_action_typing(): typing_status(tgl_typing_none) { }
    explicit tgl_message_action_typing(tgl_typing_status status): typing_status(status) { }
    virtual tgl_message_action_type type() override { return tgl_message_action_type_typing; }
    tgl_typing_status typing_status;
};

struct tgl_message_action_resend: public tgl_message_action {
    tgl_message_action_resend(): start_seq_no(-1), end_seq_no(-1) { }
    tgl_message_action_resend(int32_t start, int32_t end): start_seq_no(start), end_seq_no(end) { }
    virtual tgl_message_action_type type() override { return tgl_message_action_type_resend; }
    int32_t start_seq_no;
    int32_t end_seq_no;
};

struct tgl_message_action_noop: public tgl_message_action {
    virtual tgl_message_action_type type() override { return tgl_message_action_type_noop; }
};

struct tgl_message_action_request_key: public tgl_message_action {
    tgl_message_action_request_key(): exchange_id(0) { }
    virtual tgl_message_action_type type() override { return tgl_message_action_type_request_key; }
    int64_t exchange_id;
    std::vector<unsigned char> g_a;
};

struct tgl_message_action_accept_key: public tgl_message_action {
    tgl_message_action_accept_key(): exchange_id(0), key_fingerprint(0) { }
    virtual tgl_message_action_type type() override { return tgl_message_action_type_accept_key; }
    int64_t exchange_id;
    int64_t key_fingerprint;
    std::vector<unsigned char> g_a;
};

struct tgl_message_action_commit_key: public tgl_message_action {
    tgl_message_action_commit_key(): exchange_id(0), key_fingerprint(0) { }
    tgl_message_action_commit_key(int64_t exchange_id, int64_t key_fingerprint): exchange_id(exchange_id), key_fingerprint(key_fingerprint) { }
    virtual tgl_message_action_type type() override { return tgl_message_action_type_commit_key; }
    int64_t exchange_id;
    int64_t key_fingerprint;
};

struct tgl_message_action_abort_key: public tgl_message_action {
    tgl_message_action_abort_key(): exchange_id(0) { }
    explicit tgl_message_action_abort_key(int64_t exchange_id): exchange_id(exchange_id) { }
    virtual tgl_message_action_type type() override { return tgl_message_action_type_abort_key; }
    int64_t exchange_id;
};

struct tgl_message_action_read_messages: public tgl_message_action {
    tgl_message_action_read_messages(): read_count(0) { }
    explicit tgl_message_action_read_messages(int32_t count): read_count(count) { }
    virtual tgl_message_action_type type() override { return tgl_message_action_type_read_messages; }
    int32_t read_count;
};

struct tgl_message_action_set_message_ttl: public tgl_message_action {
    tgl_message_action_set_message_ttl(): ttl(0) { }
    explicit tgl_message_action_set_message_ttl(int32_t ttl): ttl(ttl) { }
    virtual tgl_message_action_type type() override { return tgl_message_action_type_set_message_ttl; }
    int32_t ttl;
};

struct tgl_message_action_delete_messages: public tgl_message_action {
    virtual tgl_message_action_type type() override { return tgl_message_action_type_delete_messages; }
};

struct tgl_message_action_flush_history: public tgl_message_action {
    virtual tgl_message_action_type type() override { return tgl_message_action_type_flush_history; }
};

struct tgl_message_action_none: public tgl_message_action {
    virtual tgl_message_action_type type() override { return tgl_message_action_type_none; }
};

#endif
