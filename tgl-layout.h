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

    Copyright Vitaly Valtman 2014-2015
*/
#ifndef __TGL_LAYOUT_H__
#define __TGL_LAYOUT_H__

#include <array>
#include <list>
#include <memory>
#include <string>
#include <vector>
#include "types/tgl_file_location.h"
#include "types/tgl_peer_id.h"

#define TGLDF_IMAGE 1
#define TGLDF_STICKER 2
#define TGLDF_ANIMATED 4
#define TGLDF_AUDIO 8
#define TGLDF_VIDEO 16

#define TGLMF_UNREAD 1
#define TGLMF_OUT 2
#define TGLMF_DISABLE_PREVIEW 4
#define TGLMF_MENTION 16
#define TGLMF_CREATED (1 << 8)
#define TGLMF_PENDING (1 << 9)
#define TGLMF_DELETED (1 << 10)
#define TGLMF_ENCRYPTED (1 << 11)
#define TGLMF_EMPTY (1 << 12)
#define TGLMF_SERVICE (1 << 13)
#define TGLMF_SESSION_OUTBOUND (1 << 14)
#define TGLMF_TEMP_MSG_ID (1 << 15)
#define TGLMF_POST_AS_CHANNEL (1 << 8)
#define TGLMF_HTML (1 << 9)

#define TGLMF_CREATE 0x10000


#define TGLPF_CREATED (1 << 0)
#define TGLPF_CREATE 0x80000000
#define TGLPF_HAS_PHOTO (1 << 1)
#define TGLPF_DELETED (1 << 2)
#define TGLPF_OFFICIAL (1 << 3)
#define TGLPF_KICKED (1 << 4)
#define TGLPF_ADMIN (1 << 5)
#define TGLPF_CREATOR (1 << 6)
#define TGLPF_LEFT (1 << 7)
#define TGLPF_DEACTIVATED (1 << 8)

#define TGLUF_CONTACT (1 << 16)
#define TGLUF_MUTUAL_CONTACT (1 << 17)
#define TGLUF_BLOCKED (1 << 18)
#define TGLUF_SELF (1 << 19)
#define TGLUF_CREATED TGLPF_CREATED
#define TGLUF_DELETED TGLPF_DELETED
#define TGLUF_HAS_PHOTO TGLPF_HAS_PHOTO
#define TGLUF_CREATE TGLPF_CREATE
#define TGLUF_BOT (1 << 20)
#define TGLUF_OFFICIAL TGLPF_OFFICIAL

#define TGLUF_TYPE_MASK \
  (TGLUF_CONTACT | TGLUF_MUTUAL_CONTACT | TGLUF_BLOCKED | TGLUF_SELF | TGLUF_CREATED | TGLUF_DELETED | TGLUF_OFFICIAL)

#define TGLCF_CREATED TGLPF_CREATED
#define TGLCF_CREATE TGLPF_CREATE
#define TGLCF_HAS_PHOTO TGLPF_HAS_PHOTO
#define TGLCF_KICKED TGLPF_KICKED
#define TGLCF_CREATOR TGLPF_CREATOR
#define TGLCF_ADMIN TGLPF_ADMIN
#define TGLCF_OFFICIAL TGLPF_OFFICIAL
#define TGLCF_LEFT TGLPF_LEFT
#define TGLCF_DEACTIVATED TGLPF_DEACTIVATED
#define TGLCF_ADMINS_ENABLED (1 << 16)

#define TGLCF_TYPE_MASK \
  (TGLCF_CREATED | TGLCF_KICKED | TGLCF_CREATOR | TGLCF_ADMIN | TGLCF_OFFICIAL | TGLCF_LEFT | TGLCF_DEACTIVATED | TGLCF_ADMINS_ENABLED)

#define TGLECF_CREATED TGLPF_CREATED
#define TGLECF_CREATE TGLPF_CREATE
#define TGLECF_HAS_PHOTO TGLPF_HAS_PHOTO
#define TGLECF_KICKED TGLPF_KICKED
#define TGLECF_CREATOR TGLPF_CREATOR
#define TGLECF_ADMIN TGLPF_ADMIN

#define TGLECF_TYPE_MASK \
  (TGLECF_CREATED | TGLECF_KICKED | TGLECF_CREATOR | TGLECF_ADMIN)

#define TGLCHF_CREATED TGLPF_CREATED
#define TGLCHF_CREATE TGLPF_CREATE
#define TGLCHF_HAS_PHOTO TGLPF_HAS_PHOTO
#define TGLCHF_KICKED TGLPF_KICKED
#define TGLCHF_CREATOR TGLPF_CREATOR
#define TGLCHF_ADMIN TGLPF_ADMIN
#define TGLCHF_OFFICIAL TGLPF_OFFICIAL
#define TGLCHF_LEFT TGLPF_LEFT
#define TGLCHF_DEACTIVATED TGLPF_DEACTIVATED
#define TGLCHF_BROADCAST (1 << 16)
#define TGLCHF_EDITOR (1 << 17)
#define TGLCHF_MODERATOR (1 << 18)
#define TGLCHF_MEGAGROUP (1 << 19)

#define TGLCHF_TYPE_MASK \
  (TGLCHF_CREATED | TGLCHF_KICKED | TGLCHF_CREATOR | TGLCHF_ADMIN | TGLCHF_OFFICIAL | TGLCHF_LEFT | TGLCHF_DEACTIVATED | TGLCHF_BROADCAST | TGLCHF_EDITOR | TGLCHF_MODERATOR | TGLCHF_MEGAGROUP)


#define TGLCHF_DIFF 0x20000000

#define TGL_FLAGS_UNCHANGED 0x40000000

#define TGL_PERMANENT_ID_SIZE 24
#pragma pack(push,4)

struct tgl_dc;
class tgl_connection;
class tgl_timer;

enum tgl_message_entity_type {
    tgl_message_entity_unknown,
    tgl_message_entity_mention,
    tgl_message_entity_hashtag,
    tgl_message_entity_bot_command,
    tgl_message_entity_url,
    tgl_message_entity_email,
    tgl_message_entity_bold,
    tgl_message_entity_italic,
    tgl_message_entity_code,
    tgl_message_entity_pre,
    tgl_message_entity_text_url
};

struct tgl_message_entity {
    enum tgl_message_entity_type type;
    int start;
    int length;
    std::string text_url;
    tgl_message_entity()
        : type(tgl_message_entity_unknown)
        , start(0)
        , length(0)
    { }
};

enum tgl_message_media_type {
    tgl_message_media_type_none,
    tgl_message_media_type_photo,
    tgl_message_media_type_document,
    tgl_message_media_type_geo,
    tgl_message_media_type_contact,
    tgl_message_media_type_unsupported,
    //tgl_message_media_type_photo_encr,
    //tgl_message_media_type_video_encr,
    //tgl_message_media_type_audio_encr,
    tgl_message_media_type_document_encr,
    tgl_message_media_type_webpage,
    tgl_message_media_type_venue,
    tgl_message_media_type_video,
    tgl_message_media_type_audio
};

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

enum tgl_typing_status {
    tgl_typing_none,
    tgl_typing_typing,
    tgl_typing_cancel,
    tgl_typing_record_video,
    tgl_typing_upload_video,
    tgl_typing_record_audio,
    tgl_typing_upload_audio,
    tgl_typing_upload_photo,
    tgl_typing_upload_document,
    tgl_typing_geo,
    tgl_typing_choose_contact
};

struct tgl_photo_size {
    std::string type;
    struct tgl_file_location loc;
    int w;
    int h;
    int size;
    //char *data;
    //std::vector<char> data;
    tgl_photo_size()
        : w(0)
        , h(0)
        , size(0)
    { }
};

struct tgl_geo {
    double longitude;
    double latitude;
    tgl_geo(): longitude(0), latitude(0) { }
};

struct tgl_photo {
    long long id;
    long long access_hash;
    //int user_id;
    int date;
    std::string caption;
    //struct tgl_geo geo;
    std::vector<std::shared_ptr<tgl_photo_size>> sizes;
    tgl_photo()
        : id(0)
        , access_hash(0)
        , date(0)
    { }
};

struct tgl_document {
    long long id;
    long long access_hash;
    //int user_id;
    int date;
    int size;
    int dc_id;
    std::shared_ptr<tgl_photo_size> thumb;
    std::string caption;
    std::string mime_type;

    int w;
    int h;
    int flags;
    int duration;

    tgl_document()
        : id(0)
        , access_hash(0)
        , date(0)
        , size(0)
        , dc_id(0)
        , w(0)
        , h(0)
        , flags(0)
        , duration(0)
    { }
};

struct tgl_encr_document: public tgl_document {
    std::vector<unsigned char> key;
    std::vector<unsigned char> iv;
    int key_fingerprint;
    tgl_encr_document() : key_fingerprint(0) { }
};

struct tgl_message_action {
    virtual tgl_message_action_type type() = 0;
    virtual ~tgl_message_action() { }
};

struct tgl_message_action_chat_create: public tgl_message_action {
    virtual tgl_message_action_type type() override { return tgl_message_action_type_chat_create; }
    std::string title;
    std::vector<int> users;
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
    std::vector<int> users;
};

struct tgl_message_action_chat_delete_user: public tgl_message_action {
    tgl_message_action_chat_delete_user(): user_id(0) { }
    explicit tgl_message_action_chat_delete_user(int user_id): user_id(user_id) { }
    virtual tgl_message_action_type type() override { return tgl_message_action_type_chat_delete_user; }
    int user_id;
};

struct tgl_message_action_chat_add_user_by_link: public tgl_message_action {
    tgl_message_action_chat_add_user_by_link(): inviter_id(0) { }
    explicit tgl_message_action_chat_add_user_by_link(int inviter_id): inviter_id(inviter_id) { }
    virtual tgl_message_action_type type() override { return tgl_message_action_type_chat_add_user_by_link; }
    int inviter_id;
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
    explicit tgl_message_action_screenshot_messages(int count): screenshot_count(count) { }
    virtual tgl_message_action_type type() override { return tgl_message_action_type_screenshot_messages; }
    int screenshot_count;
};

struct tgl_message_action_notify_layer: public tgl_message_action {
    tgl_message_action_notify_layer(): layer(0) { }
    explicit tgl_message_action_notify_layer(int l): layer(l) { }
    virtual tgl_message_action_type type() override { return tgl_message_action_type_notify_layer; }
    int layer;
};

struct tgl_message_action_typing: public tgl_message_action {
    tgl_message_action_typing(): typing_status(tgl_typing_none) { }
    explicit tgl_message_action_typing(tgl_typing_status status): typing_status(status) { }
    virtual tgl_message_action_type type() override { return tgl_message_action_type_typing; }
    tgl_typing_status typing_status;
};

struct tgl_message_action_resend: public tgl_message_action {
    tgl_message_action_resend(): start_seq_no(-1), end_seq_no(-1) { }
    tgl_message_action_resend(int start, int end): start_seq_no(start), end_seq_no(end) { }
    virtual tgl_message_action_type type() override { return tgl_message_action_type_resend; }
    int start_seq_no;
    int end_seq_no;
};

struct tgl_message_action_noop: public tgl_message_action {
    virtual tgl_message_action_type type() override { return tgl_message_action_type_noop; }
};

struct tgl_message_action_request_key: public tgl_message_action {
    tgl_message_action_request_key(): exchange_id(0) { }
    virtual tgl_message_action_type type() override { return tgl_message_action_type_request_key; }
    long long exchange_id;
    std::vector<unsigned char> g_a;
};

struct tgl_message_action_accept_key: public tgl_message_action {
    tgl_message_action_accept_key(): exchange_id(0), key_fingerprint(0) { }
    virtual tgl_message_action_type type() override { return tgl_message_action_type_accept_key; }
    long long exchange_id;
    long long key_fingerprint;
    std::vector<unsigned char> g_a;
};

struct tgl_message_action_commit_key: public tgl_message_action {
    tgl_message_action_commit_key(): exchange_id(0), key_fingerprint(0) { }
    tgl_message_action_commit_key(long long exchange_id, long long key_fingerprint): exchange_id(exchange_id), key_fingerprint(key_fingerprint) { }
    virtual tgl_message_action_type type() override { return tgl_message_action_type_commit_key; }
    long long exchange_id;
    long long key_fingerprint;
};

struct tgl_message_action_abort_key: public tgl_message_action {
    tgl_message_action_abort_key(): exchange_id(0) { }
    explicit tgl_message_action_abort_key(long long exchange_id): exchange_id(exchange_id) { }
    virtual tgl_message_action_type type() override { return tgl_message_action_type_abort_key; }
    long long exchange_id;
};

struct tgl_message_action_read_messages: public tgl_message_action {
    tgl_message_action_read_messages(): read_count(0) { }
    explicit tgl_message_action_read_messages(int count): read_count(count) { }
    virtual tgl_message_action_type type() override { return tgl_message_action_type_read_messages; }
    int read_count;
};

struct tgl_message_action_set_message_ttl: public tgl_message_action {
    tgl_message_action_set_message_ttl(): ttl(0) { }
    explicit tgl_message_action_set_message_ttl(int ttl): ttl(ttl) { }
    virtual tgl_message_action_type type() override { return tgl_message_action_type_set_message_ttl; }
    int ttl;
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

struct tgl_webpage {
    long long id;
    std::string url;
    std::string display_url;
    std::string type;
    std::string site_name;
    std::string title;
    std::string description;
    std::shared_ptr<tgl_photo> photo;
    std::string embed_url;
    std::string embed_type;
    std::string author;
    int embed_width;
    int embed_height;
    int duration;
    tgl_webpage()
        : id(0)
        , embed_width(0)
        , embed_height(0)
        , duration(0)
    { }
};

struct tgl_message_media {
    virtual tgl_message_media_type type() = 0;
    virtual ~tgl_message_media() { }
};

struct tgl_message_media_none: public tgl_message_media {
    virtual tgl_message_media_type type() override { return tgl_message_media_type_none; }
};

struct tgl_message_media_photo: public tgl_message_media {
    virtual tgl_message_media_type type() override { return tgl_message_media_type_photo; }
    std::shared_ptr<tgl_photo> photo;
    std::string caption;
};

struct tgl_message_media_document: public tgl_message_media {
    virtual tgl_message_media_type type() override { return tgl_message_media_type_document; }
    std::shared_ptr<tgl_document> document;
    std::string caption;
};

struct tgl_message_media_geo: public tgl_message_media {
    virtual tgl_message_media_type type() override { return tgl_message_media_type_geo; }
    tgl_geo geo;
};

struct tgl_message_media_contact: public tgl_message_media {
    tgl_message_media_contact(): user_id(0) { }
    virtual tgl_message_media_type type() override { return tgl_message_media_type_contact; }
    std::string phone;
    std::string first_name;
    std::string last_name;
    int user_id;
};

struct tgl_message_media_unsupported: public tgl_message_media {
    virtual tgl_message_media_type type() override { return tgl_message_media_type_unsupported; }
};

struct tgl_message_media_document_encr: public tgl_message_media {
    virtual tgl_message_media_type type() override { return tgl_message_media_type_document_encr; }
    std::shared_ptr<tgl_encr_document> encr_document;
};

struct tgl_message_media_webpage: public tgl_message_media {
    virtual tgl_message_media_type type() override { return tgl_message_media_type_webpage; }
    std::shared_ptr<tgl_webpage> webpage;
};

struct tgl_message_media_venue: public tgl_message_media {
    virtual tgl_message_media_type type() override { return tgl_message_media_type_venue; }
    struct tgl_geo geo;
    std::string title;
    std::string address;
    std::string provider;
    std::string venue_id;
};

struct tgl_message_media_video: public tgl_message_media {
    virtual tgl_message_media_type type() override { return tgl_message_media_type_video; }
    std::shared_ptr<tgl_document> document;
    std::string caption;
};

struct tgl_message_media_audio: public tgl_message_media {
    virtual tgl_message_media_type type() override { return tgl_message_media_type_audio; }
    std::shared_ptr<tgl_document> document;
    std::string caption;
};

struct tgl_message_reply_markup {
  int flags;
  std::vector<std::vector<std::string>> button_matrix;
  tgl_message_reply_markup(): flags(0) { }
};

typedef struct tgl_message_id {
    unsigned peer_type;
    unsigned peer_id;
    long long id;
    long long access_hash;
} tgl_message_id_t;

struct tgl_message {
    long long server_id;
    long long random_id;
    struct tgl_message_id permanent_id;
    int flags;
    tgl_peer_id_t fwd_from_id;
    int fwd_date;
    int reply_id;
    tgl_peer_id_t from_id;
    tgl_peer_id_t to_id;
    int date;
    std::vector<std::shared_ptr<tgl_message_entity>> entities;
    std::shared_ptr<tgl_message_reply_markup> reply_markup;
    std::shared_ptr<tgl_message_action> action;
    std::shared_ptr<tgl_message_media> media;
    std::string message;
    tgl_message()
        : server_id(0)
        , random_id(0)
        , permanent_id({0, 0, 0, 0})
        , flags(0)
        , fwd_from_id({0, 0, 0})
        , fwd_date(0)
        , reply_id(0)
        , from_id({0, 0, 0})
        , to_id({0, 0, 0})
        , date(0)
        , action(std::make_shared<tgl_message_action_none>())
        , media(std::make_shared<tgl_message_media_none>())
    { }
};

#pragma pack(pop)
#endif
