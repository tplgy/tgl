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
#ifndef __STRUCTURES_H__
#define __STRUCTURES_H__

#include <assert.h>

#include "auto/auto-types.h"
#include "tools.h"
#include "tgl/tgl_bot.h"
#include "tgl/tgl_chat.h"
#include "tgl/tgl_channel.h"
#include "tgl/tgl_user.h"
#include "tgl/tgl_message.h"
#include "tgl/tgl_message_media.h"

class user_agent;

std::shared_ptr<tgl_user> tglf_fetch_alloc_user(user_agent* ua, const tl_ds_user* DS_U, bool invoke_callbacks = true);
std::shared_ptr<tgl_user> tglf_fetch_alloc_user_full(user_agent* ua, const tl_ds_user_full* DS_U);
std::shared_ptr<tgl_chat> tglf_fetch_alloc_chat(user_agent* ua, const tl_ds_chat* DS_C, bool invoke_callbacks = true);
std::shared_ptr<tgl_chat> tglf_fetch_alloc_chat_full(user_agent* ua, const tl_ds_messages_chat_full* DS_MCF);
std::shared_ptr<tgl_channel> tglf_fetch_alloc_channel(user_agent* ua, const tl_ds_chat* DS_C, bool invoke_callbacks = true);
std::shared_ptr<tgl_channel> tglf_fetch_alloc_channel_full(user_agent* ua, const tl_ds_messages_chat_full* DS_MCF);
std::shared_ptr<tgl_secret_chat> tglf_fetch_alloc_encrypted_chat(user_agent* ua, const tl_ds_encrypted_chat* DS_EC);
std::shared_ptr<tgl_message> tglf_fetch_alloc_message(user_agent* ua, const tl_ds_message* DS_M);
tgl_peer_id_t tglf_fetch_peer_id(const tl_ds_peer* DS_P);

std::shared_ptr<tgl_message_media> tglf_fetch_message_media(const tl_ds_message_media* DS_MM);
std::shared_ptr<tgl_message_action> tglf_fetch_message_action(const tl_ds_message_action* DS_MA);

void tglf_fetch_encrypted_message_file(const std::shared_ptr<tgl_message_media>& M, const tl_ds_encrypted_file* DS_EF);
std::shared_ptr<tgl_message_media> tglf_fetch_message_media_encrypted(const tl_ds_decrypted_message_media* DS_DMM);
std::shared_ptr<tgl_message_action> tglf_fetch_message_action_encrypted(const tl_ds_decrypted_message_action* DS_DMA);

tgl_user_status tglf_fetch_user_status(const tl_ds_user_status* DS_US);
enum tgl_typing_status tglf_fetch_typing(const tl_ds_send_message_action* DS_SMA);
void tglf_fetch_chat_participants(const std::shared_ptr<tgl_chat>& C, const tl_ds_chat_participants* DS_CP);

tgl_file_location tglf_fetch_file_location(const tl_ds_file_location* DS_FL);

void tglf_fetch_message_short(const std::shared_ptr<tgl_message>& M, const tl_ds_updates* DS_U);
void tglf_fetch_message_short_chat(const std::shared_ptr<tgl_message>& M, const tl_ds_updates* DS_U);

std::shared_ptr<tgl_message> tglf_fetch_alloc_message_short(user_agent* ua, const tl_ds_updates* DS_U);
std::shared_ptr<tgl_message> tglf_fetch_alloc_message_short_chat(const tl_ds_updates* DS_U);
std::shared_ptr<tgl_photo> tglf_fetch_alloc_photo(const tl_ds_photo* DS_P);
std::shared_ptr<tgl_webpage> tglf_fetch_alloc_webpage(const tl_ds_web_page* DS_W);
std::shared_ptr<tgl_bot_info> tglf_fetch_alloc_bot_info(const tl_ds_bot_info* DS_BI);
std::shared_ptr<tgl_message_reply_markup> tglf_fetch_alloc_reply_markup(const tl_ds_reply_markup* DS_RM);
void tglf_fetch_message_entities(const std::shared_ptr<tgl_message>& M, const tl_ds_vector* DS);

#endif
