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
*/
#ifndef __STRUCTURES_H__
#define __STRUCTURES_H__

#include <assert.h>
#include "tgl-layout.h"
#include "tgl-fetch.h"
#include "tgl.h"
#include "tools.h"

void tgls_free_bot_info (struct tgl_bot_info *B);

std::shared_ptr<tgl_message> tglm_message_create(int64_t message_id, const tgl_peer_id_t& from_id,
                                        const tgl_input_peer_t& to_id, tgl_peer_id_t *fwd_from_id, int *fwd_date,
                                        int *date, const std::string& message,
                                        const tl_ds_message_media *media, const tl_ds_message_action *action,
                                        int reply_id, struct tl_ds_reply_markup *reply_markup, int flags);

std::shared_ptr<tgl_message> tglm_create_encr_message(const std::shared_ptr<tgl_secret_chat>& secret_chat,
        int64_t message_id,
        const tgl_peer_id_t& from_id,
        const tgl_input_peer_t& to_id,
        const int* date,
        const std::string& message,
        const tl_ds_decrypted_message_media* media,
        const tl_ds_decrypted_message_action* action,
        const tl_ds_encrypted_file* file,
        int flags);

std::shared_ptr<tgl_secret_message> tglf_fetch_encrypted_message(const tl_ds_encrypted_message*);
void tglf_encrypted_message_received(const std::shared_ptr<tgl_secret_message>& secret_message);

std::shared_ptr<tgl_message> tglm_message_alloc(int64_t message_id);

#endif
