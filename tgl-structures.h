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

std::shared_ptr<tgl_message> tglm_message_create(tgl_message_id_t *id, tgl_peer_id_t *from_id,
                                        tgl_peer_id_t *to_id, tgl_peer_id_t *fwd_from_id, int *fwd_date,
                                        int *date, const char *message,
                                        const tl_ds_message_media *media, const tl_ds_message_action *action,
                                        int *reply_id, struct tl_ds_reply_markup *reply_markup, int flags);

std::shared_ptr<tgl_message> tglm_create_encr_message(tgl_message_id* id,
        const tgl_peer_id_t* from_id,
        const tgl_peer_id_t* to_id,
        const int* date,
        const char* message,
        int message_len,
        const tl_ds_decrypted_message_media* media,
        const tl_ds_decrypted_message_action* action,
        const tl_ds_encrypted_file* file,
        int flags);

std::shared_ptr<tgl_secret_message> tglf_fetch_encrypted_message(const tl_ds_encrypted_message*);
void tglf_encrypted_message_received(const std::shared_ptr<tgl_secret_message>& secret_message);

std::shared_ptr<tgl_message> tglm_message_alloc(const tgl_message_id_t* id);

//void tglm_message_insert_tree (struct tgl_message *M);
void tglm_update_message_id (struct tgl_message *M, long long id);
#if 0
void tglm_message_insert (struct tgl_message *M);
void tglm_message_insert_unsent (struct tgl_message *M);
void tglm_message_remove_unsent (struct tgl_message *M);
#endif
void tglm_send_all_unsent ();
#if 0
void tglm_message_remove_tree (struct tgl_message *M);
void tglm_message_add_peer (struct tgl_message *M);
void tglm_message_del_peer (struct tgl_message *M);
void tglm_message_del_temp_id (struct tgl_message *M);
void tglm_message_del_random_id (struct tgl_message *M);
#endif

//enum tgl_typing_status tglf_fetch_typing_buf (void);
//void tgls_messages_mark_read (struct tgl_message *M, int out, int seq);

//void tgls_insert_random2local (long long random_id, tgl_message_id_t *local_id);
//void tgls_insert_temp2local (int temp_id, tgl_message_id_t *local_id);
tgl_message_id_t *tgls_get_local_by_random (long long random_id);
tgl_message_id_t *tgls_get_local_by_temp (int temp_id);


void tgls_message_change_temp_id (struct tgl_message *M, int temp_id);
void tgls_message_change_random_id (struct tgl_message *M, long long random_id);

tgl_message_id_t tgl_convert_temp_msg_id (tgl_message_id_t msg_id);

static inline tgl_peer_id_t tgl_msg_id_to_peer_id (tgl_message_id_t msg_id) {
  tgl_peer_id_t id;
  id.peer_type = msg_id.peer_type;
  id.peer_id = msg_id.peer_id;
  id.access_hash = msg_id.access_hash;
  return id;
}

static inline tgl_message_id_t tgl_peer_id_to_msg_id (tgl_peer_id_t peer_id, long long msg_id) {
  tgl_message_id_t id;
  id.peer_type = peer_id.peer_type;
  id.peer_id = peer_id.peer_id;
  id.access_hash = peer_id.access_hash;
  id.id = msg_id;
  return id;
}

static inline tgl_message_id_t tgl_peer_id_to_random_msg_id (tgl_peer_id_t peer_id) {
  long long id;
  tglt_secure_random ((unsigned char*)&id, 8);
  return tgl_peer_id_to_msg_id (peer_id, id);
}

#endif
