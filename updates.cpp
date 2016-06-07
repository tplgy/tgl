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
#include "tgl.h"
#include "updates.h"
#include "auto/auto.h"
#include "auto/auto-types.h"
#include "auto/auto-fetch-ds.h"
#include "auto/auto-free-ds.h"
#include "mtproto-common.h"
#include "queries-encrypted.h"
#include "tgl-log.h"
#include "tgl-structures.h"
#include "tgl-methods-in.h"
#include "tgl-timer-asio.h"
#include "types/tgl_update_callback.h"
#include "types/tgl_secret_chat.h"

#include <assert.h>

static void fetch_dc_option (struct tl_ds_dc_option *DS_DO) {
  TGL_DEBUG("id = " << DS_LVAL (DS_DO->id) << ", ip = " << std::string(DS_DO->ip_address->data, DS_DO->ip_address->len) << ", port = " << DS_LVAL (DS_DO->port));

  //bl_do_dc_option (TLS, DS_LVAL (DS_DO->flags), DS_LVAL (DS_DO->id), NULL, 0, DS_STR (DS_DO->ip_address), DS_LVAL (DS_DO->port));
  tgl_state::instance()->set_dc_option (0, DS_LVAL (DS_DO->id), std::string(DS_DO->ip_address->data, DS_DO->ip_address->len), DS_LVAL (DS_DO->port));
}

int tgl_check_pts_diff (int pts, int pts_count) {
    TGL_DEBUG("pts = " << pts << ", pts_count = " << pts_count);
    if (!tgl_state::instance()->pts()) {
        return 1;
    }
    //assert (TLS->pts);
    if (pts < tgl_state::instance()->pts() + pts_count) {
        TGL_NOTICE("Duplicate message with pts=" << pts);
        return -1;
    }
    if (pts > tgl_state::instance()->pts() + pts_count) {
        TGL_NOTICE("Hole in pts: pts = "<< pts <<", count = "<< pts_count <<", cur_pts = "<< tgl_state::instance()->pts());
        tgl_do_get_difference(0, 0);
        return -1;
    }
    if (tgl_state::instance()->locks & TGL_LOCK_DIFF) {
        TGL_DEBUG("Update during get_difference. pts = " << pts);
        return -1;
    }
    TGL_DEBUG("Ok update. pts = " << pts);
    return 1;
}

int tgl_check_qts_diff (int qts, int qts_count) {
    TGL_NOTICE("qts = " << qts << ", qts_count = " << qts_count);
    if (qts < tgl_state::instance()->qts() + qts_count) {
        TGL_NOTICE("Duplicate message with qts=" << qts);
        return -1;
    }
    if (qts > tgl_state::instance()->qts() + qts_count) {
        TGL_NOTICE("Hole in qts (qts = " << qts << ", count = " << qts_count << ", cur_qts = " << tgl_state::instance()->qts() << ")");
        tgl_do_get_difference (0, 0);
        return -1;
    }
    if (tgl_state::instance()->locks & TGL_LOCK_DIFF) {
        TGL_DEBUG("Update during get_difference. qts = " << qts);
        return -1;
    }
    TGL_DEBUG("Ok update. qts = " << qts);
    return 1;
}

int tgl_check_channel_pts_diff (tgl_peer_id_t channel_id, int pts, int pts_count) {
    // TODO: remember channel pts
#if 0
  TGL_DEBUG("channel " << tgl_get_peer_id (channel_id) << ": pts = " << pts << ", pts_count = " << pts_count << ", current_pts = " << E->pts);
  if (!E->pts) {
    return 1;
  }
  //assert (tgl_state::instance()->pts);
  if (pts < E->pts + pts_count) {
    TGL_NOTICE("Duplicate message with pts=" << pts);
    return -1;
  }
  if (pts > E->pts + pts_count) {
    TGL_NOTICE("Hole in pts (pts = " << pts << ", count = " << pts_count << ", cur_pts = " << E->pts);
    tgl_do_get_channel_difference (tgl_get_peer_id (channel_id), 0, 0);
    return -1;
  }
  if (E->flags & TGLCHF_DIFF) {
    TGL_DEBUG("Update during get_difference. pts = " << pts);
    return -1;
  }
  TGL_DEBUG("Ok update. pts = " << pts);
#endif
  return 1;
}

static int do_skip_seq (int seq) {
    if (!seq) {
        TGL_DEBUG("Ok update. seq = " << seq);
        return 0;
    }
    if (tgl_state::instance()->seq()) {
        if (seq <= tgl_state::instance()->seq()) {
            TGL_NOTICE("Duplicate message with seq=" << seq);
            return -1;
        }
        if (seq > tgl_state::instance()->seq() + 1) {
            TGL_NOTICE("Hole in seq (seq = " << seq <<", cur_seq = " << tgl_state::instance()->seq() << ")");
            //vlogprintf (E_NOTICE, "lock_diff = %s", (TLS->locks & TGL_LOCK_DIFF) ? "true" : "false");
            tgl_do_get_difference (0, 0);
            return -1;
        }
        if (tgl_state::instance()->locks & TGL_LOCK_DIFF) {
            TGL_DEBUG("Update during get_difference. seq = " << seq);
            return -1;
        }
        TGL_DEBUG("Ok update. seq = " << seq);
        return 0;
    } else {
        return -1;
    }
}

void tglu_work_update (int check_only, struct tl_ds_update *DS_U, std::shared_ptr<void> extra) {
  if (check_only > 0 || (tgl_state::instance()->locks & TGL_LOCK_DIFF)) {
    TGL_DEBUG("Update during get_difference. DROP");
    return;
  }

  if (DS_U->pts) {
    assert (DS_U->pts_count);

    if (!check_only && tgl_check_pts_diff(DS_LVAL (DS_U->pts), DS_LVAL (DS_U->pts_count)) <= 0) {
      return;
    }
  }

  if (DS_U->qts) {
    if (!check_only && tgl_check_qts_diff(DS_LVAL (DS_U->qts), 1) <= 0) {
      return;
    }
  }

  if (DS_U->channel_pts) {
    assert (DS_U->channel_pts_count);
    int channel_id;
    if (DS_U->channel_id) {
      channel_id = DS_LVAL (DS_U->channel_id);
    } else {
      assert (DS_U->message);
      if (!DS_U->message->to_id) {
        return;
      }
      assert (DS_U->message->to_id);
      assert (DS_U->message->to_id->magic == CODE_peer_channel);
      channel_id = DS_LVAL (DS_U->message->to_id->channel_id);
    }    

    tgl_peer_id_t E = tgl_peer_id_channel (channel_id);

    if (!check_only && tgl_check_channel_pts_diff (E, DS_LVAL (DS_U->channel_pts), DS_LVAL (DS_U->channel_pts_count)) <= 0) {
      return;
    }
  }

  if (check_only > 0 && DS_U->magic != CODE_update_message_i_d) { return; }
  switch (DS_U->magic) {
  case CODE_update_new_message:
    {
      std::shared_ptr<tgl_message> M = tglf_fetch_alloc_message (DS_U->message);
      tgl_state::instance()->callback()->new_messages({M});
      break;
    };
  case CODE_update_message_i_d:
    {
      auto message = std::static_pointer_cast<tgl_message>(extra);
      if (message) {
          tgl_state::instance()->callback()->message_sent(message, DS_LVAL(DS_U->id), -1);
      }
#if 0 // FIXME
      tgl_message_id_t msg_id;
      msg_id.peer_type = TGL_PEER_RANDOM_ID;
      msg_id.id = DS_LVAL (DS_U->random_id);
      //struct tgl_message *M = tgl_message_get (&msg_id);
      //if (M && (M->flags & TGLMF_PENDING)) {
        //msg_id = M->permanent_id;
        //msg_id.id = DS_LVAL (DS_U->id);
        //bl_do_set_msg_id (&M->permanent_id, &msg_id);
        //bl_do_msg_update (&msg_id);
        //TODO update the id of the message
      //}
#endif
    }
    break;
  case CODE_update_user_typing:
    {
      //tgl_peer_id_t id = tgl_peer_id_user (DS_LVAL (DS_U->user_id));
      //tgl_peer_t *U = tgl_peer_get (id);
      enum tgl_typing_status status = tglf_fetch_typing (DS_U->action);

      tgl_state::instance()->callback()->typing_status_changed(DS_LVAL(DS_U->user_id), DS_LVAL(DS_U->user_id), tgl_peer_type::user, status);
    }
    break;
  case CODE_update_chat_user_typing:
    {
      tgl_peer_id_t chat_id = tgl_peer_id_chat (DS_LVAL (DS_U->chat_id));
      tgl_peer_id_t id = tgl_peer_id_user (DS_LVAL (DS_U->user_id));
      enum tgl_typing_status status = tglf_fetch_typing (DS_U->action);

      tgl_state::instance()->callback()->typing_status_changed(id.peer_id, chat_id.peer_id, tgl_peer_type::chat, status);
    }
    break;
  case CODE_update_user_status:
    {
      tgl_user_status status = tglf_fetch_user_status(DS_U->status);
      tgl_state::instance()->callback()->status_notification(DS_LVAL (DS_U->user_id), status);
    }
    break;
  case CODE_update_user_name:
    {
      tgl_peer_id_t user_id = tgl_peer_id_user (DS_LVAL (DS_U->user_id));
      DS_CSTR (firstname, DS_U->first_name);
      DS_CSTR (lastname, DS_U->last_name);
      DS_CSTR (username, DS_U->username);

      //TODO make that one call with a map or vector of changes
      tgl_state::instance()->callback()->user_update(user_id.peer_id, username, tgl_update_username);
      tgl_state::instance()->callback()->user_update(user_id.peer_id, username, tgl_update_firstname);
      tgl_state::instance()->callback()->user_update(user_id.peer_id, username, tgl_update_last_name);
      free(firstname);
      free(lastname);
      free(username);
      break;
    }
  case CODE_update_user_photo:
    {
      if (DS_U->photo) {
        tgl_file_location photo_big = tglf_fetch_file_location(DS_U->photo->photo_big);
        tgl_file_location photo_small = tglf_fetch_file_location(DS_U->photo->photo_small);
        tgl_state::instance()->callback()->avatar_update(DS_LVAL (DS_U->user_id), tgl_peer_type::user, photo_small, photo_big);
      }
      break;
    }
    case CODE_update_delete_messages:
    {
        break;
    }
    case CODE_update_chat_participants:
    {
      tgl_peer_id_t chat_id = tgl_peer_id_chat (DS_LVAL (DS_U->chat_id));
      if (DS_U->participants->magic == CODE_chat_participants) {
        for (int i=0; i<*DS_U->participants->participants->cnt; ++i) {
          tgl_state::instance()->callback()->chat_add_user(chat_id.peer_id, *DS_U->participants->participants->data[i]->user_id,
              DS_U->participants->participants->data[i]->inviter_id ? *DS_U->participants->participants->data[i]->inviter_id : 0,
              DS_U->participants->participants->data[i]->date ? *DS_U->participants->participants->data[i]->date : 0);
        }
      }
      break;
    }
    case CODE_update_contact_registered:
    {
        tgl_state::instance()->callback()->user_registered(DS_LVAL (DS_U->user_id));
        break;
    }
    case CODE_update_contact_link:
    {
        break;
    }
    case CODE_update_new_authorization:
    {
        tgl_state::instance()->callback()->new_authorization(DS_U->device->data, DS_U->location->data);
    }
    break;
  /*case CODE_update_new_geo_chat_message:
    {
    }
    break;*/
  case CODE_update_new_encrypted_message:
    {
      auto message = tglf_fetch_encrypted_message(DS_U->encr_message);
      if (!message) {
          return;
      }
      tglf_encrypted_message_received(message);
    }
    break;
  case CODE_update_encryption:
    {
      std::shared_ptr<tgl_secret_chat> secret_chat = tglf_fetch_alloc_encrypted_chat (DS_U->encr_chat);
      if (!secret_chat) {
          break;
      }
      if (secret_chat->state == sc_ok) {
        tgl_do_send_encr_chat_layer(secret_chat);
      }
    }
    break;
  case CODE_update_encrypted_chat_typing:
    {
      tgl_state::instance()->callback()->typing_status_changed(DS_LVAL(DS_U->chat_id), DS_LVAL(DS_U->chat_id), tgl_peer_type::enc_chat, tgl_typing_status::tgl_typing_typing);
    }
    break;
  case CODE_update_encrypted_messages_read:
    {
#if 0
      tgl_peer_id_t id = tgl_peer_id_enc_chat (DS_LVAL (DS_U->chat_id));
      tgl_peer_t *P = tgl_peer_get (id);
      
      if (P && P->last) {
        struct tgl_message *M = P->last;
        while (M && (!(M->flags & TGLMF_OUT) || (M->flags & TGLMF_UNREAD))) {
          if (M->flags & TGLMF_OUT) {
            bl_do_edit_message_encr (tgl_state::instance(), &M->permanent_id, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, M->flags & ~TGLMF_UNREAD);
          }
          M = M->next;
        }
      }
#endif
    }
    break;
  case CODE_update_chat_participant_add:
    {
      tgl_peer_id_t chat_id = tgl_peer_id_chat (DS_LVAL (DS_U->chat_id));
      tgl_peer_id_t user_id = tgl_peer_id_user (DS_LVAL (DS_U->user_id));
      tgl_peer_id_t inviter_id = tgl_peer_id_user (DS_LVAL (DS_U->inviter_id));
      //int version = DS_LVAL (DS_U->version); 

      //bl_do_chat_add_user (C->id, version, user_id.peer_id, inviter_id.peer_id, time (0));
      tgl_state::instance()->callback()->chat_add_user(chat_id.peer_id, user_id.peer_id, inviter_id.peer_id, time (0));
    }
    break;
  case CODE_update_chat_participant_delete:
    {
      tgl_peer_id_t chat_id = tgl_peer_id_chat (DS_LVAL (DS_U->chat_id));
      tgl_peer_id_t user_id = tgl_peer_id_user (DS_LVAL (DS_U->user_id));
      //int version = DS_LVAL (DS_U->version); 
      
      //bl_do_chat_del_user (C->id, version, user_id.peer_id);
      tgl_state::instance()->callback()->chat_delete_user(chat_id.peer_id, user_id.peer_id);
    }
    break;
  case CODE_update_dc_options:
    {
      int i;
      for (i = 0; i < DS_LVAL (DS_U->dc_options->cnt); i++) {
        fetch_dc_option (DS_U->dc_options->data[i]);
      }
    }
    break;
  case CODE_update_user_blocked:
    {
      int blocked = DS_BVAL (DS_U->blocked);
      tgl_peer_id_t peer_id = tgl_peer_id_user (DS_LVAL (DS_U->user_id));

      //bl_do_user (tgl_get_peer_id (peer_id), NULL, NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL, NULL, flags);
      tgl_state::instance()->callback()->user_update(peer_id.peer_id, &blocked, tgl_update_blocked);
    }
    break;
  case CODE_update_notify_settings:
    {
    }
    break;
  case CODE_update_service_notification:
    {
      TGL_ERROR("Notification " << std::string(DS_U->type->data, DS_U->type->len) << ":" << std::string(DS_U->message_text->data, DS_U->message_text->len));
      tgl_state::instance()->callback()->notification(DS_U->type->data, DS_U->message_text->data);
    }
    break;
  case CODE_update_privacy:
    TGL_NOTICE("privacy change update");
    break;
  case CODE_update_user_phone:
    {
      tgl_peer_id_t user_id = tgl_peer_id_user (DS_LVAL (DS_U->user_id));
      //bl_do_user (user_id.peer_id, NULL, NULL, 0, NULL, 0, DS_STR (DS_U->phone), NULL, 0, NULL, NULL, NULL, NULL, NULL, TGL_FLAGS_UNCHANGED);
      DS_CSTR (phone, DS_U->phone);
      tgl_state::instance()->callback()->user_update(user_id.peer_id, phone, tgl_update_phone);
    }
    break;
  case CODE_update_read_history_inbox:
    {
      tgl_peer_id_t id = tglf_fetch_peer_id (DS_U->peer);
      tgl_state::instance()->callback()->messages_mark_read_in(id, DS_LVAL(DS_U->max_id));
    }
    break;
  case CODE_update_read_history_outbox:
    {
      tgl_peer_id_t id = tglf_fetch_peer_id (DS_U->peer);
      tgl_state::instance()->callback()->messages_mark_read_out(id, DS_LVAL(DS_U->max_id));
    }
    break;
  case CODE_update_web_page:
    {
    }
    break;
  /*case CODE_update_msg_update:
    {
      struct tgl_message *M = tgl_message_get (DS_LVAL (DS_U->id));
      if (M) {
        //bl_do_msg_update (TLS, M->id);
        tgl_state::instance()->callback.new_msg(M);
      }
    }
    break;*/
  case CODE_update_read_messages_contents:
    break;
  case CODE_update_channel_too_long:
    {
      tgl_do_get_channel_difference (DS_LVAL (DS_U->channel_id), NULL);
    }
    break;
  case CODE_update_channel:
    break;
  case CODE_update_channel_group:
    break;
  case CODE_update_new_channel_message: {
    auto msg = tglf_fetch_alloc_message (DS_U->message);
    tgl_state::instance()->callback()->new_messages({msg});
    break;
  }
  case CODE_update_read_channel_inbox:
    break;
  case CODE_update_delete_channel_messages:
    break;
  case CODE_update_channel_message_views:
    break;
  case CODE_update_chat_admins:
    break;
  case CODE_update_chat_participant_admin:
    break;
  case CODE_update_new_sticker_set:
    break;
  case CODE_update_sticker_sets_order:
    break;
  case CODE_update_sticker_sets:
    break;
  case CODE_update_saved_gifs:
    break;
  case CODE_update_bot_inline_query:
    break;
  default:
    assert (0);
  }

  if (check_only) { return; }

  if (DS_U->pts) {
    assert (DS_U->pts_count);
    tgl_state::instance()->set_pts(DS_LVAL (DS_U->pts));
  }
  if (DS_U->qts) {
    tgl_state::instance()->set_qts(DS_LVAL (DS_U->qts));
  }
  if (DS_U->channel_pts) {
    assert (DS_U->channel_pts_count);
    
#if 0 // FIXME
    int channel_id;
    if (DS_U->channel_id) {
      channel_id = DS_LVAL (DS_U->channel_id);
    } else {
      assert (DS_U->message);
      assert (DS_U->message->to_id);
      assert (DS_U->message->to_id->magic == CODE_peer_channel);
      channel_id = DS_LVAL (DS_U->message->to_id->channel_id);
    }    

    bl_do_set_channel_pts (channel_id, DS_LVAL (DS_U->channel_pts));
#endif
  }
}

void tglu_work_updates (int check_only, struct tl_ds_updates *DS_U, std::shared_ptr<void> extra) {
  if (check_only > 0 || (tgl_state::instance()->locks & TGL_LOCK_DIFF)) {
    return;
  }

  if (!check_only && do_skip_seq (DS_LVAL (DS_U->seq)) < 0) {
    return;
  }
  int i;
  if (DS_U->users) {
    for (i = 0; i < DS_LVAL (DS_U->users->cnt); i++) {
      tglf_fetch_alloc_user (DS_U->users->data[i]);    
    }
  }
  if (DS_U->chats) {
    for (i = 0; i < DS_LVAL (DS_U->chats->cnt); i++) {
      tglf_fetch_alloc_chat (DS_U->chats->data[i]);
    }
  }
  if (DS_U->updates) {
    for (i = 0; i < DS_LVAL (DS_U->updates->cnt); i++) {
      tglu_work_update (check_only, DS_U->updates->data[i], extra);
    }
  }

  if (check_only) { return; }
  //bl_do_set_date (TLS, DS_LVAL (DS_U->date));
  //bl_do_set_seq (TLS, DS_LVAL (DS_U->seq));
  tgl_state::instance()->set_date (DS_LVAL (DS_U->date));
  tgl_state::instance()->set_seq (DS_LVAL (DS_U->seq));
}

void tglu_work_updates_combined (int check_only, struct tl_ds_updates *DS_U) {
  if (check_only > 0 || (tgl_state::instance()->locks & TGL_LOCK_DIFF)) {
    return;
  }

  if (!check_only && do_skip_seq (DS_LVAL (DS_U->seq_start)) < 0) {
    return;
  }
  
  int i;
  for (i = 0; i < DS_LVAL (DS_U->users->cnt); i++) {
    tglf_fetch_alloc_user (DS_U->users->data[i]);    
  }
  for (i = 0; i < DS_LVAL (DS_U->chats->cnt); i++) {
    tglf_fetch_alloc_chat (DS_U->chats->data[i]);
  }
  for (i = 0; i < DS_LVAL (DS_U->updates->cnt); i++) {
    tglu_work_update (check_only, DS_U->updates->data[i], nullptr);
  }

  if (check_only) { return; }
  //bl_do_set_date (TLS, DS_LVAL (DS_U->date));
  //bl_do_set_seq (TLS, DS_LVAL (DS_U->seq));
  tgl_state::instance()->set_date (DS_LVAL (DS_U->date));
  tgl_state::instance()->set_seq (DS_LVAL (DS_U->seq));
}

void tglu_work_update_short_message (int check_only, struct tl_ds_updates *DS_U) {
  if (check_only > 0 || (tgl_state::instance()->locks & TGL_LOCK_DIFF)) {
    return;
  }

  if (!check_only && tgl_check_pts_diff (DS_LVAL (DS_U->pts), DS_LVAL (DS_U->pts_count)) <= 0) {
    return;
  }
  
  if (check_only > 0) { return; }
  
  //struct tgl_message *N = tgl_message_get (DS_LVAL (DS_U->id));
  //int new = (!N || !(N->flags & TGLMF_CREATED));
  
  tglf_fetch_alloc_message_short (DS_U);

  if (check_only > 0 || (tgl_state::instance()->locks & TGL_LOCK_DIFF)) {
    return;
  }
  
  if (check_only) { return; }
  //bl_do_set_pts (DS_LVAL (DS_U->pts));
  tgl_state::instance()->set_pts (DS_LVAL (DS_U->pts));
}

void tglu_work_update_short_chat_message (int check_only, struct tl_ds_updates *DS_U) {
  if (check_only > 0 || (tgl_state::instance()->locks & TGL_LOCK_DIFF)) {
    return;
  }

  if (!check_only && tgl_check_pts_diff (DS_LVAL (DS_U->pts), DS_LVAL (DS_U->pts_count)) <= 0) {
    return;
  }
  
  if (check_only > 0) { return; }
  
  //struct tgl_message *N = tgl_message_get (DS_LVAL (DS_U->id));
  //int new = (!N || !(N->flags & TGLMF_CREATED));
  
  auto msg = tglf_fetch_alloc_message_short_chat (DS_U);
  tgl_state::instance()->callback()->new_messages({msg});
  
  if (check_only > 0 || (tgl_state::instance()->locks & TGL_LOCK_DIFF)) {
    return;
  }
  
#if 0
  assert (M);

  if (1) {
    //bl_do_msg_update (&M->permanent_id);
    tgl_state::instance()->callback()->new_message(M);
  }
#endif

  if (check_only) { return; }
  //bl_do_set_pts (DS_LVAL (DS_U->pts));
  tgl_state::instance()->set_pts (DS_LVAL (DS_U->pts));
}

void tglu_work_updates_too_long (int check_only, struct tl_ds_updates *DS_U) {
  if (check_only > 0 || (tgl_state::instance()->locks & TGL_LOCK_DIFF)) {
    return;
  }
  TGL_NOTICE("updates too long... Getting difference");
  if (check_only) { return; }
  tgl_do_get_difference (0, 0);
}

void tglu_work_update_short (int check_only, struct tl_ds_updates *DS_U) {
  if (check_only > 0 || (tgl_state::instance()->locks & TGL_LOCK_DIFF)) {
    return;
  }
  tglu_work_update (check_only, DS_U->update, nullptr);
}

void tglu_work_update_short_sent_message (int check_only, struct tl_ds_updates *DS_U, std::shared_ptr<void> extra) {
  if (DS_U->pts) {
    assert (DS_U->pts_count);

    if (!check_only && tgl_check_pts_diff (DS_LVAL (DS_U->pts), DS_LVAL (DS_U->pts_count)) <= 0) {
      return;
    }
  }
  std::shared_ptr<tgl_message> M = std::static_pointer_cast<tgl_message>(extra);

  if (!M) { return; }

  int f = DS_LVAL (DS_U->flags);

  unsigned flags = M->flags;
  if (f & 1) {
    flags |= TGLMF_UNREAD;
  }
  if (f & 2) {
    flags |= TGLMF_OUT;
  }
  if (f & 16) {
    flags |= TGLMF_MENTION;
  }

  if (check_only) { return; }
  tgl_state::instance()->callback()->new_messages({M});

  if (DS_U->pts) {
    tgl_state::instance()->set_pts (DS_LVAL (DS_U->pts));
  }
}

void tglu_work_any_updates (int check_only, struct tl_ds_updates *DS_U, std::shared_ptr<void> extra) {
  if (check_only > 0 || (tgl_state::instance()->locks & TGL_LOCK_DIFF)) {
    return;
  }
  switch (DS_U->magic) {
  case CODE_updates_too_long:
    tglu_work_updates_too_long (check_only, DS_U);
    return;
  case CODE_update_short_message:
    tglu_work_update_short_message (check_only, DS_U);
    return;
  case CODE_update_short_chat_message:
    tglu_work_update_short_chat_message (check_only, DS_U);
    return;
  case CODE_update_short:
    tglu_work_update_short (check_only, DS_U);
    return;
  case CODE_updates_combined:
    tglu_work_updates_combined (check_only, DS_U);
    return;
  case CODE_updates:
    tglu_work_updates (check_only, DS_U, extra);
    return;
  case CODE_update_short_sent_message:
    tglu_work_update_short_sent_message (check_only, DS_U, extra);
    return;
  default:
    assert (0);
  }
}

void tglu_work_any_updates_buf (tgl_in_buffer* in) {
  struct paramed_type type = TYPE_TO_PARAM (updates);
  struct tl_ds_updates *DS_U = fetch_ds_type_updates (in, &type);
  assert (DS_U);
  tglu_work_any_updates (1, DS_U, NULL);
  tglu_work_any_updates (0, DS_U, NULL);
  free_ds_type_updates (DS_U, &type);
}
