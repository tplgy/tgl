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
#include "tgl-binlog.h"
extern "C" {
#include "auto.h"
#include "auto/auto-types.h"
#include "auto/auto-fetch-ds.h"
#include "auto/auto-free-ds.h"
#include "auto/auto-store-ds.h"
#include "mtproto-common.h"
}
#include "tgl-log.h"
#include "tgl-structures.h"
#include "tgl-methods-in.h"
#include "tgl-timer-asio.h"
//#include "tree.h"

#include <assert.h>

void tgl_do_get_channel_difference (int channel_id, void (*callback)(std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra);

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
        tgl_do_get_difference(0, 0, 0);
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
    TGL_ERROR("qts = " << qts << ", qts_count = " << qts_count);
    if (qts < tgl_state::instance()->qts() + qts_count) {
        TGL_NOTICE("Duplicate message with qts=" << qts);
        return -1;
    }
    if (qts > tgl_state::instance()->qts() + qts_count) {
        TGL_NOTICE("Hole in qts (qts = " << qts << ", count = " << qts_count << ", cur_qts = " << tgl_state::instance()->qts() << ")");
        tgl_do_get_difference (0, 0, 0);
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
            //vlogprintf (E_NOTICE, "lock_diff = %s\n", (TLS->locks & TGL_LOCK_DIFF) ? "true" : "false");
            tgl_do_get_difference (0, 0, 0);
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

void tglu_work_update (int check_only, struct tl_ds_update *DS_U) {
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

    tgl_peer_id_t E = TGL_MK_CHANNEL (channel_id);

    if (!check_only && tgl_check_channel_pts_diff (E, DS_LVAL (DS_U->channel_pts), DS_LVAL (DS_U->channel_pts_count)) <= 0) {
      return;
    }
  }

  TGL_NOTICE("update 0x" << std::hex << DS_U->magic << " (check=" << std::dec << check_only << ")");
  if (check_only > 0 && DS_U->magic != CODE_update_message_i_d) { return; }
  switch (DS_U->magic) {
  case CODE_update_new_message:
    {
      //struct tgl_message *N = tgl_message_get (TLS, DS_LVAL (DS_U->id));
      //int new = (!N || !(N->flags & TGLMF_CREATED));
      int new_msg = 0;
      struct tgl_message *M = tglf_fetch_alloc_message (DS_U->message, &new_msg);
      assert (M);
      if (new_msg) {
        //bl_do_msg_update (&M->permanent_id);
        tgl_state::instance()->callback.new_msg(M);
      }
      break;
    };
  case CODE_update_message_i_d:
    {
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
    }
    break;
/*  case CODE_update_read_messages:
    {
      int n = DS_LVAL (DS_U->messages->cnt);
      
      int i;
      for (i = 0; i < n; i++) {
        struct tgl_message *M = tgl_message_get (DS_LVAL (DS_U->messages->data[i]));
        if (M) {
          tgl_peer_t *P;
          if (M->flags & TGLMF_OUT) {
            P = tgl_peer_get (M->to_id);
            if (P && (P->flags & TGLMF_CREATED)) {
              if (tgl_get_peer_type (P->id) == TGL_PEER_USER) {
                bl_do_user (tgl_get_peer_id (P->id), NULL, NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, 0, NULL, 0, NULL, NULL, (int *)&M->id, TGL_FLAGS_UNCHANGED);
              } else {
                bl_do_chat (tgl_get_peer_id (P->id), NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, (int *)&M->id, TGL_FLAGS_UNCHANGED);
              }
            }
          } else {
            if (tgl_get_peer_type (M->to_id) == TGL_PEER_USER) {
              P = tgl_peer_get (M->from_id);
            } else {
              P = tgl_peer_get (M->to_id);
            }
            if (P && (P->flags & TGLMF_CREATED)) {
              if (tgl_get_peer_type (P->id) == TGL_PEER_USER) {
                bl_do_user (tgl_get_peer_id (P->id), NULL, NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, 0, NULL, 0, NULL, (int *)&M->id, NULL, TGL_FLAGS_UNCHANGED);
              } else {
                bl_do_chat (tgl_get_peer_id (P->id), NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, (int *)&M->id, NULL, TGL_FLAGS_UNCHANGED);
              }
            }
          }
        }
      }
    }
    break;*/
  case CODE_update_user_typing:
    {
      //tgl_peer_id_t id = TGL_MK_USER (DS_LVAL (DS_U->user_id));
      //tgl_peer_t *U = tgl_peer_get (id);
      enum tgl_typing_status status = tglf_fetch_typing (DS_U->action);

      if (tgl_state::instance()->callback.type_notification) {
        tgl_state::instance()->callback.type_notification (DS_LVAL (DS_U->user_id), status);
      }
    }
    break;
  case CODE_update_chat_user_typing:
    {
      tgl_peer_id_t chat_id = TGL_MK_CHAT (DS_LVAL (DS_U->chat_id));
      tgl_peer_id_t id = TGL_MK_USER (DS_LVAL (DS_U->user_id));
      enum tgl_typing_status status = tglf_fetch_typing (DS_U->action);

      if (tgl_state::instance()->callback.type_in_chat_notification) {
        tgl_state::instance()->callback.type_in_chat_notification (tgl_get_peer_id(id), tgl_get_peer_id(chat_id), status);
      }
    }
    break;
  case CODE_update_user_status:
    {
      //tgl_peer_id_t user_id = TGL_MK_USER (DS_LVAL (DS_U->user_id));
      //tglf_fetch_user_status (&U->user.status, &U->user, DS_U->status);

      if (tgl_state::instance()->callback.status_notification) {
        //int expires = 0;
        //enum tgl_user_status_type status = tglf_fetch_user_status(DS_U->status, &expires);
        //tgl_state::instance()->callback.status_notification (user_id, status, expires);
      }
    }
    break;
  case CODE_update_user_name:
    {
      tgl_peer_id_t user_id = TGL_MK_USER (DS_LVAL (DS_U->user_id));
      //bl_do_user (tgl_get_peer_id (user_id), NULL, DS_STR (DS_U->first_name), DS_STR (DS_U->last_name), NULL, 0, DS_STR (DS_U->username), NULL, NULL, NULL, NULL, NULL, TGL_FLAGS_UNCHANGED);
      DS_CSTR (firstname, DS_U->first_name);
      DS_CSTR (lastname, DS_U->last_name);
      DS_CSTR (username, DS_U->username);
      tgl_state::instance()->callback.new_user(tgl_get_peer_id(user_id), "", firstname, lastname, username);
      free(firstname);
      free(lastname);
      free(username);
      break;
    }
    case CODE_update_user_photo:
    {
      tgl_peer_id_t user_id = TGL_MK_USER (DS_LVAL (DS_U->user_id));
      //bl_do_user (tgl_get_peer_id (user_id), NULL, NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, DS_U->photo, NULL, NULL, NULL, TGL_FLAGS_UNCHANGED);
      tgl_state::instance()->callback.new_user(tgl_get_peer_id(user_id), "", "", "", "");
      if (DS_U->photo) {
        tgl_file_location photo_big = tglf_fetch_file_location(DS_U->photo->photo_big);
        tgl_file_location photo_small = tglf_fetch_file_location(DS_U->photo->photo_small);
        tgl_state::instance()->callback.avatar_update(DS_LVAL (DS_U->user_id), photo_small, photo_big);
      }
      break;
    }
    case CODE_update_delete_messages:
    {
        break;
    }
    case CODE_update_chat_participants:
    {
      tgl_peer_id_t chat_id = TGL_MK_CHAT (DS_LVAL (DS_U->chat_id));
      if (DS_U->participants->magic == CODE_chat_participants) {
        //bl_do_chat (tgl_get_peer_id (chat_id), NULL, 0, NULL, NULL, DS_U->participants->version, (struct tl_ds_vector *)DS_U->participants->participants, NULL, NULL, NULL, NULL, NULL, TGL_FLAGS_UNCHANGED);
        for (int i=0; i<*DS_U->participants->participants->cnt; ++i) {
          //C->chat.users_num = *DS_U->participants->participants->cnt;
          tgl_state::instance()->callback.chat_add_user(tgl_get_peer_id (chat_id), *DS_U->participants->participants->data[i]->user_id,
              *DS_U->participants->participants->data[i]->inviter_id, *DS_U->participants->participants->data[i]->date);
        }
      }
      break;
    }
    case CODE_update_contact_registered:
    {
        if (tgl_state::instance()->callback.user_registered) {
            tgl_state::instance()->callback.user_registered(DS_LVAL (DS_U->user_id));
        }
        break;
    }
    case CODE_update_contact_link:
    {
        break;
    }
    case CODE_update_new_authorization:
    {
        if (tgl_state::instance()->callback.new_authorization) {
            tgl_state::instance()->callback.new_authorization (DS_U->device->data, DS_U->location->data);
        }
    }
    break;
  /*case CODE_update_new_geo_chat_message:
    {
    }
    break;*/
  case CODE_update_new_encrypted_message:
    {
#ifdef ENABLE_SECRET_CHAT
      struct tgl_message *M = tglf_fetch_alloc_encrypted_message (TLS, DS_U->encr_message);
      if (M) {
        //bl_do_msg_update (TLS, &M->permanent_id);
        TLS->callback.new_msg(M);
      }
#endif
    }
    break;
  case CODE_update_encryption:
    {
#ifdef ENABLE_SECRET_CHAT
      struct tgl_secret_chat *E = tglf_fetch_alloc_encrypted_chat (DS_U->encr_chat);
      TGL_DEBUG("Secret chat state = %d\n", E->state);
      if (E->state == sc_ok) {
        tgl_do_send_encr_chat_layer (E);
      }
#endif
    }
    break;
  case CODE_update_encrypted_chat_typing:
    {
      if (tgl_state::instance()->callback.type_in_secret_chat_notification) {
        tgl_state::instance()->callback.type_in_secret_chat_notification(DS_LVAL (DS_U->chat_id));
      }
    }
    break;
  case CODE_update_encrypted_messages_read:
    {
#ifdef ENABLE_SECRET_CHAT
      tgl_peer_id_t id = TGL_MK_ENCR_CHAT (DS_LVAL (DS_U->chat_id));
      tgl_peer_t *P = tgl_peer_get (id);
      
      if (P && P->last) {
        struct tgl_message *M = P->last;
        while (M && (!(M->flags & TGLMF_OUT) || (M->flags & TGLMF_UNREAD))) {
          if (M->flags & TGLMF_OUT) {
            bl_do_edit_message_encr (&M->permanent_id, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, M->flags & ~TGLMF_UNREAD);
          }
          M = M->next;
        }
      }
#endif
    }
    break;
  case CODE_update_chat_participant_add:
    {
      tgl_peer_id_t chat_id = TGL_MK_CHAT (DS_LVAL (DS_U->chat_id));
      tgl_peer_id_t user_id = TGL_MK_USER (DS_LVAL (DS_U->user_id));
      tgl_peer_id_t inviter_id = TGL_MK_USER (DS_LVAL (DS_U->inviter_id));
      //int version = DS_LVAL (DS_U->version); 

      //bl_do_chat_add_user (C->id, version, tgl_get_peer_id (user_id), tgl_get_peer_id (inviter_id), time (0));
      if (tgl_state::instance()->callback.chat_add_user) {
        tgl_state::instance()->callback.chat_add_user(tgl_get_peer_id (chat_id), tgl_get_peer_id (user_id), tgl_get_peer_id (inviter_id), time (0));
      }
    }
    break;
  case CODE_update_chat_participant_delete:
    {
      tgl_peer_id_t chat_id = TGL_MK_CHAT (DS_LVAL (DS_U->chat_id));
      tgl_peer_id_t user_id = TGL_MK_USER (DS_LVAL (DS_U->user_id));
      //int version = DS_LVAL (DS_U->version); 
      
      //bl_do_chat_del_user (C->id, version, tgl_get_peer_id (user_id));
      if (tgl_state::instance()->callback.chat_delete_user) {
        tgl_state::instance()->callback.chat_delete_user (tgl_get_peer_id (chat_id), tgl_get_peer_id (user_id));
      }
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
      tgl_peer_id_t peer_id = TGL_MK_USER (DS_LVAL (DS_U->user_id));

      //bl_do_user (tgl_get_peer_id (peer_id), NULL, NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL, NULL, flags);
      if (tgl_state::instance()->callback.user_update) {
        tgl_state::instance()->callback.user_update(tgl_get_peer_id (peer_id), &blocked, tgl_update_blocked);
      }
    }
    break;
  case CODE_update_notify_settings:
    {
    }
    break;
  case CODE_update_service_notification:
    {
      TGL_ERROR("Notification " << std::string(DS_U->type->data, DS_U->type->len) << ":" << std::string(DS_U->message_text->data, DS_U->message_text->len));
      if (tgl_state::instance()->callback.notification) {
        tgl_state::instance()->callback.notification (DS_U->type->data, DS_U->message_text->data);
      }
    }
    break;
  case CODE_update_privacy:
    TGL_NOTICE("privacy change update");
    break;
  case CODE_update_user_phone:
    {
      tgl_peer_id_t user_id = TGL_MK_USER (DS_LVAL (DS_U->user_id));
      //bl_do_user (tgl_get_peer_id (user_id), NULL, NULL, 0, NULL, 0, DS_STR (DS_U->phone), NULL, 0, NULL, NULL, NULL, NULL, NULL, TGL_FLAGS_UNCHANGED);
      if (tgl_state::instance()->callback.user_update) {
        DS_CSTR (phone, DS_U->phone);
        tgl_state::instance()->callback.user_update(tgl_get_peer_id (user_id), phone, tgl_update_phone);
      }
    }
    break;
  case CODE_update_read_history_inbox:
    {
      tgl_peer_id_t id = tglf_fetch_peer_id (DS_U->peer);
      if (tgl_get_peer_type (id) == TGL_PEER_USER) {
        //bl_do_user (tgl_get_peer_id (id), NULL, NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, DS_U->max_id, NULL, NULL, TGL_FLAGS_UNCHANGED);
        // TODO update read history (id) DS_U->max_id
      } else {
        //bl_do_chat (tgl_get_peer_id (id), NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, DS_U->max_id, NULL, TGL_FLAGS_UNCHANGED);
        if (DS_U->max_id) {
          //P->chat.last_read_in = *DS_U->max_id;
          //tgls_messages_mark_read (P->chat.last, 0, *DS_U->max_id);
        }
      }
    }
    break;
  case CODE_update_read_history_outbox:
    {
      tgl_peer_id_t id = tglf_fetch_peer_id (DS_U->peer);
      if (tgl_get_peer_type (id) == TGL_PEER_USER) {
        //bl_do_user (tgl_get_peer_id (id), NULL, NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, NULL, DS_U->max_id, NULL, TGL_FLAGS_UNCHANGED);
        // TODO update read history (id) DS_U->max_id
      } else {
        //bl_do_chat (tgl_get_peer_id (id), NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, DS_U->max_id, TGL_FLAGS_UNCHANGED);
        if (DS_U->max_id) {
          //P->chat.last_read_out = *DS_U->max_id;
          //tgls_messages_mark_read (P->chat.last, TGLMF_OUT, *DS_U->max_id);
        }
      }
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
      tgl_do_get_channel_difference (DS_LVAL (DS_U->channel_id), NULL, NULL);
    }
    break;
  case CODE_update_channel:
    break;
  case CODE_update_channel_group:
    break;
  case CODE_update_new_channel_message:
    {
      int new_msg = 0;
      struct tgl_message *M = tglf_fetch_alloc_message (DS_U->message, &new_msg);
      if (M && new_msg) {
        //bl_do_msg_update (&M->permanent_id);
      }
    }
    break;
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

    //bl_do_set_pts (DS_LVAL (DS_U->pts));
    tgl_state::instance()->set_pts(DS_LVAL (DS_U->pts));
  }
  if (DS_U->qts) {
    //bl_do_set_qts (DS_LVAL (DS_U->qts));
    tgl_state::instance()->set_qts(DS_LVAL (DS_U->qts));
  }
  if (DS_U->channel_pts) {
    assert (DS_U->channel_pts_count);
    
    int channel_id;
    if (DS_U->channel_id) {
      channel_id = DS_LVAL (DS_U->channel_id);
    } else {
      assert (DS_U->message);
      assert (DS_U->message->to_id);
      assert (DS_U->message->to_id->magic == CODE_peer_channel);
      channel_id = DS_LVAL (DS_U->message->to_id->channel_id);
    }    

    //bl_do_set_channel_pts (channel_id, DS_LVAL (DS_U->channel_pts));
  }
}

void tglu_work_updates (int check_only, struct tl_ds_updates *DS_U) {
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
      tglu_work_update (check_only, DS_U->updates->data[i]);
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
    tglu_work_update (check_only, DS_U->updates->data[i]);
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
  
  struct tgl_message *M = tglf_fetch_alloc_message_short (DS_U);
  
  if (check_only > 0 || (tgl_state::instance()->locks & TGL_LOCK_DIFF)) {
    return;
  }
  assert (M);

  if (1) {
    //bl_do_msg_update (&M->permanent_id);
    tgl_state::instance()->callback.new_msg(M);
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
  
  struct tgl_message *M = tglf_fetch_alloc_message_short_chat (DS_U);
  
  if (check_only > 0 || (tgl_state::instance()->locks & TGL_LOCK_DIFF)) {
    return;
  }
  
  assert (M);

  if (1) {
    //bl_do_msg_update (&M->permanent_id);
    tgl_state::instance()->callback.new_msg(M);
  }

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
  tgl_do_get_difference (0, 0, 0);
}

void tglu_work_update_short (int check_only, struct tl_ds_updates *DS_U) {
  if (check_only > 0 || (tgl_state::instance()->locks & TGL_LOCK_DIFF)) {
    return;
  }
  tglu_work_update (check_only, DS_U->update);
}

void tglu_work_update_short_sent_message (int check_only, struct tl_ds_updates *DS_U, void *extra) {
  if (DS_U->pts) {
    assert (DS_U->pts_count);

    if (!check_only && tgl_check_pts_diff (DS_LVAL (DS_U->pts), DS_LVAL (DS_U->pts_count)) <= 0) {
      return;
    }
  }
  struct tgl_message *M = (struct tgl_message *)extra;

  if (!M) { return; }
  
  //long long random_id = M->permanent_id.id;
  tgl_message_id_t msg_id = M->permanent_id;
  msg_id.id = DS_LVAL (DS_U->id);
  //bl_do_set_msg_id (&M->permanent_id, &msg_id);
  //tgls_insert_random2local (random_id, &msg_id);

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

#if 0
  bl_do_edit_message (&M->permanent_id, 
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL, 0,
    DS_U->media,
    NULL,
    NULL,
    NULL, 
    NULL,
    flags);
#endif
 
  if (check_only) { return; }
  //bl_do_msg_update (&M->permanent_id);
  
  if (DS_U->pts) {
    //bl_do_set_pts (DS_LVAL (DS_U->pts));
    tgl_state::instance()->set_pts (DS_LVAL (DS_U->pts));
  }
}

void tglu_work_any_updates (int check_only, struct tl_ds_updates *DS_U, void *extra) {
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
    tglu_work_updates (check_only, DS_U);    
    return;
  case CODE_update_short_sent_message:
    tglu_work_update_short_sent_message (check_only, DS_U, extra);    
    return;
  default:
    assert (0);
  }
}

void tglu_work_any_updates_buf () {
  struct paramed_type type = TYPE_TO_PARAM (updates);
  struct tl_ds_updates *DS_U = fetch_ds_type_updates (&type);
  assert (DS_U);
  tglu_work_any_updates (1, DS_U, NULL);
  tglu_work_any_updates (0, DS_U, NULL);
  free_ds_type_updates (DS_U, &type);
}

//#define user_cmp(a,b) (tgl_get_peer_id ((a)->id) - tgl_get_peer_id ((b)->id))
//DEFINE_TREE(user, struct tgl_user *,user_cmp,0)

#if 0
static void notify_status (struct tgl_user *U, void *ex) {
    if (tgl_state::instance()->callback.user_status_update) {
        tgl_state::instance()->callback.user_status_update (U);
    }
}

static void status_notify (void *arg) {
    tree_act_ex_user (tgl_state::instance()->online_updates, notify_status);
    tree_clear_user (tgl_state::instance()->online_updates);
    tgl_state::instance()->online_updates = NULL;
    tgl_state::instance()->timer_methods->free (tgl_state::instance()->online_updates_timer);
    tgl_state::instance()->online_updates_timer = NULL;
}
#endif

void tgl_insert_status_update (struct tgl_user *U) {
  //if (!tree_lookup_user (tgl_state::instance()->online_updates, U)) {
    //tgl_state::instance()->online_updates = tree_insert_user (tgl_state::instance()->online_updates, U, rand ());
  //}
  //if (!tgl_state::instance()->online_updates_timer) {
    //tgl_state::instance()->online_updates_timer = tgl_state::instance()->timer_methods->alloc (status_notify, 0);
    //tgl_state::instance()->timer_methods->insert (tgl_state::instance()->online_updates_timer, 0);
  //}
}

static void user_expire (void *arg) {
    struct tgl_user *U = (struct tgl_user *)arg;
    U->status.ev->cancel();
    U->status.ev = nullptr;
    U->status.online = -1;
    U->status.when = tglt_get_double_time ();
    tgl_insert_status_update (U);
}

void tgl_insert_status_expire (struct tgl_user *U) {
    assert (!U->status.ev);
    U->status.ev = tgl_state::instance()->timer_factory()->create_timer(std::bind(&user_expire, U));

    U->status.ev->start(U->status.when - tglt_get_double_time ());
}

void tgl_remove_status_expire (struct tgl_user *U) {
    U->status.ev->cancel();
    U->status.ev = nullptr;
}
