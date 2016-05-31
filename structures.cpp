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


#include <assert.h>
#include <string.h>
#include <strings.h>
#include "tgl-queries.h"
#include "tgl-structures.h"
#include "queries.h"
#include "queries-encrypted.h"
#include "tgl-methods-in.h"
#include "updates.h"
#include "mtproto-client.h"
#include "types/tgl_bot.h"
#include "types/tgl_update_callback.h"
#include "types/tgl_user.h"

#include "tgl.h"
#include "auto.h"
#include "auto/auto-skip.h"
#include "auto/auto-types.h"
#include "auto/auto-free-ds.h"
#include "auto/auto-fetch-ds.h"
#include "crypto/aes.h"
#include "crypto/bn.h"
#include "crypto/sha.h"
#include "mtproto-common.h"

//static void increase_peer_size ();

enum tgl_typing_status tglf_fetch_typing (struct tl_ds_send_message_action *DS_SMA) {
  if (!DS_SMA) { return tgl_typing_none; }
  switch (DS_SMA->magic) {
  case CODE_send_message_typing_action:
    return tgl_typing_typing;
  case CODE_send_message_cancel_action:
    return tgl_typing_cancel;
  case CODE_send_message_record_video_action:
    return tgl_typing_record_video;
  case CODE_send_message_upload_video_action:
    return tgl_typing_upload_video;
  case CODE_send_message_record_audio_action:
    return tgl_typing_record_audio;
  case CODE_send_message_upload_audio_action:
    return tgl_typing_upload_audio;
  case CODE_send_message_upload_photo_action:
    return tgl_typing_upload_photo;
  case CODE_send_message_upload_document_action:
    return tgl_typing_upload_document;
  case CODE_send_message_geo_location_action:
    return tgl_typing_geo;
  case CODE_send_message_choose_contact_action:
    return tgl_typing_choose_contact;
  default:
    assert (0);
    return tgl_typing_none;
  }
}

/*enum tgl_typing_status tglf_fetch_typing (void) {
  struct paramed_type type = TYPE_TO_PARAM (send_message_action);
  struct tl_ds_send_message_action *DS_SMA = fetch_ds_type_send_message_action (&type);
  enum tgl_typing_status res = tglf_fetch_typing_new (DS_SMA);
  free_ds_type_send_message_action (DS_SMA, &type);
  return res;
}*/

/* {{{ Fetch */

tgl_peer_id_t tglf_fetch_peer_id (struct tl_ds_peer *DS_P) {
  switch (DS_P->magic) {
  case CODE_peer_user:
    return TGL_MK_USER (DS_LVAL (DS_P->user_id));
  case CODE_peer_chat:
    return TGL_MK_CHAT (DS_LVAL (DS_P->chat_id));
  case CODE_peer_channel:
    return TGL_MK_CHANNEL (DS_LVAL (DS_P->channel_id));
  default: 
    assert (0);
    exit (2);
  }

}

tgl_file_location tglf_fetch_file_location (struct tl_ds_file_location *DS_FL) {
  tgl_file_location location;

  if (!DS_FL) {
    return location;
  }

  location.set_dc(DS_LVAL(DS_FL->dc_id));
  location.set_volume(DS_LVAL(DS_FL->volume_id));
  location.set_local_id(DS_LVAL(DS_FL->local_id));
  location.set_secret(DS_LVAL(DS_FL->secret));

  return location;
}

tgl_user_status tglf_fetch_user_status(struct tl_ds_user_status *DS_US) {
    tgl_user_status new_status;
    if (!DS_US) { return new_status; }
    switch (DS_US->magic) {
    case CODE_user_status_empty:
        new_status.online = tgl_user_online_status::unknown;
        new_status.when = 0;
        break;
    case CODE_user_status_online:
    {
        new_status.online = tgl_user_online_status::online;
        new_status.when = DS_LVAL (DS_US->expires);
    }
        break;
    case CODE_user_status_offline:
        new_status.online = tgl_user_online_status::offline;
        new_status.when = DS_LVAL (DS_US->was_online);
        break;
    case CODE_user_status_recently:
        new_status.online = tgl_user_online_status::recent;
        break;
    case CODE_user_status_last_week:
        new_status.online = tgl_user_online_status::last_week;
        break;
    case CODE_user_status_last_month:
        new_status.online = tgl_user_online_status::last_month;
        break;
    default:
        assert (0);
    }
    return new_status;
}

std::shared_ptr<tgl_user> tglf_fetch_alloc_user(struct tl_ds_user *DS_U, bool invoke_callback) {
  if (!DS_U) { return nullptr; }
  if (DS_U->magic == CODE_user_empty) {
    return nullptr;
  } 

  tgl_peer_id_t user_id = TGL_MK_USER (DS_LVAL (DS_U->id));  
  user_id.access_hash = DS_LVAL (DS_U->access_hash);

  std::shared_ptr<tgl_user> user = std::make_shared<tgl_user>();
  user->id = user_id;

  int flags = user->flags;

  if (DS_LVAL (DS_U->flags) & (1 << 10)) {
    //bl_do_set_our_id (user->id);
    tgl_state::instance()->set_our_id (tgl_get_peer_id(user_id));
    flags |= TGLUF_SELF;
  } else {
    flags &= ~TGLUF_SELF;
  }

  if (DS_LVAL (DS_U->flags) & (1 << 11)) {
    flags |= TGLUF_CONTACT;
  } else {
    flags &= ~TGLUF_CONTACT;
  }
  
  if (DS_LVAL (DS_U->flags) & (1 << 12)) {
    flags |= TGLUF_MUTUAL_CONTACT;
  } else {
    flags &= ~TGLUF_MUTUAL_CONTACT;
  }
  
  bool is_bot = false;
  if (DS_LVAL (DS_U->flags) & (1 << 14)) {
    is_bot = true;
  }
  /*
  if (DS_LVAL (DS_U->flags) & (1 << 15)) {
    flags |= TGLUF_BOT_FULL_ACCESS;
  }
  
  if (DS_LVAL (DS_U->flags) & (1 << 16)) {
    flags |= TGLUF_BOT_NO_GROUPS;
  }*/
  
  if (DS_LVAL (DS_U->flags) & (1 << 17)) {
    flags |= TGLUF_OFFICIAL;
  } else {
    flags &= ~TGLUF_OFFICIAL;
  }

  if (!(flags & TGLUF_CREATED)) {
      flags |= TGLUF_CREATE | TGLUF_CREATED;
  }

#if 0
  bl_do_user (tgl_get_peer_id (user->id),
    DS_U->access_hash,
    DS_STR (DS_U->first_name), 
    DS_STR (DS_U->last_name), 
    DS_STR (DS_U->phone),
    DS_STR (DS_U->username),
    NULL,
    DS_U->photo,
    NULL, NULL,
    NULL,
    flags
  );
#endif

  if (DS_LVAL (DS_U->flags) & (1 << 13)) {
    tgl_state::instance()->callback()->user_deleted(tgl_get_peer_id(user_id));
    return user;
  } else {
    DS_CSTR(firstname, DS_U->first_name);
    DS_CSTR(lastname, DS_U->last_name);
    DS_CSTR(phone, DS_U->phone);
    DS_CSTR(username, DS_U->username);
    user->firstname = firstname;
    user->lastname = lastname;
    user->username = username;
    user->phone = phone;

    tgl_user_status status = tglf_fetch_user_status(DS_U->status);
    if (invoke_callback) {
        tgl_state::instance()->callback()->new_user(tgl_get_peer_id(user_id), phone, firstname, lastname, username,
            DS_U->access_hash ? * DS_U->access_hash : 0, status, is_bot);
    }

    free(firstname);
    free(lastname);
    free(phone);
    free(username);

    if (DS_U->photo && invoke_callback) {
      tgl_file_location photo_big = tglf_fetch_file_location(DS_U->photo->photo_big);
      tgl_file_location photo_small = tglf_fetch_file_location(DS_U->photo->photo_small);

      tgl_state::instance()->callback()->avatar_update(tgl_get_peer_id(user_id), user_id.peer_type, photo_small, photo_big);
    }
    return user;
  }
}

std::shared_ptr<tgl_user> tglf_fetch_alloc_user_full(struct tl_ds_user_full *DS_UF) {
  if (!DS_UF) { return nullptr; }

  auto user = tglf_fetch_alloc_user(DS_UF->user);
  if (!user) { return nullptr; }

  int flags = user->flags;
  
  if (DS_BVAL (DS_UF->blocked)) {
    flags |= TGLUF_BLOCKED;
  } else {
    flags &= ~TGLUF_BLOCKED;
  }

#if 0
  bl_do_user (tgl_get_peer_id (user->id),
    NULL,
    NULL, 0, 
    NULL, 0,
    NULL, 0,
    NULL, 0,
    DS_UF->profile_photo,
    NULL,
    NULL, NULL,
    DS_UF->bot_info,
    flags
  );
#endif

    if (DS_UF->user->photo) {
        tgl_file_location photo_big = tglf_fetch_file_location(DS_UF->user->photo->photo_big);
        tgl_file_location photo_small = tglf_fetch_file_location(DS_UF->user->photo->photo_small);
        tgl_state::instance()->callback()->avatar_update(tgl_get_peer_id(user->id), user->id.peer_type,photo_small, photo_big);
    }

  return user;
}

void str_to_256 (unsigned char *dst, char *src, int src_len) {
  if (src_len >= 256) {
    memcpy (dst, src + src_len - 256, 256);
  } else {
    memset(dst, 0, 256 - src_len);
    memcpy (dst + 256 - src_len, src, src_len);
  }
}

void str_to_32 (unsigned char *dst, char *src, int src_len) {
  if (src_len >= 32) {
    memcpy (dst, src + src_len - 32, 32);
  } else {
    memset(dst, 0, 32 - src_len);
    memcpy (dst + 32 - src_len, src, src_len);
  }
}

std::shared_ptr<tgl_secret_chat> tglf_fetch_alloc_encrypted_chat (struct tl_ds_encrypted_chat *DS_EC) {
  if (!DS_EC) {
    return nullptr;
  }

  if (DS_EC->magic == CODE_encrypted_chat_empty) {
    return nullptr;
  }

  tgl_peer_id_t chat_id = TGL_MK_ENCR_CHAT (DS_LVAL (DS_EC->id));  
  chat_id.access_hash = DS_LVAL (DS_EC->access_hash);
  
  std::shared_ptr<tgl_secret_chat> secret_chat = tgl_state::instance()->secret_chat_for_id(chat_id);

  if (!secret_chat) {
    int admin_id = DS_LVAL(DS_EC->id);

    if (!admin_id) {
      // It must be a secret chat which is encryptedChatDiscarded#13d6dd27
      // For a discarded secret chat which is not on our side either, we do nothing.
      return nullptr;
    }

    if (admin_id != tgl_state::instance()->our_id().peer_id) {
      // It must be a new secret chat requested from the peer.
      secret_chat = tgl_state::instance()->create_secret_chat(chat_id);
    }
  }

  if (!secret_chat) {
    return NULL;
  }
  
  bool is_new = !(secret_chat->flags & TGLPF_CREATED);
 
  if (DS_EC->magic == CODE_encrypted_chat_discarded) {
    if (is_new) {
        return nullptr;
    }

    tgl_secret_chat_state state = sc_deleted;
    tgl_update_secret_chat(secret_chat,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        &state,
        NULL,
        NULL,
        NULL,
        TGL_FLAGS_UNCHANGED);

    return secret_chat;
  }

  static unsigned char g_key[256];
  if (is_new) {
    if (DS_EC->magic != CODE_encrypted_chat_requested) {
      //TGL_WARNING("Unknown chat. May be we forgot something...");
      return secret_chat;
    }

    str_to_256 (g_key, DS_STR (DS_EC->g_a));
 
    int user_id =  DS_LVAL (DS_EC->participant_id) + DS_LVAL (DS_EC->admin_id) - tgl_get_peer_id (tgl_state::instance()->our_id());
    tgl_secret_chat_state state = sc_request;
    tgl_update_secret_chat(secret_chat,
            DS_EC->access_hash,
            DS_EC->date,
            DS_EC->admin_id,
            &user_id,
            NULL,
            g_key,
            &state,
            NULL,
            NULL,
            NULL,
            TGLECF_CREATE | TGLECF_CREATED);
  } else {
    if (DS_EC->magic == CODE_encrypted_chat_waiting) {
      tgl_secret_chat_state state = sc_waiting;
      tgl_update_secret_chat(secret_chat,
            DS_EC->access_hash,
            DS_EC->date,
            NULL,
            NULL,
            NULL,
            NULL,
            &state,
            NULL,
            NULL,
            NULL,
            TGL_FLAGS_UNCHANGED);
      return secret_chat; // We needed only access hash from here
    }
    
    str_to_256 (g_key, DS_STR (DS_EC->g_a_or_b));
    
    //write_secret_chat_file ();
    tgl_secret_chat_state state = sc_ok;
    secret_chat->temp_key_fingerprint = DS_LVAL(DS_EC->key_fingerprint);
    tgl_update_secret_chat(secret_chat,
            DS_EC->access_hash,
            DS_EC->date,
            NULL,
            NULL,
            NULL,
            g_key,
            &state,
            NULL,
            NULL,
            NULL,
            TGL_FLAGS_UNCHANGED);
  }

  return secret_chat;
}

std::shared_ptr<tgl_chat> tglf_fetch_alloc_chat (struct tl_ds_chat *DS_C, bool invoke_callback) {
  if (!DS_C) { return nullptr; }
  if (DS_C->magic == CODE_chat_empty) { 
    return nullptr;
  }
  if (DS_C->magic == CODE_channel || DS_C->magic == CODE_channel_forbidden) {
    return tglf_fetch_alloc_channel(DS_C, false);
  }
  tgl_peer_id_t chat_id = TGL_MK_CHAT (DS_LVAL (DS_C->id));  
  chat_id.access_hash = 0; // chats don't have access hash

  std::shared_ptr<tgl_chat> C = std::make_shared<tgl_chat>();
  C->id = chat_id;

  bool creator = false;
  bool kicked = false;
  bool left = false;
  bool admins_enabled = false;
  bool deactivated = false;
  bool admin = false;

  if (DS_LVAL (DS_C->flags) & 1) {
    creator = TGLCF_CREATED;
  }

  if (DS_LVAL (DS_C->flags) & 2) {
    kicked = TGLCF_KICKED;
  }

  if (DS_LVAL (DS_C->flags) & 4) {
    left = TGLCF_LEFT;
  }

  if (DS_LVAL (DS_C->flags) & 8) {
    admins_enabled = TGLCF_ADMINS_ENABLED;
  }

  if (DS_LVAL (DS_C->flags) & 16) {
    admin = TGLCF_ADMIN;
  }

  if (DS_LVAL (DS_C->flags) & 32) {
    deactivated |= TGLCF_DEACTIVATED;
  }

#if 0
  bl_do_chat (tgl_get_peer_id (C->id),
    DS_STR (DS_C->title),
    DS_C->participants_count, 
    DS_C->date,
    NULL,
    NULL,
    DS_C->photo,
    NULL,
    NULL,
    NULL, NULL,
    flags
  );
#endif

  C->photo_big = tglf_fetch_file_location(DS_C->photo->photo_big);
  C->photo_small = tglf_fetch_file_location(DS_C->photo->photo_small);

  std::string title = DS_C->title ? std::string(DS_C->title->data, DS_C->title->len) : "";
  std::string username = DS_C->username ? std::string(DS_C->username->data, DS_C->username->len) : "";

  C->title = title;
  C->username = username;

  if (invoke_callback) {
    tgl_state::instance()->callback()->chat_update(tgl_get_peer_id(C->id), *DS_C->participants_count, title, *(DS_C->date), creator,
        admin, admins_enabled, kicked, left, deactivated);
    tgl_state::instance()->callback()->avatar_update(tgl_get_peer_id(C->id), C->id.peer_type, C->photo_big, C->photo_small);
  }
  return C;
}

std::shared_ptr<tgl_chat> tglf_fetch_alloc_chat_full (struct tl_ds_messages_chat_full *DS_MCF) {
  if (!DS_MCF) { return nullptr; }
  if (DS_MCF->full_chat->magic == CODE_channel_full) {
    return tglf_fetch_alloc_channel_full (DS_MCF);
  }
 
  if (DS_MCF->users) {
    int i;
    for (i = 0; i < DS_LVAL (DS_MCF->users->cnt); i++) {
      tglf_fetch_alloc_user (DS_MCF->users->data[i]);
    }
  }

  if (DS_MCF->chats) {
    int i;
    for (i = 0; i < DS_LVAL (DS_MCF->chats->cnt); i++) {
      tglf_fetch_alloc_chat (DS_MCF->chats->data[i]);
    }
  }

  struct tl_ds_chat_full *DS_CF = DS_MCF->full_chat;

  if (DS_CF->bot_info) {
    int n = DS_LVAL (DS_CF->bot_info->cnt);
    int i;
    for (i = 0; i < n; i++) {
#if 0
      struct tl_ds_bot_info *DS_BI = DS_CF->bot_info->data[i];

      tgl_peer_id_t peer_id = TGL_MK_USER (DS_LVAL (DS_BI->user_id));
      if (P && (P->flags & TGLCF_CREATED)) {
        bl_do_user (tgl_get_peer_id (P->id), 
            NULL,
            NULL, 0, 
            NULL, 0,
            NULL, 0,
            NULL, 0,
            NULL,
            NULL,
            NULL, NULL,
            DS_BI,
            TGL_FLAGS_UNCHANGED
            );
      }
#endif
    }
  }

  tgl_peer_id_t chat_id = TGL_MK_CHAT (DS_LVAL (DS_CF->id));  
  std::shared_ptr<tgl_chat> C = std::make_shared<tgl_chat>();
  C->id = chat_id;

#if 0
  bl_do_chat (tgl_get_peer_id (C->id),
      NULL, 0,
      NULL, 
      NULL,
      DS_CF->participants->version,
      (struct tl_ds_vector *)DS_CF->participants->participants,
      NULL,
      DS_CF->chat_photo,
      NULL,
      //DS_CF->participants->admin_id,
      NULL, NULL,
      C->flags & 0xffff
      );
#endif

  if (DS_CF->chat_photo && DS_CF->chat_photo->sizes && *DS_CF->chat_photo->sizes->cnt > 1) {
    C->photo_big = tglf_fetch_file_location(DS_CF->chat_photo->sizes->data[1]->location);
  }
  if (DS_CF->chat_photo && DS_CF->chat_photo->sizes && *DS_CF->chat_photo->sizes->cnt > 0) {
    C->photo_small = tglf_fetch_file_location(DS_CF->chat_photo->sizes->data[0]->location);
  }

  //tgl_state::instance()->callback()->chat_update(tgl_get_peer_id (C->id), *DS_CF->participants->participants->cnt, DS_CF->);
  if (DS_CF->participants && DS_CF->participants->participants) {
        for (int i=0; i<*(DS_CF->participants->participants->cnt); ++i) {
            tgl_state::instance()->callback()->chat_add_user(tgl_get_peer_id (C->id), *DS_CF->participants->participants->data[i]->user_id,
                    DS_CF->participants->participants->data[i]->inviter_id ? *DS_CF->participants->participants->data[i]->inviter_id : 0,
                    DS_CF->participants->participants->data[i]->date ? *DS_CF->participants->participants->data[i]->date : 0);
        }
  }
  //TODO update users

  return C;
}

std::shared_ptr<tgl_channel> tglf_fetch_alloc_channel (struct tl_ds_chat *DS_C, bool invoke_callback) {
  if (!DS_C) { return nullptr; }
  
  tgl_peer_id_t chat_id = TGL_MK_CHANNEL (DS_LVAL (DS_C->id));  
  chat_id.access_hash = DS_LVAL (DS_C->access_hash); 

  std::shared_ptr<tgl_channel> C = std::make_shared<tgl_channel>();
  C->id = chat_id;
  
  int flags = C->flags;
  if (!(flags & TGLCHF_CREATED)) {
    flags |= TGLCHF_CREATE | TGLCHF_CREATED;
  }
  
  if (DS_LVAL (DS_C->flags) & 1) {
    flags |= TGLCHF_CREATOR;
  } else {
    flags &= ~TGLCHF_CREATOR;
  }

  if (DS_LVAL (DS_C->flags) & 2) {
    flags |= TGLCHF_KICKED;
  } else {
    flags &= ~TGLCHF_KICKED;
  }

  if (DS_LVAL (DS_C->flags) & 4) {
    flags |= TGLCHF_LEFT;
  } else {
    flags &= ~TGLCHF_LEFT;
  }

  if (DS_LVAL (DS_C->flags) & 8) {
    flags |= TGLCHF_EDITOR;
  } else {
    flags &= ~TGLCHF_EDITOR;
  }

  if (DS_LVAL (DS_C->flags) & 16) {
    flags |= TGLCHF_MODERATOR;
  } else {
    flags &= ~TGLCHF_MODERATOR;
  }

  if (DS_LVAL (DS_C->flags) & 32) {
    flags |= TGLCHF_BROADCAST;
  } else {
    flags &= ~TGLCHF_BROADCAST;
  }

  if (DS_LVAL (DS_C->flags) & 128) {
    flags |= TGLCHF_OFFICIAL;
  } else {
    flags &= ~TGLCHF_OFFICIAL;
  }

  if (DS_LVAL (DS_C->flags) & 256) {
    flags |= TGLCHF_MEGAGROUP;
  } else {
    flags &= ~TGLCHF_MEGAGROUP;
  }

#if 0
  bl_do_channel (tgl_get_peer_id (C->id),
    DS_C->access_hash,
    DS_C->date,
    DS_STR (DS_C->title),
    DS_STR (DS_C->username),
    DS_C->photo,
    NULL,
    NULL,
    NULL, 0,
    NULL, NULL, NULL, NULL,
    flags
  );
#endif

  std::string title = DS_C->title ? std::string(DS_C->title->data, DS_C->title->len) : "";
  std::string username = DS_C->username ? std::string(DS_C->username->data, DS_C->username->len) : "";

  C->title = title;
  C->username = username;

  if (invoke_callback) {
    tgl_state::instance()->callback()->channel_update(tgl_get_peer_id(C->id), *(DS_C->access_hash), *(DS_C->date), title, username);
    
      if (DS_C->photo) {
          C->photo_big = tglf_fetch_file_location(DS_C->photo->photo_big);
          C->photo_small = tglf_fetch_file_location(DS_C->photo->photo_small);
          tgl_state::instance()->callback()->avatar_update(tgl_get_peer_id(C->id), tgl_get_peer_type(C->id), C->photo_big, C->photo_small);
      }
  }
  return C;
}

std::shared_ptr<tgl_channel> tglf_fetch_alloc_channel_full (struct tl_ds_messages_chat_full *DS_MCF) {
  if (!DS_MCF) { return nullptr; }
  
  if (DS_MCF->users) {
    int i;
    for (i = 0; i < DS_LVAL (DS_MCF->users->cnt); i++) {
      tglf_fetch_alloc_user (DS_MCF->users->data[i]);
    }
  }

  if (DS_MCF->chats) {
    int i;
    for (i = 0; i < DS_LVAL (DS_MCF->chats->cnt); i++) {
      tglf_fetch_alloc_chat (DS_MCF->chats->data[i]);
    }
  }
  struct tl_ds_chat_full *DS_CF = DS_MCF->full_chat;

  tgl_peer_id_t chat_id = TGL_MK_CHANNEL (DS_LVAL (DS_CF->id));

  std::shared_ptr<tgl_channel> C = std::make_shared<tgl_channel>();
  C->id = chat_id;

#if 0
  bl_do_channel (tgl_get_peer_id (C->id),
    NULL,
    NULL,
    NULL, 0,
    NULL, 0,
    NULL,
    DS_CF->chat_photo,
    NULL,
    DS_STR (DS_CF->about),
    DS_CF->participants_count,
    DS_CF->admins_count,
    DS_CF->kicked_count,
    DS_CF->read_inbox_max_id,
    TGL_FLAGS_UNCHANGED
  );
#endif

  return C;
}

static std::shared_ptr<tgl_photo_size> tglf_fetch_photo_size(const struct tl_ds_photo_size *DS_PS) {
  auto photo_size = std::make_shared<tgl_photo_size>();

  if (DS_PS->type && DS_PS->type->data) {
    photo_size->type = std::string(DS_PS->type->data, DS_PS->type->len);
  }

  photo_size->w = DS_LVAL(DS_PS->w);
  photo_size->h = DS_LVAL(DS_PS->h);
  photo_size->size = DS_LVAL(DS_PS->size);
  if (DS_PS->bytes) {
    photo_size->size = DS_PS->bytes->len;
  }

  photo_size->loc = tglf_fetch_file_location(DS_PS->location);

  return photo_size;
}

void tglf_fetch_geo (struct tgl_geo *G, struct tl_ds_geo_point *DS_GP) {
  G->longitude = DS_LVAL (DS_GP->longitude);
  G->latitude = DS_LVAL (DS_GP->latitude);
}

std::shared_ptr<tgl_photo> tglf_fetch_alloc_photo(const tl_ds_photo *DS_P) {
  if (!DS_P) {
    return nullptr;
  }
  if (DS_P->magic == CODE_photo_empty) {
    return nullptr;
  }

  auto photo = std::make_shared<tgl_photo>();
  photo->id = DS_LVAL(DS_P->id);
  //photo->refcnt = 1;

  photo->access_hash = DS_LVAL(DS_P->access_hash);
  //photo->user_id = DS_LVAL(DS_P->user_id);
  photo->date = DS_LVAL(DS_P->date);
  //photo->caption = NULL;//DS_STR_DUP (DS_P->caption);
  /*if (DS_P->geo) {
    tglf_fetch_geo (&P->geo, DS_P->geo);
  }*/

  int sizes_num = DS_LVAL(DS_P->sizes->cnt);
  photo->sizes.resize(sizes_num);
  for (int i = 0; i < sizes_num; ++i) {
    photo->sizes[i] = tglf_fetch_photo_size(DS_P->sizes->data[i]);
  }

  return photo;
}

std::shared_ptr<tgl_document> tglf_fetch_alloc_video(const tl_ds_video *DS_V) {
  if (!DS_V) {
    return nullptr;
  }
  
  if (DS_V->magic == CODE_video_empty) {
    return nullptr;
  }

  auto document = std::make_shared<tgl_document>();
  document->id = DS_LVAL(DS_V->id);

  document->flags = TGLDF_VIDEO;

  document->access_hash = DS_LVAL(DS_V->access_hash);
  //document->user_id = DS_LVAL(DS_V->user_id);
  document->date = DS_LVAL(DS_V->date);
  //document->caption = NULL;//DS_STR_DUP (DS_V->caption);
  document->duration = DS_LVAL(DS_V->duration);
  document->mime_type = "video/";//DS_STR_DUP (DS_V->mime_type);
  document->size = DS_LVAL(DS_V->size);

  if (DS_V->thumb && DS_V->thumb->magic != CODE_photo_size_empty) {
    document->thumb = tglf_fetch_photo_size(DS_V->thumb);
  }

  document->dc_id = DS_LVAL(DS_V->dc_id);
  document->w = DS_LVAL(DS_V->w);
  document->h = DS_LVAL(DS_V->h);

  return document;
}

std::shared_ptr<tgl_document> tglf_fetch_alloc_audio(const tl_ds_audio *DS_A) {
  if (!DS_A) {
    return nullptr;
  }
  
  if (DS_A->magic == CODE_audio_empty) {
    return nullptr;
  }

  auto document = std::make_shared<tgl_document>();
  document->id = DS_LVAL(DS_A->id);
  document->flags = TGLDF_AUDIO;

  document->access_hash = DS_LVAL(DS_A->access_hash);
  //document->user_id = DS_LVAL(DS_A->user_id);
  document->date = DS_LVAL(DS_A->date);
  document->duration = DS_LVAL(DS_A->duration);
  if (DS_A->mime_type && DS_A->mime_type->data) {
    document->mime_type = std::string(DS_A->mime_type->data, DS_A->mime_type->len);
  }
  document->size = DS_LVAL(DS_A->size);
  document->dc_id = DS_LVAL(DS_A->dc_id);

  return document;
}

void tglf_fetch_document_attribute (const std::shared_ptr<tgl_document>& D, struct tl_ds_document_attribute *DS_DA) {
  switch (DS_DA->magic) {
  case CODE_document_attribute_image_size:
    D->flags |= TGLDF_IMAGE;
    D->w = DS_LVAL (DS_DA->w);
    D->h = DS_LVAL (DS_DA->h);
    return;
  case CODE_document_attribute_animated:
    D->flags |= TGLDF_ANIMATED;
    return;
  case CODE_document_attribute_sticker:
    D->flags |= TGLDF_STICKER;
    return;
  case CODE_document_attribute_video:
    D->flags |= TGLDF_VIDEO;
    D->duration = DS_LVAL (DS_DA->duration);
    D->w = DS_LVAL (DS_DA->w);
    D->h = DS_LVAL (DS_DA->h);
    return;
  case CODE_document_attribute_audio:
    D->flags |= TGLDF_AUDIO;
    D->duration = DS_LVAL (DS_DA->duration);
    return;
  case CODE_document_attribute_filename:
    if (DS_DA->file_name && DS_DA->file_name->data) {
        D->caption = std::string(DS_DA->file_name->data, DS_DA->file_name->len);
    }
    return;
  default:
    assert (0);
  }
}

std::shared_ptr<tgl_document> tglf_fetch_alloc_document(const tl_ds_document *DS_D) {
  if (!DS_D) {
    return nullptr;
  }
  
  if (DS_D->magic == CODE_document_empty) {
    return nullptr;
  }

  auto document = std::make_shared<tgl_document>();
  document->id = DS_LVAL (DS_D->id);
  document->access_hash = DS_LVAL (DS_D->access_hash);
  //D->user_id = DS_LVAL (DS_D->user_id);
  document->date = DS_LVAL (DS_D->date);
  if (DS_D->mime_type && DS_D->mime_type->data) {
    document->mime_type = std::string(DS_D->mime_type->data, DS_D->mime_type->len);
  }
  document->size = DS_LVAL (DS_D->size);
  document->dc_id = DS_LVAL (DS_D->dc_id);

  if (DS_D->thumb && DS_D->thumb->magic != CODE_photo_size_empty) {
    document->thumb = tglf_fetch_photo_size (DS_D->thumb);
  }

  if (DS_D->attributes) {
    for (int i = 0; i < DS_LVAL (DS_D->attributes->cnt); i++) {
      tglf_fetch_document_attribute (document, DS_D->attributes->data[i]);
    }
  }

  return document;
}

static std::shared_ptr<tgl_webpage> tglf_fetch_alloc_webpage(const tl_ds_web_page *DS_W) {
  if (!DS_W) {
    return nullptr;
  }

  auto webpage = std::make_shared<tgl_webpage>();
  webpage->id = DS_LVAL(DS_W->id);
  //webpage->refcnt = 1;

  if (DS_W->url && DS_W->url->data) {
    webpage->url = std::string(DS_W->url->data, DS_W->url->len);
  }

  if (DS_W->display_url && DS_W->display_url->data) {
    webpage->display_url = std::string(DS_W->display_url->data, DS_W->display_url->len);
  }

  if (DS_W->type && DS_W->type->data) {
    webpage->type = std::string(DS_W->type->data, DS_W->type->len);
  }

  if (DS_W->title && DS_W->title->data) {
    webpage->title = std::string(DS_W->title->data, DS_W->title->len);
  }

  webpage->photo = tglf_fetch_alloc_photo(DS_W->photo);

  if (DS_W->description && DS_W->description->data) {
    webpage->description = std::string(DS_W->description->data, DS_W->description->len);
  }

  if (DS_W->embed_url && DS_W->embed_url->data) {
    webpage->embed_url = std::string(DS_W->embed_url->data, DS_W->embed_url->len);
  }

  if (DS_W->embed_type && DS_W->embed_type->data) {
    webpage->embed_type = std::string(DS_W->embed_type->data, DS_W->embed_type->len);
  }

  webpage->embed_width = DS_LVAL(DS_W->embed_width);
  webpage->embed_height = DS_LVAL(DS_W->embed_height);
  webpage->duration = DS_LVAL(DS_W->duration);

  if (DS_W->author && DS_W->author->data) {
    webpage->author = std::string(DS_W->author->data, DS_W->author->len);
  }

  return webpage;
}

std::shared_ptr<tgl_message_action> tglf_fetch_message_action(const tl_ds_message_action *DS_MA) {
  if (!DS_MA) {
    return nullptr;
  }

  switch (DS_MA->magic) {
  case CODE_message_action_empty:
    return std::make_shared<tgl_message_action_none>();
  /*case CODE_message_action_geo_chat_create:
    {
      M->type = tgl_message_action_geo_chat_create;
      assert (0);
    }
    break;*/
  /*case CODE_message_action_geo_chat_checkin:
    M->type = tgl_message_action_geo_chat_checkin;
    break;*/
  case CODE_message_action_chat_create:
  {
    auto action = std::make_shared<tgl_message_action_chat_create>();
    if (DS_MA->title && DS_MA->title->data) {
      action->title = std::string(DS_MA->title->data, DS_MA->title->len);
    }
    action->users.resize(DS_LVAL(DS_MA->users->cnt));
    for (size_t i = 0; i < action->users.size(); ++i) {
      action->users[i] = DS_LVAL(DS_MA->users->data[i]);
    }
    return action;
  }
  case CODE_message_action_chat_edit_title:
  {
    auto action = std::make_shared<tgl_message_action_chat_edit_title>();
    if (DS_MA->title && DS_MA->title->data) {
      action->new_title = std::string(DS_MA->title->data, DS_MA->title->len);
    }
    return action;
  }
  case CODE_message_action_chat_edit_photo:
    return std::make_shared<tgl_message_action_chat_edit_photo>(tglf_fetch_alloc_photo(DS_MA->photo));
  case CODE_message_action_chat_delete_photo:
    return std::make_shared<tgl_message_action_chat_delete_photo>();
  case CODE_message_action_chat_add_user:
  {
    auto action = std::make_shared<tgl_message_action_chat_add_users>();
    action->users.resize(DS_LVAL(DS_MA->users->cnt));
    for (size_t i = 0; i < action->users.size(); ++i) {
      action->users[i] = DS_LVAL(DS_MA->users->data[i]);
    }
    return action;
  }
  case CODE_message_action_chat_delete_user:
    return std::make_shared<tgl_message_action_chat_delete_user>(DS_LVAL(DS_MA->user_id));
  case CODE_message_action_chat_joined_by_link:
    return std::make_shared<tgl_message_action_chat_add_user_by_link>(DS_LVAL(DS_MA->inviter_id));
  case CODE_message_action_channel_create:
  {
    auto action = std::make_shared<tgl_message_action_channel_create>();
    if (DS_MA->title && DS_MA->title->data) {
      action->title = std::string(DS_MA->title->data, DS_MA->title->len);
    }
  }
  case CODE_message_action_chat_migrate_to:
    return std::make_shared<tgl_message_action_chat_migrate_to>();
  case CODE_message_action_channel_migrate_from:
  {
    auto action = std::make_shared<tgl_message_action_channel_migrate_from>();
    if (DS_MA->title && DS_MA->title->data) {
      action->title = std::string(DS_MA->title->data, DS_MA->title->len);
    }
    return action;
  }
  default:
    assert (0);
    return nullptr;
  }
}

void tglf_fetch_alloc_message_short (struct tl_ds_updates *DS_U) {
  tgl_peer_id_t peer_id = TGL_MK_USER (DS_LVAL (DS_U->user_id));

  tgl_message_id_t msg_id = tgl_peer_id_to_msg_id (peer_id, DS_LVAL (DS_U->id));
  //struct tgl_message *M = (struct tgl_message *)talloc0 (sizeof (*M));
  //M->permanent_id = msg_id;

  //int flags = M->flags & 0xffff;
  int flags = 0;

  //if (M->flags & TGLMF_PENDING) {
  //  M->flags ^= TGLMF_PENDING;
  //}

  if (!(flags & TGLMF_CREATED)) {
    flags |= TGLMF_CREATE | TGLMF_CREATED;
  }

  int f = DS_LVAL (DS_U->flags);

  if (f & 1) {
    flags |= TGLMF_UNREAD;
  }
  if (f & 2) {
    flags |= TGLMF_OUT;
  }
  if (f & 16) {
    flags |= TGLMF_MENTION;
  }

  struct tl_ds_message_media A;
  A.magic = CODE_message_media_empty;

  tgl_peer_id_t our_id = tgl_state::instance()->our_id();

  tgl_peer_id_t fwd_from_id;
  if (DS_U->fwd_from_id) {
    fwd_from_id = tglf_fetch_peer_id (DS_U->fwd_from_id);
  } else {
    fwd_from_id = TGL_MK_USER (0);
  }

#if 0
  bl_do_edit_message (&msg_id, 
    (f & 2) ? &our_id : &peer_id,
    (f & 2) ? &peer_id : &our_id,
    DS_U->fwd_from_id ? &fwd_from_id : NULL,
    DS_U->fwd_date,
    DS_U->date,
    DS_STR (DS_U->message),
    &A,
    NULL,
    DS_U->reply_to_msg_id,
    NULL, 
    (void *)DS_U->entities,
    flags
  );
#endif

  DS_CSTR (msg_text, DS_U->message);
  tglm_message_create (&msg_id,
          (f & 2) ? &our_id : &peer_id,
          (f & 2) ? &peer_id : &our_id,
          DS_U->fwd_from_id ? &fwd_from_id : NULL,
          DS_U->fwd_date,
          DS_U->date,
          msg_text,
          &A,
          NULL,
          DS_U->reply_to_msg_id,
          NULL,
          flags
          );
  free(msg_text);
}

void tglf_fetch_alloc_message_short_chat (struct tl_ds_updates *DS_U) {
  tgl_peer_id_t from_id = TGL_MK_USER (DS_LVAL (DS_U->from_id));
  tgl_peer_id_t to_id = TGL_MK_CHAT (DS_LVAL (DS_U->chat_id));
  
  tgl_message_id_t msg_id = tgl_peer_id_to_msg_id (to_id, DS_LVAL (DS_U->id));
  //struct tgl_message *M = (struct tgl_message *)talloc0 (sizeof (*M));
  //M->permanent_id = msg_id;

  //int flags = M->flags & 0xffff;
  int flags = 0;
  
  //if (M->flags & TGLMF_PENDING) {
  //  M->flags ^= TGLMF_PENDING;
  //}

  if (!(flags & TGLMF_CREATED)) {
    flags |= TGLMF_CREATE | TGLMF_CREATED;
  }

  int f = DS_LVAL (DS_U->flags);

  if (f & 1) {
    flags |= TGLMF_UNREAD;
  }
  if (f & 2) {
    flags |= TGLMF_OUT;
  }
  if (f & 16) {
    flags |= TGLMF_MENTION;
  }

  struct tl_ds_message_media A;
  A.magic = CODE_message_media_empty;

  tgl_peer_id_t fwd_from_id;
  if (DS_U->fwd_from_id) {
    fwd_from_id = tglf_fetch_peer_id (DS_U->fwd_from_id);
  } else {
    fwd_from_id = TGL_MK_USER (0);
  }

#if 0
  bl_do_edit_message (&msg_id,
    &from_id,
    &to_id,
    DS_U->fwd_from_id ? &fwd_from_id : NULL,
    DS_U->fwd_date,
    DS_U->date,
    DS_STR (DS_U->message),
    &A,
    NULL,
    DS_U->reply_to_msg_id,
    NULL,
    NULL,
    flags
  );
#endif

  DS_CSTR (msg_text, DS_U->message);
  tglm_message_create (&msg_id,
      &from_id,
      &to_id,
      DS_U->fwd_from_id ? &fwd_from_id : NULL,
      DS_U->fwd_date,
      DS_U->date,
      msg_text,
      &A,
      NULL,
      DS_U->reply_to_msg_id,
      NULL,
      flags
      );
  free(msg_text);
}


std::shared_ptr<tgl_message_media> tglf_fetch_message_media(const tl_ds_message_media *DS_MM) {
  if (!DS_MM) {
    return nullptr;
  }

  switch (DS_MM->magic) {
  case CODE_message_media_empty:
    return std::make_shared<tgl_message_media_none>();
  case CODE_message_media_photo:
  case CODE_message_media_photo_l27:
  {
    auto media = std::make_shared<tgl_message_media_photo>();
    media->photo = tglf_fetch_alloc_photo(DS_MM->photo);
    if (DS_MM->caption && DS_MM->caption->data) {
      media->caption = std::string(DS_MM->caption->data, DS_MM->caption->len);
    }
    return media;
  }
  case CODE_message_media_video:
  case CODE_message_media_video_l27:
  {
    auto media = std::make_shared<tgl_message_media_video>();
    media->document = tglf_fetch_alloc_video(DS_MM->video);
    if (DS_MM->caption && DS_MM->caption->data) {
      media->caption = std::string(DS_MM->caption->data, DS_MM->caption->len);
    }
    return media;
  }
  case CODE_message_media_audio:
  {
    auto media = std::make_shared<tgl_message_media_audio>();
    media->document = tglf_fetch_alloc_audio(DS_MM->audio);
    if (DS_MM->caption && DS_MM->caption->data) {
      media->caption = std::string(DS_MM->caption->data, DS_MM->caption->len);
    }
    return media;
  }
  case CODE_message_media_document:
  {
    auto media = std::make_shared<tgl_message_media_document>();
    media->document = tglf_fetch_alloc_document(DS_MM->document);
    if (DS_MM->caption && DS_MM->caption->data) {
      media->caption = std::string(DS_MM->caption->data, DS_MM->caption->len);
    }
    return media;
  }
  case CODE_message_media_geo:
  {
    auto media = std::make_shared<tgl_message_media_geo>();
    tglf_fetch_geo(&media->geo, DS_MM->geo);
    return media;
  }
  case CODE_message_media_contact:
  {
    auto media = std::make_shared<tgl_message_media_contact>();
    if (DS_MM->phone_number && DS_MM->phone_number->data) {
      media->phone = std::string(DS_MM->phone_number->data, DS_MM->phone_number->len);
    }
    if (DS_MM->first_name && DS_MM->first_name->data) {
      media->first_name = std::string(DS_MM->first_name->data, DS_MM->first_name->len);
    }
    if (DS_MM->last_name && DS_MM->last_name->data) {
      media->last_name = std::string(DS_MM->last_name->data, DS_MM->last_name->len);
    }
    media->user_id = DS_LVAL(DS_MM->user_id);
    return media;
  }
  case CODE_message_media_web_page:
  {
    auto media = std::make_shared<tgl_message_media_webpage>();
    media->webpage = tglf_fetch_alloc_webpage(DS_MM->webpage);
    return media;
  }
  case CODE_message_media_venue:
  {
    auto media = std::make_shared<tgl_message_media_venue>();
    tglf_fetch_geo(&media->geo, DS_MM->geo);
    if (DS_MM->title && DS_MM->title->data) {
      media->title = std::string(DS_MM->title->data, DS_MM->title->len);
    }
    if (DS_MM->address && DS_MM->address->data) {
      media->address = std::string(DS_MM->address->data, DS_MM->address->len);
    }
    if (DS_MM->provider && DS_MM->provider->data) {
      media->provider = std::string(DS_MM->provider->data, DS_MM->provider->len);
    }
    if (DS_MM->venue_id && DS_MM->venue_id->data) {
      media->venue_id = std::string(DS_MM->venue_id->data, DS_MM->venue_id->len);
    }
    return media;
  }
  case CODE_message_media_unsupported:
    return std::make_shared<tgl_message_media_unsupported>();
  default:
    assert (0);
    return nullptr;
  }
}

std::shared_ptr<tgl_message_media> tglf_fetch_message_media_encrypted(const tl_ds_decrypted_message_media *DS_DMM) {
  if (!DS_DMM) {
    return nullptr;
  }

  switch (DS_DMM->magic) {
  case CODE_decrypted_message_media_empty:
    return std::make_shared<tgl_message_media_none>();
  case CODE_decrypted_message_media_photo:
  case CODE_decrypted_message_media_video:
  case CODE_decrypted_message_media_video_l12:
  case CODE_decrypted_message_media_document:
  case CODE_decrypted_message_media_audio:
  {
    //M->type = CODE_decrypted_message_media_video;
    auto media = std::make_shared<tgl_message_media_document_encr>();

    media->encr_document = std::make_shared<tgl_encr_document>();

    std::string default_mime;
    switch (DS_DMM->magic) {
    case CODE_decrypted_message_media_photo:
        media->encr_document->flags = TGLDF_IMAGE;
        media->encr_document->mime_type = "image/jpeg"; // Default mime in case there is no mime from the message media
        break;
    case CODE_decrypted_message_media_video:
    case CODE_decrypted_message_media_video_l12:
        media->encr_document->flags = TGLDF_VIDEO;
        break;
    case CODE_decrypted_message_media_document:
        //media->encr_document->flags = TGLDF_DOCUMENT;
        break;
    case CODE_decrypted_message_media_audio:
        media->encr_document->flags = TGLDF_AUDIO;
        break;
    }

    media->encr_document->w = DS_LVAL(DS_DMM->w);
    media->encr_document->h = DS_LVAL(DS_DMM->h);
    media->encr_document->size = DS_LVAL(DS_DMM->size);
    media->encr_document->duration = DS_LVAL(DS_DMM->duration);
    if (DS_DMM->mime_type && DS_DMM->mime_type->data) {
      media->encr_document->mime_type = std::string(DS_DMM->mime_type->data, DS_DMM->mime_type->len);
    }
    if (DS_DMM->thumb && DS_DMM->magic != CODE_photo_size_empty) {
      media->encr_document->thumb = tglf_fetch_photo_size(DS_DMM->thumb);
    }

    media->encr_document->key.resize(32);
    str_to_32 (media->encr_document->key.data(), DS_STR(DS_DMM->key));
    media->encr_document->iv.resize(32);
    str_to_32 (media->encr_document->iv.data(), DS_STR(DS_DMM->iv));

    return media;
  }
  case CODE_decrypted_message_media_geo_point:
  {
    auto media = std::make_shared<tgl_message_media_geo>();
    media->geo.latitude = DS_LVAL(DS_DMM->latitude);
    media->geo.longitude = DS_LVAL(DS_DMM->longitude);
    return media;
  }
  case CODE_decrypted_message_media_contact:
  {
    auto media = std::make_shared<tgl_message_media_contact>();
    if (DS_DMM->phone_number && DS_DMM->phone_number->data) {
      media->phone = std::string(DS_DMM->phone_number->data, DS_DMM->phone_number->len);
    }
    if (DS_DMM->first_name && DS_DMM->first_name->data) {
      media->first_name = std::string(DS_DMM->first_name->data, DS_DMM->first_name->len);
    }
    if (DS_DMM->last_name && DS_DMM->last_name->data) {
      media->last_name = std::string(DS_DMM->last_name->data, DS_DMM->last_name->len);
    }
    media->user_id = DS_LVAL(DS_DMM->user_id);
    return media;
  }
  default:
    assert (0);
    return nullptr;
  }
}

std::shared_ptr<tgl_message_action> tglf_fetch_message_action_encrypted(const tl_ds_decrypted_message_action *DS_DMA) {
  if (!DS_DMA) {
    return nullptr;
  }
  
  switch (DS_DMA->magic) {
  case CODE_decrypted_message_action_set_message_t_t_l:
    return std::make_shared<tgl_message_action_set_message_ttl>(DS_LVAL(DS_DMA->ttl_seconds));
  case CODE_decrypted_message_action_read_messages: 
    return std::make_shared<tgl_message_action_read_messages>(DS_LVAL(DS_DMA->random_ids->cnt));
#if 0 // FIXME
    for (int i = 0; i < M->read_cnt; i++) {
      tgl_message_id_t id;
      id.peer_type = TGL_PEER_RANDOM_ID;
      id.id = DS_LVAL (DS_DMA->random_ids->data[i]);
      struct tgl_message *N = tgl_message_get (&id);
      if (N) {
        N->flags &= ~TGLMF_UNREAD;
      }
    }
#endif
  case CODE_decrypted_message_action_delete_messages: 
    return std::make_shared<tgl_message_action_delete_messages>();
  case CODE_decrypted_message_action_screenshot_messages: 
    return std::make_shared<tgl_message_action_screenshot_messages>(DS_LVAL(DS_DMA->random_ids->cnt));
  case CODE_decrypted_message_action_notify_layer: 
    return std::make_shared<tgl_message_action_notify_layer>(DS_LVAL(DS_DMA->layer));
  case CODE_decrypted_message_action_flush_history:
    return std::make_shared<tgl_message_action_flush_history>();
  case CODE_decrypted_message_action_typing:
    return std::make_shared<tgl_message_action_typing>(tglf_fetch_typing(DS_DMA->action));
  case CODE_decrypted_message_action_resend:
    return std::make_shared<tgl_message_action_resend>(DS_LVAL(DS_DMA->start_seq_no), DS_LVAL(DS_DMA->end_seq_no));
  case CODE_decrypted_message_action_noop:
    return std::make_shared<tgl_message_action_noop>();
  case CODE_decrypted_message_action_request_key:
  {
    auto action = std::make_shared<tgl_message_action_request_key>();
    action->exchange_id = DS_LVAL(DS_DMA->exchange_id);
    action->g_a.resize(256);
    str_to_256(action->g_a.data(), DS_STR(DS_DMA->g_a));
    return action;
  }
  case CODE_decrypted_message_action_accept_key:
  {
    auto action = std::make_shared<tgl_message_action_accept_key>();
    action->exchange_id = DS_LVAL(DS_DMA->exchange_id);
    action->g_a.resize(256);
    str_to_256(action->g_a.data(), DS_STR(DS_DMA->g_b));
    action->key_fingerprint = DS_LVAL(DS_DMA->key_fingerprint);
    return action;
  }
  case CODE_decrypted_message_action_commit_key:
    return std::make_shared<tgl_message_action_commit_key>(DS_LVAL(DS_DMA->exchange_id), DS_LVAL(DS_DMA->key_fingerprint));
  case CODE_decrypted_message_action_abort_key:
    return std::make_shared<tgl_message_action_abort_key>(DS_LVAL(DS_DMA->exchange_id));
  default:
    assert (0);
    return nullptr;
  }
}

static std::shared_ptr<tgl_message_entity> tglf_fetch_message_entity(const tl_ds_message_entity* DS_ME) {
  auto entity = std::make_shared<tgl_message_entity>();
  entity->start = DS_LVAL(DS_ME->offset);
  entity->length = DS_LVAL(DS_ME->length);
  switch (DS_ME->magic) {
  case CODE_message_entity_unknown:
    entity->type = tgl_message_entity_unknown;
    break;
  case CODE_message_entity_mention:
    entity->type = tgl_message_entity_mention;
    break;
  case CODE_message_entity_hashtag:
    entity->type = tgl_message_entity_hashtag;
    break;
  case CODE_message_entity_bot_command:
    entity->type = tgl_message_entity_bot_command;
    break;
  case CODE_message_entity_url:
    entity->type = tgl_message_entity_url;
    break;
  case CODE_message_entity_email:
    entity->type = tgl_message_entity_email;
    break;
  case CODE_message_entity_bold:
    entity->type = tgl_message_entity_bold;
    break;
  case CODE_message_entity_italic:
    entity->type = tgl_message_entity_italic;
    break;
  case CODE_message_entity_code:
    entity->type = tgl_message_entity_code;
    break;
  case CODE_message_entity_pre:
    entity->type = tgl_message_entity_pre;
    break;
  case CODE_message_entity_text_url:
    entity->type = tgl_message_entity_text_url;
    if (DS_ME->url && DS_ME->url->data) {
        entity->text_url = std::string(DS_ME->url->data, DS_ME->url->len);
    }
    break;
  default:
    assert (0);
  }
  return entity;
}

void tglf_fetch_message_entities (const std::shared_ptr<tgl_message>& M, struct tl_ds_vector *DS) {
  int entities_num = DS_LVAL (DS->f1);
  M->entities.resize(entities_num);
  for (int i = 0; i < entities_num; i++) {
    struct tl_ds_message_entity *D = (struct tl_ds_message_entity *)DS->f2[i];
    M->entities[i] = tglf_fetch_message_entity(D);
  }
}

std::shared_ptr<tgl_message> tglf_fetch_alloc_message(struct tl_ds_message *DS_M, int *new_msg) {
  if (new_msg) {
    *new_msg = 0;
  }
  if (!DS_M || DS_M->magic == CODE_message_empty) { 
    TGL_NOTICE("empty message");
    return NULL; 
  }

  tgl_peer_id_t to_id = tglf_fetch_peer_id (DS_M->to_id);

  tgl_peer_id_t from_id;
  if (DS_M->from_id) {
    from_id = TGL_MK_USER (DS_LVAL (DS_M->from_id));
  } else {
    from_id = TGL_MK_USER (0);
  }

  tgl_message_id_t msg_id;
  if (DS_M->from_id && !tgl_cmp_peer_id (to_id, tgl_state::instance()->our_id())) {
    msg_id = tgl_peer_id_to_msg_id (from_id, DS_LVAL (DS_M->id));
  } else {
    msg_id = tgl_peer_id_to_msg_id (to_id, DS_LVAL (DS_M->id));
  }

  if (new_msg) {
    *new_msg = 1;
  }
  int flags = 0;
  if (DS_LVAL (DS_M->flags) & 1) {
    flags |= TGLMF_UNREAD;
  }
  if (DS_LVAL (DS_M->flags) & 2) {
    flags |= TGLMF_OUT;
  }
  if (DS_LVAL (DS_M->flags) & 16) {
    flags |= TGLMF_MENTION;
  }

  tgl_peer_id_t fwd_from_id;
  if (DS_M->fwd_from_id) {
    fwd_from_id = tglf_fetch_peer_id (DS_M->fwd_from_id);
  } else {
    fwd_from_id = TGL_MK_USER (0);
  }

#if 0
  bl_do_edit_message (&msg_id,
      DS_M->from_id ? &from_id : NULL,
      &to_id,
      DS_M->fwd_from_id ? &fwd_from_id : NULL,
      DS_M->fwd_date,
      DS_M->date,
      DS_STR (DS_M->message),
      DS_M->media,
      DS_M->action,
      DS_M->reply_to_msg_id,
      DS_M->reply_markup,
      (void *)DS_M->entities,
      flags | TGLMF_CREATE | TGLMF_CREATED
      );
#endif
  DS_CSTR (msg_text, DS_M->message);
  std::shared_ptr<tgl_message> M = tglm_message_create(&msg_id,
      DS_M->from_id ? &from_id : NULL,
      &to_id,
      DS_M->fwd_from_id ? &fwd_from_id : NULL,
      DS_M->fwd_date,
      DS_M->date,
      msg_text,
      DS_M->media,
      DS_M->action,
      DS_M->reply_to_msg_id,
      DS_M->reply_markup,
      flags
      );
  free(msg_text);
  return M;
}

static int *decr_ptr;
static int *decr_end;

static int decrypt_encrypted_message (struct tgl_secret_chat* secret_chat) {
  int *msg_key = decr_ptr;
  decr_ptr += 4;
  assert (decr_ptr < decr_end);
  static unsigned char sha1a_buffer[20];
  static unsigned char sha1b_buffer[20];
  static unsigned char sha1c_buffer[20];
  static unsigned char sha1d_buffer[20];
 
  static unsigned char buf[64];

  const int *e_key = secret_chat->exchange_state != tgl_sce_committed
      ? reinterpret_cast<const int*>(secret_chat->key()) : secret_chat->exchange_key;

  memcpy (buf, msg_key, 16);
  memcpy (buf + 16, e_key, 32);
  TGLC_sha1 (buf, 48, sha1a_buffer);
  
  memcpy (buf, e_key + 8, 16);
  memcpy (buf + 16, msg_key, 16);
  memcpy (buf + 32, e_key + 12, 16);
  TGLC_sha1 (buf, 48, sha1b_buffer);
  
  memcpy (buf, e_key + 16, 32);
  memcpy (buf + 32, msg_key, 16);
  TGLC_sha1 (buf, 48, sha1c_buffer);
  
  memcpy (buf, msg_key, 16);
  memcpy (buf + 16, e_key + 24, 32);
  TGLC_sha1 (buf, 48, sha1d_buffer);

  static unsigned char key[32];
  memcpy (key, sha1a_buffer + 0, 8);
  memcpy (key + 8, sha1b_buffer + 8, 12);
  memcpy (key + 20, sha1c_buffer + 4, 12);

  static unsigned char iv[32];
  memcpy (iv, sha1a_buffer + 8, 12);
  memcpy (iv + 12, sha1b_buffer + 0, 8);
  memcpy (iv + 20, sha1c_buffer + 16, 4);
  memcpy (iv + 24, sha1d_buffer + 0, 8);

  TGLC_aes_key aes_key;
  TGLC_aes_set_decrypt_key (key, 256, &aes_key);
  TGLC_aes_ige_encrypt (reinterpret_cast<const unsigned char*>(decr_ptr),
          reinterpret_cast<unsigned char*>(decr_ptr), 4 * (decr_end - decr_ptr), &aes_key, iv, 0);
  memset (&aes_key, 0, sizeof (aes_key));

  int x = *(decr_ptr);
  if (x < 0 || (x & 3)) {
    return -1;
  }
  assert (x >= 0 && !(x & 3));
  TGLC_sha1 (reinterpret_cast<const unsigned char*>(decr_ptr), 4 + x, sha1a_buffer);

    if (memcmp (sha1a_buffer + 4, msg_key, 16)) {
        return -1;
    }
    return 0;
}

std::shared_ptr<tgl_secret_message> tglf_fetch_encrypted_message(const tl_ds_encrypted_message* DS_EM) {
    if (!DS_EM) {
        return nullptr;
    }

    std::shared_ptr<tgl_secret_chat> secret_chat = tgl_state::instance()->secret_chat_for_id(TGL_MK_ENCR_CHAT(DS_LVAL(DS_EM->chat_id)));
    if (!secret_chat || secret_chat->state != sc_ok) {
        TGL_WARNING("encrypted message to unknown chat, dropping");
        return nullptr;
    }

    tgl_message_id_t msg_id = tgl_peer_id_to_msg_id(secret_chat->id, DS_LVAL(DS_EM->random_id));
#if 0
    struct tgl_message *M = tgl_message_get (&msg_id);
    if (!M) {
      M = static_cast<tgl_message*>(calloc(1, sizeof (*M)));
      M->permanent_id = msg_id;
      tglm_message_insert_tree (M);
      tgl_state::instance()->messages_allocated ++;
      assert (tgl_message_get (&msg_id) == M);
    }

    int is_new = !(M->flags & TGLMF_CREATED);
    if (!is_new) {
      return M;
    }
#endif

    decr_ptr = reinterpret_cast<int*>(DS_EM->bytes->data);
    decr_end = decr_ptr + (DS_EM->bytes->len / 4);

    if (secret_chat->exchange_state == tgl_sce_committed && secret_chat->key_fingerprint() == *(long long *)decr_ptr) {
        tgl_do_confirm_exchange(secret_chat, 0);
        assert (secret_chat->exchange_state == tgl_sce_none);
    }

    long long key_fingerprint = secret_chat->exchange_state != tgl_sce_committed ? secret_chat->key_fingerprint() : secret_chat->exchange_key_fingerprint;
    if (*(long long *)decr_ptr != key_fingerprint) {
        TGL_WARNING("Encrypted message with bad fingerprint to chat " << secret_chat->print_name);
        return nullptr;
    }

    decr_ptr += 2;

    if (decrypt_encrypted_message(secret_chat.get()) < 0) {
        TGL_WARNING("can not decrypt message");
        return nullptr;
    }

    int decrypted_data_length = *decr_ptr; // decrypted data length
    tgl_in_buffer in = { decr_ptr, decr_ptr + decrypted_data_length / 4 + 1 };
    auto result = fetch_int(&in);
    TGL_ASSERT_UNUSED(result, result == decrypted_data_length);

    std::shared_ptr<tgl_secret_message> secret_message;
    if (*in.ptr == CODE_decrypted_message_layer) {
        struct paramed_type decrypted_message_layer = TYPE_TO_PARAM(decrypted_message_layer);
        tgl_in_buffer skip_in = in;
        if (skip_type_decrypted_message_layer(&skip_in, &decrypted_message_layer) < 0 || skip_in.ptr != skip_in.end) {
            TGL_WARNING("can not fetch message");
            return nullptr;
        }

        struct tl_ds_decrypted_message_layer *DS_DML = fetch_ds_type_decrypted_message_layer(&in, &decrypted_message_layer);
        assert(DS_DML);

        struct tl_ds_decrypted_message *DS_DM = DS_DML->message;
        if (msg_id.id != DS_LVAL (DS_DM->random_id)) {
            TGL_ERROR("Incorrect message: id = " << msg_id.id << ", new_id = " << DS_LVAL (DS_DM->random_id));
            free_ds_type_decrypted_message_layer(DS_DML, &decrypted_message_layer);
            return nullptr;
        }

        tgl_peer_id_t from_id = TGL_MK_USER(secret_chat->user_id);
        tgl_peer_id_t to_id = tgl_state::instance()->our_id();

        secret_message = std::make_shared<tgl_secret_message>(
                tglm_create_encr_message(&msg_id,
                        &from_id,
                        &to_id,
                        DS_EM->date,
                        DS_STR(DS_DM->message),
                        DS_DM->media,
                        DS_DM->action,
                        DS_EM->file,
                        TGLMF_CREATE | TGLMF_CREATED | TGLMF_ENCRYPTED),
               DS_LVAL(DS_DML->layer), DS_LVAL(DS_DML->in_seq_no), DS_LVAL(DS_DML->out_seq_no));

        free_ds_type_decrypted_message_layer(DS_DML, &decrypted_message_layer);
    } else {
        // Pre-layer 17 encrypted message
        struct paramed_type decrypted_message = TYPE_TO_PARAM(decrypted_message);
        tgl_in_buffer skip_in = in;
        if (skip_type_decrypted_message(&skip_in, &decrypted_message) < 0 || skip_in.ptr != skip_in.end) {
            TGL_WARNING("can not fetch message");
            return NULL;
        }

        struct tl_ds_decrypted_message *DS_DM = fetch_ds_type_decrypted_message(&in, &decrypted_message);
        assert (DS_DM);

        int layer = 8; // default secret chat layer is 8
        if (DS_DM->action && DS_DM->action->magic == CODE_decrypted_message_action_notify_layer) {
            layer = *(DS_DM->action->layer);
        }

        tgl_peer_id_t from_id = TGL_MK_USER(secret_chat->user_id);
        tgl_peer_id_t to_id = tgl_state::instance()->our_id();

        secret_message = std::make_shared<tgl_secret_message>(
                tglm_create_encr_message(&msg_id,
                        &from_id,
                        &to_id,
                        DS_EM->date,
                        DS_STR(DS_DM->message),
                        DS_DM->media,
                        DS_DM->action,
                        DS_EM->file,
                        TGLMF_CREATE | TGLMF_CREATED | TGLMF_ENCRYPTED),
                layer, -1, -1);
    }

    return secret_message;
}

void tglf_fetch_encrypted_message_file(const std::shared_ptr<tgl_message_media>& M, const tl_ds_encrypted_file *DS_EF) {
  if (DS_EF->magic == CODE_encrypted_file_empty) {
      assert (M->type() != tgl_message_media_type_document_encr);
  } else {
      assert (M->type() == tgl_message_media_type_document_encr);
      if (M->type() != tgl_message_media_type_document_encr) {
          return;
      }

      auto media = std::static_pointer_cast<tgl_message_media_document_encr>(M);

      assert(media->encr_document);
      if (!media->encr_document) {
          return;
      }

      media->encr_document->id = DS_LVAL(DS_EF->id);
      media->encr_document->access_hash = DS_LVAL(DS_EF->access_hash);
      media->encr_document->size = DS_LVAL(DS_EF->size);
      media->encr_document->dc_id = DS_LVAL(DS_EF->dc_id);
      media->encr_document->key_fingerprint = DS_LVAL(DS_EF->key_fingerprint);
  }
}

#if 0
static int id_cmp (struct tgl_message *M1, struct tgl_message *M2) {
  if (M1->permanent_id.peer_type < M2->permanent_id.peer_type) { return -1; }
  if (M1->permanent_id.peer_type > M2->permanent_id.peer_type) { return 1; }
  if (M1->permanent_id.peer_id < M2->permanent_id.peer_id) { return -1; }
  if (M1->permanent_id.peer_id > M2->permanent_id.peer_id) { return 1; }
  if (M1->permanent_id.id < M2->permanent_id.id) { return -1; }
  if (M1->permanent_id.id > M2->permanent_id.id) { return 1; }
  else { return 0; }
}

static void increase_peer_size () {
    if (tgl_state::instance()->peer_num == tgl_state::instance()->peer_size) {
        int new_size = tgl_state::instance()->peer_size ? 2 * tgl_state::instance()->peer_size : 10;
        int old_size = tgl_state::instance()->peer_size;
        if (old_size) {
            tgl_state::instance()->Peers = trealloc (tgl_state::instance()->Peers, old_size * sizeof (void *), new_size * sizeof (void *));
        } else {
            tgl_state::instance()->Peers = talloc (new_size * sizeof (void *));
        }
        tgl_state::instance()->peer_size = new_size;
    }
}
#endif

void tglf_encrypted_message_received(const std::shared_ptr<tgl_secret_message>& secret_message) {
    const auto& message = secret_message->message;
    if (!(message->flags & TGLMF_CREATED)) {
        return;
    }

    std::shared_ptr<tgl_secret_chat> secret_chat = tgl_state::instance()->secret_chat_for_id(TGL_MK_ENCR_CHAT(message->permanent_id.peer_id));
    assert(secret_chat);

    int* our_in_seq_no_ptr = nullptr;
    int* ttl_ptr = nullptr;
    int in_seq_no = secret_message->in_seq_no;
    int out_seq_no = secret_message->out_seq_no;
    int layer = secret_message->layer;

    if (in_seq_no >=0 && out_seq_no >= 0) {
        if (out_seq_no / 2 < secret_chat->in_seq_no) {
            return;
        } else if (out_seq_no / 2 > secret_chat->in_seq_no) {
            TGL_WARNING("hole in seq in secret chat, expecting in_seq_no of " << secret_chat->in_seq_no << " but " << in_seq_no / 2 << " was received");
            // FIXME: enable requesting resending messages from the remote peer to fill the hole, probaly only need to make test cases and then uncomment the following code.
#if 0
           int start_seq_no = 2 * secret_chat->in_seq_no + (secret_chat->admin_id != tgl_get_peer_id(tgl_state::instance()->our_id()));
           int end_seq_no = out_seq_no - 2;
           if (end_seq_no >= start_seq_no) {
               std::cerr << "Requesting resend message from " << start_seq_no << " to " << end_seq_no << " for secret chat " << secret_chat->id.peer_id;
               tgl_do_send_encr_chat_request_resend(secret_chat, start_seq_no, end_seq_no);
           }
#else
            tgl_do_discard_secret_chat(secret_chat, [=](bool success, const std::shared_ptr<tgl_secret_chat>& secret_chat) {
                if (success) {
                    tgl_secret_chat_deleted(secret_chat);
                }
            });
#endif
            return;
        }

        if ((out_seq_no & 1)  != 1 - (secret_chat->admin_id == tgl_get_peer_id (tgl_state::instance()->our_id())) ||
            (in_seq_no & 1) != (secret_chat->admin_id == tgl_get_peer_id (tgl_state::instance()->our_id()))) {
            TGL_WARNING("bad msg admin");
            return;
        }

        if (in_seq_no / 2 > secret_chat->out_seq_no) {
            TGL_WARNING("in_seq_no " << in_seq_no / 2 << " of remote client is bigger than our out_seq_no of " << secret_chat->out_seq_no << ", dropping the message");
            return;
        }

        out_seq_no = out_seq_no / 2 + 1;
        our_in_seq_no_ptr = &out_seq_no;
    }

    auto action_type = message->action ? message->action->type() : tgl_message_action_type_none;
    if (action_type == tgl_message_action_type_request_key) {
        auto action = std::static_pointer_cast<tgl_message_action_request_key>(message->action);
        if (secret_chat->exchange_state == tgl_sce_none || (secret_chat->exchange_state == tgl_sce_requested && secret_chat->exchange_id > action->exchange_id )) {
            tgl_do_accept_exchange(secret_chat, action->exchange_id, action->g_a);
        } else {
            TGL_WARNING("secret_chatxchange: Incorrect state (received request, state = " << secret_chat->exchange_state << ")");
        }
    } else if (action_type == tgl_message_action_type_accept_key) {
        auto action = std::static_pointer_cast<tgl_message_action_accept_key>(message->action);
        if (secret_chat->exchange_state == tgl_sce_requested && secret_chat->exchange_id == action->exchange_id) {
            tgl_do_commit_exchange(secret_chat, action->g_a);
        } else {
            TGL_WARNING("secret_chatxchange: Incorrect state (received accept, state = " << secret_chat->exchange_state << ")");
        }
    } else if (action_type == tgl_message_action_type_commit_key) {
        auto action = std::static_pointer_cast<tgl_message_action_commit_key>(message->action);
        if (secret_chat->exchange_state == tgl_sce_accepted && secret_chat->exchange_id == action->exchange_id) {
            tgl_do_confirm_exchange(secret_chat, 1);
        } else {
            TGL_WARNING("secret_chatxchange: Incorrect state (received commit, state = " << secret_chat->exchange_state << ")");
        }
    } else if (action_type == tgl_message_action_type_abort_key) {
        auto action = std::static_pointer_cast<tgl_message_action_abort_key>(message->action);
        if (secret_chat->exchange_state != tgl_sce_none && secret_chat->exchange_id == action->exchange_id) {
            tgl_do_abort_exchange(secret_chat);
        } else {
            TGL_WARNING("secret_chatxchange: Incorrect state (received abort, state = " << secret_chat->exchange_state << ")");
        }
    } else if (action_type == tgl_message_action_type_notify_layer) {
        auto action = std::static_pointer_cast<tgl_message_action_notify_layer>(message->action);
        layer = action->layer;
    } else if (action_type == tgl_message_action_type_set_message_ttl) {
        auto action = std::static_pointer_cast<tgl_message_action_set_message_ttl>(message->action);
        ttl_ptr = &(action->ttl);
    }

    tgl_update_secret_chat(secret_chat, NULL, NULL, NULL, NULL, NULL, NULL, NULL, ttl_ptr, &layer, our_in_seq_no_ptr, TGL_FLAGS_UNCHANGED);
    tgl_state::instance()->callback()->new_message(message);
}

std::shared_ptr<tgl_bot_info> tglf_fetch_alloc_bot_info (struct tl_ds_bot_info *DS_BI) {
    if (!DS_BI || DS_BI->magic == CODE_bot_info_empty) { return NULL; }
    std::shared_ptr<tgl_bot_info> B = std::make_shared<tgl_bot_info>();
    B->version = DS_LVAL (DS_BI->version);
    if (DS_BI->share_text->data) {
       B->share_text = std::string(DS_BI->share_text->data, DS_BI->share_text->len);
    }

    if (DS_BI->description->data) {
        B->description = std::string(DS_BI->description->data, DS_BI->description->len);
    }

    int commands_num = DS_LVAL (DS_BI->commands->cnt);
    B->commands.resize(commands_num);
    for (int i = 0; i < commands_num; i++) {
        struct tl_ds_bot_command *BC = DS_BI->commands->data[i];
        B->commands[i] = std::make_shared<tgl_bot_command>();
        if (BC->command->data) {
            B->commands[i]->command = std::string(BC->command->data, BC->command->len);
        }
        if (BC->description->data) {
            B->commands[i]->description = std::string(BC->description->data, BC->description->len);
        }
    }
    return B;
}

std::shared_ptr<tgl_message_reply_markup> tglf_fetch_alloc_reply_markup(const tl_ds_reply_markup *DS_RM) {
    if (!DS_RM) {
        return nullptr;
    }

    auto reply_markup = std::make_shared<tgl_message_reply_markup>();
    reply_markup->flags = DS_LVAL(DS_RM->flags);
    int rows = DS_RM->rows ? DS_LVAL(DS_RM->rows->cnt) : 0;
    if (rows <= 0) {
        return reply_markup;
    }

    reply_markup->button_matrix.resize(rows);
    for (int i = 0; i < rows; ++i) {
        const tl_ds_keyboard_button_row* row = DS_RM->rows->data[i];
        int button_count = DS_LVAL(row->buttons->cnt);
        reply_markup->button_matrix[i].resize(button_count);
        for (int j = 0; j < button_count; ++j) {
            const tl_ds_keyboard_button* button = row->buttons->data[j];
            if (button && button->text && button->text->data) {
                reply_markup->button_matrix[i][j] = std::string(button->text->data, button->text->len);
            }
        }
    }

    return reply_markup;
}
/* }}} */

#if 0
void tglp_insert_encrypted_chat (tgl_peer_t *P) {
  tgl_state::instance()->encr_chats_allocated ++;
  tgl_state::instance()->peer_tree = tree_insert_peer (tgl_state::instance()->peer_tree, P, rand ());
  increase_peer_size ();
  tgl_state::instance()->Peers[tgl_state::instance()->peer_num ++] = P;
}

void tglp_insert_user (tgl_peer_t *P) {
  tgl_state::instance()->users_allocated ++;
  tgl_state::instance()->peer_tree = tree_insert_peer (tgl_state::instance()->peer_tree, P, rand ());
  increase_peer_size ();
  tgl_state::instance()->Peers[tgl_state::instance()->peer_num ++] = P;
}

void tglp_insert_chat (tgl_peer_t *P) {
  tgl_state::instance()->chats_allocated ++;
  tgl_state::instance()->peer_tree = tree_insert_peer (tgl_state::instance()->peer_tree, P, rand ());
  increase_peer_size ();
  tgl_state::instance()->Peers[tgl_state::instance()->peer_num ++] = P;
}

void tglp_insert_channel (tgl_peer_t *P) {
  tgl_state::instance()->channels_allocated ++;
  tgl_state::instance()->peer_tree = tree_insert_peer (tgl_state::instance()->peer_tree, P, rand ());
  increase_peer_size ();
  tgl_state::instance()->Peers[tgl_state::instance()->peer_num ++] = P;
}

void tgl_insert_empty_user (int uid) {
    tgl_peer_id_t id = TGL_MK_USER (uid);
    if (tgl_peer_get (id)) { return; }
    tgl_peer_t *P = (tgl_peer_t *)talloc0 (sizeof (*P));
    P->id = id;
}

void tgl_insert_empty_chat (int cid) {
    tgl_peer_id_t id = TGL_MK_CHAT (cid);
    if (tgl_peer_get (id)) { return; }
    tgl_peer_t *P = (tgl_peer_t *)talloc0 (sizeof (*P));
    P->id = id;
    tglp_insert_chat (P);
}
#endif

/* Messages {{{ */

#if 0
void tglm_message_add_peer ( struct tgl_message *M) {
  tgl_peer_id_t id;
  if (!tgl_cmp_peer_id (M->to_id, tgl_state::instance()->our_id())) {
    id = M->from_id;
  } else {
    id = M->to_id;
  }
  tgl_peer_t *P = (tgl_peer_t *)talloc0 (sizeof (*P));
  P->id = id;
  if (!P->last) {
    P->last = M;
    M->prev = M->next = 0;
  } else {
    if (tgl_get_peer_type (P->id) != TGL_PEER_ENCR_CHAT) {
      struct tgl_message *N = P->last;
      struct tgl_message *NP = 0;
      while (N && N->permanent_id.id > M->permanent_id.id) {
        NP = N;
        N = N->next;
      }
      if (N) {
        assert (N->permanent_id.id < M->permanent_id.id); 
      }
      M->next = N;
      M->prev = NP;
      if (N) { N->prev = M; }
      if (NP) { NP->next = M; }
      else { P->last = M; }
    } else {
      struct tgl_message *N = P->last;
      struct tgl_message *NP = 0;
      M->next = N;
      M->prev = NP;
      if (N) { N->prev = M; }
      if (NP) { NP->next = M; }
      else { P->last = M; }
    }
  }
}

void tglm_message_del_peer (struct tgl_message *M) {
  tgl_peer_id_t id;
  if (!tgl_cmp_peer_id (M->to_id, tgl_state::instance()->our_id())) {
    id = M->from_id;
  } else {
    id = M->to_id;
  }
  tgl_peer_t *P = tgl_peer_get (id);
  if (M->prev) {
    M->prev->next = M->next;
  }
  if (M->next) {
    M->next->prev = M->prev;
  }
  if (P && P->last == M) {
    P->last = M->next;
  }
}
#endif

std::shared_ptr<tgl_message> tglm_message_alloc(const tgl_message_id_t *id) {
    auto message = std::make_shared<tgl_message>();
    message->permanent_id = *id;
    return message;
}

std::shared_ptr<tgl_message> tglm_message_create(tgl_message_id_t *id, tgl_peer_id_t *from_id,
                                        tgl_peer_id_t *to_id, tgl_peer_id_t *fwd_from_id, int *fwd_date,
                                        int *date, const char *message,
                                        const tl_ds_message_media *media, const tl_ds_message_action *action,
                                        int *reply_id, struct tl_ds_reply_markup *reply_markup, int flags)
{
    std::shared_ptr<tgl_message> M = tglm_message_alloc(id);

    M->flags = flags;

    if (flags & TGLMF_TEMP_MSG_ID) {
        M->flags |= TGLMF_TEMP_MSG_ID;
    }

    if (from_id) {
        M->from_id = *from_id;
    }
    if (to_id) {
        M->to_id = *to_id;
        assert (to_id->peer_type != TGL_PEER_ENCR_CHAT);
    }

    if (date) {
        M->date = *date;
    }

    if (fwd_from_id) {
        M->fwd_from_id = *fwd_from_id;
        M->fwd_date = *fwd_date;
    }

    if (action) {
        M->action = tglf_fetch_message_action(action);
        M->flags |= TGLMF_SERVICE;
    }

    if (message && strlen(message) != 0) {
        M->message = message;
        assert (!(M->flags & TGLMF_SERVICE));
    }

    if (media) {
        M->media = tglf_fetch_message_media(media);
        assert (!(M->flags & TGLMF_SERVICE));
    }

    if (reply_id) {
        M->reply_id = DS_LVAL (reply_id);
    }

    if (reply_markup) {
        M->reply_markup = tglf_fetch_alloc_reply_markup (reply_markup);
    }
    tgl_state::instance()->callback()->new_message(M);
    return M;
}

static std::shared_ptr<tgl_message> create_or_edit_encr_message(
        const std::shared_ptr<tgl_message>& m,
        const tgl_message_id* id,
        const tgl_peer_id_t* from_id,
        const tgl_peer_id_t* to_id,
        const int* date,
        const char* message,
        int message_len,
        const tl_ds_decrypted_message_media* media,
        const tl_ds_decrypted_message_action* action,
        const tl_ds_encrypted_file* file,
        int flags)
{
    assert (!(flags & 0xfffe0000));

    std::shared_ptr<tgl_message> M = m;

    if (flags & (1 << 16)) {
      if (!M) {
        M = tglm_message_alloc(id);
      } else {
        assert (!(M->flags & TGLMF_CREATED));
      }
      assert (!(M->flags & TGLMF_CREATED));
    } else {
      assert (M->flags & TGLMF_CREATED);
    }

    assert (flags & TGLMF_CREATED);
    assert (flags & TGLMF_ENCRYPTED);

#if 0
    if ((M->flags & TGLMF_PENDING) && !(flags & TGLMF_PENDING)){
        tglm_message_remove_unsent(M);
    }

    if (!(M->flags & TGLMF_PENDING) && (flags & TGLMF_PENDING)){
        tglm_message_insert_unsent(M);
    }
#endif

    M->flags = flags & 0xffff;

    if (from_id) {
        M->from_id = *from_id;
    }

    if (to_id) {
        assert (flags & 0x10000);
        M->to_id = *to_id;
    }

    if (date) {
        M->date = *date;
    }

    std::shared_ptr<tgl_secret_chat> E = tgl_state::instance()->secret_chat_for_id(TGL_MK_ENCR_CHAT(M->permanent_id.peer_id));
    assert(E);

    if (action) {
        M->action = tglf_fetch_message_action_encrypted(action);
        M->flags |= TGLMF_SERVICE;
    }

    if (message) {
        M->message = std::string(message, message_len);
        assert(!(M->flags & TGLMF_SERVICE));
    }

    if (media) {
        M->media = tglf_fetch_message_media_encrypted(media);
        assert(!(M->flags & TGLMF_SERVICE));
    }

    if (file) {
        tglf_fetch_encrypted_message_file(M->media, file);
        //assert(!(M->flags & TGLMF_SERVICE));
    }

    if (action && !(M->flags & TGLMF_OUT) && M->action && M->action->type() == tgl_message_action_type_notify_layer) {
        E->layer = std::static_pointer_cast<tgl_message_action_notify_layer>(M->action)->layer;
    }

    if ((flags & TGLMF_CREATE) && (flags & TGLMF_OUT)) {
        E->out_seq_no++;
    }

#if 0
    if (flags & 0x10000) {
        tglm_message_insert(M);
    }
#endif

    return M;
}

std::shared_ptr<tgl_message> tglm_create_encr_message(
        const tgl_message_id* id,
        const tgl_peer_id_t* from_id,
        const tgl_peer_id_t* to_id,
        const int* date,
        const char* message,
        int message_len,
        const tl_ds_decrypted_message_media* media,
        const tl_ds_decrypted_message_action* action,
        const tl_ds_encrypted_file* file,
        int flags)
{
    return create_or_edit_encr_message(nullptr, id, from_id, to_id, date,
            message, message_len, media, action, file, flags);
}

void tglm_edit_encr_message(const std::shared_ptr<tgl_message>& m,
        const tgl_peer_id_t* from_id,
        const tgl_peer_id_t* to_id,
        const int* date,
        const char* message,
        int message_len,
        const tl_ds_decrypted_message_media* media,
        const tl_ds_decrypted_message_action* action,
        const tl_ds_encrypted_file* file,
        int flags)
{
    create_or_edit_encr_message(m, &m->permanent_id, from_id, to_id, date,
            message, message_len, media, action, file, flags);
}


#if 0
void tglm_message_insert_tree (struct tgl_message *M) {
  assert (M->permanent_id.id);
  //tgl_state::instance()->message_tree = tree_insert_message (tgl_state::instance()->message_tree, M, rand ());
}

void tglm_message_remove_tree (struct tgl_message *M) {
  assert (M->permanent_id.id);
  //tgl_state::instance()->message_tree = tree_delete_message (tgl_state::instance()->message_tree, M);
}

void tglm_message_insert (struct tgl_message *M) {
  tglm_message_add_use (M);
  tglm_message_add_peer (M);
}

void tglm_message_insert_unsent (struct tgl_message *M) {
  tgl_state::instance()->unsent_messages.push_back(M);
}

void tglm_message_remove_unsent (struct tgl_message *M) {
  for (auto it = tgl_state::instance()->unsent_messages.begin(); it != tgl_state::instance()->unsent_messages.end(); it++) {
    if (id_cmp(M, *it) == 0) {
      tgl_state::instance()->unsent_messages.erase(it);
      return;
    }
  }
}
#endif

static void __send_msg (const std::shared_ptr<tgl_message>& M) {
  TGL_NOTICE("Resending message...");
  //print_message (M);

  if (M->media->type() != tgl_message_media_type_none) {
    assert (M->flags & TGLMF_ENCRYPTED);
    //bl_do_message_delete (&M->permanent_id);
    tgl_state::instance()->callback()->message_deleted(M->permanent_id.id);
  } else {
    tgl_do_send_msg (M, 0);
  }
}

void tglm_send_all_unsent () {
  for (auto it = tgl_state::instance()->unsent_messages.begin(); it != tgl_state::instance()->unsent_messages.end(); it++) {
    __send_msg(*it);
  }
}
/* }}} */

void tglf_fetch_int_array (int *dst, struct tl_ds_vector *src, int len) {
    int i;
    assert (len <= *src->f1);
    for (i = 0; i < len; i++) {
        dst[i] = *(int *)src->f2[i];
    }
}

void tglf_fetch_int_tuple (int *dst, int **src, int len) {
    int i;
    for (i = 0; i < len; i++) {
        dst[i] = *src[i];
    }
}

#if 0
void tgls_messages_mark_read (struct tgl_message *M, int out, int seq) {
  while (M && M->permanent_id.id > seq) { 
    if ((M->flags & TGLMF_OUT) == out) {
      if (!(M->flags & TGLMF_UNREAD)) {
        return;
      }
    }
    M = M->next; 
  }
  while (M) {
    if ((M->flags & TGLMF_OUT) == out) {
      if (M->flags & TGLMF_UNREAD) {
        M->flags &= ~TGLMF_UNREAD;
        //tgl_state::instance()->callback()->marked_read (1, &M);
      } else {
        return;
      }
    }
    M = M->next;
  }
}
 
void tgls_insert_random2local (long long random_id, tgl_message_id_t *msg_id) {
  struct random2local *X = talloc (sizeof (*X));
  X->random_id = random_id;
  X->local_id = *msg_id;

  struct random2local *R = tree_lookup_random_id (tgl_state::instance()->random_id_tree, X);
  assert (!R);
  
  tgl_state::instance()->random_id_tree = tree_insert_random_id (tgl_state::instance()->random_id_tree, X, rand ());
}

tgl_message_id_t *tgls_get_local_by_random (long long random_id) {
  struct random2local X;
  X.random_id = random_id;
  struct random2local *Y = tree_lookup_random_id (tgl_state::instance()->random_id_tree, &X);
  if (Y) { 
    //tgl_state::instance()->random_id_tree = tree_delete_random_id (tgl_state::instance()->random_id_tree, Y);
    return &Y->local_id;
  } else {
    return NULL;
  }
}
  
void tgls_insert_temp2local (int temp_id, tgl_message_id_t *msg_id) {
  struct random2local *X = talloc (sizeof (*X));
  X->random_id = temp_id;
  X->local_id = *msg_id;

  struct random2local *R = tree_lookup_random_id (tgl_state::instance()->temp_id_tree, X);
  assert (!R);
  
  tgl_state::instance()->temp_id_tree = tree_insert_random_id (tgl_state::instance()->temp_id_tree, X, rand ());
}

tgl_message_id_t *tgls_get_local_by_random (long long random_id) {
  struct tgl_message M;
  M.random_id = random_id;
  struct tgl_message *N = tree_lookup_random_id (tgl_state::instance()->random_id_tree, &M);
  if (N) {
    return &N->permanent_id;
  } else {
    return NULL;
  }
}

tgl_message_id_t *tgls_get_local_by_temp (int temp_id) {
  struct tgl_message M;
  M.temp_id = temp_id;
  struct tgl_message *N = tree_lookup_temp_id (tgl_state::instance()->temp_id_tree, &M);
  if (N) {
    return &N->permanent_id;
  } else {
    return NULL;
  }
}
#endif

tgl_message_id_t tgl_convert_temp_msg_id (tgl_message_id_t msg_id) {
  //struct tgl_message M;
  //M.temp_id = msg_id.id;
  //struct tgl_message *N = tree_lookup_temp_id (tgl_state::instance()->temp_id_tree, &M);
  //if (N) {
    //return N->permanent_id;
  //} else {
    return msg_id;
  //}
}

#if 0
void tgls_message_change_temp_id (struct tgl_message *M, int temp_id) {
  if (M->temp_id == temp_id) { return; }
  assert (!M->temp_id);
  M->temp_id = temp_id;
  tgl_state::instance()->temp_id_tree = tree_insert_temp_id (tgl_state::instance()->temp_id_tree, M, rand ());
}

void tgls_message_change_random_id (struct tgl_message *M, long long random_id) {
  if (M->random_id == random_id) { return; }
  assert (!M->random_id);
  M->random_id = random_id;
  tgl_state::instance()->random_id_tree = tree_insert_random_id (tgl_state::instance()->random_id_tree, M, rand ());
}

void tglm_message_del_temp_id (struct tgl_message *M) {
  if (M->temp_id) {
    tgl_state::instance()->temp_id_tree = tree_delete_temp_id (tgl_state::instance()->temp_id_tree, M);
  }
}

void tglm_message_del_random_id (struct tgl_message *M) {
  if (M->random_id) {
    tgl_state::instance()->random_id_tree = tree_delete_random_id (tgl_state::instance()->random_id_tree, M);
  }
}
#endif
