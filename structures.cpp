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
#include "tgl-structures.h"
#include "crypto/aes.h"
#include "crypto/bn.h"
#include "crypto/sha.h"
#include "queries.h"
#include "tgl-binlog.h"
#include "tgl-methods-in.h"
#include "updates.h"
#include "mtproto-client.h"

#include "tgl.h"
extern "C" {
#include "auto.h"
#include "auto/auto-types.h"
#include "auto/auto-free-ds.h"
#include "auto/auto-fetch-ds.h"

#include "mtproto-common.h"
}

static void increase_peer_size ();

char *tgls_default_create_print_name (tgl_peer_id_t id, const char *a1, const char *a2, const char *a3, const char *a4) {
    const char *d[4];
    d[0] = a1; d[1] = a2; d[2] = a3; d[3] = a4;
    static char buf[10000];
    buf[0] = 0;
    int i;
    int p = 0;
    for (i = 0; i < 4; i++) {
        if (d[i] && strlen (d[i])) {
            p += tsnprintf (buf + p, 9999 - p, "%s%s", p ? "_" : "", d[i]);
            assert (p < 9990);
        }
    }
  }
  char *s = buf;
  while (*s) {
    if (((unsigned char)*s) <= ' ') { *s = '_'; }
    if (*s == '#') { *s = '_'; }
    if (*s == '$') { *s = '_'; }
    if (*s == '@') { *s = '_'; }
    s++;
  }
  s = buf;
  int fl = strlen (s);
  int cc = 0;
  while (1) {
    tgl_peer_t *P = tgl_peer_get_by_name (s);
    if (!P || !tgl_cmp_peer_id (P->id, id)) {
      break;
    }
    cc ++;
    assert (cc <= 9999);
    tsnprintf (s + fl, 9999 - fl, "#%d", cc);
  }
  return tstrdup (s);
}

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

tgl_file_location tglf_fetch_file_location (struct tgl_file_location *loc, struct tl_ds_file_location *DS_FL) {
  if (!DS_FL) { return tgl_file_location(); }
  return tgl_file_location(DS_LVAL (DS_FL->dc_id), DS_LVAL (DS_FL->volume_id), DS_LVAL (DS_FL->local_id), DS_LVAL (DS_FL->secret));
}

int tglf_fetch_user_status (struct tgl_user_status *S, struct tgl_user *U, struct tl_ds_user_status *DS_US) {
  if (!DS_US) { return 0; }
  switch (DS_US->magic) {
  case CODE_user_status_empty:
    if (S->online) {
      tgl_insert_status_update (U);
      if (S->online == 1) {
        tgl_remove_status_expire (U);
      }
    }
    S->online = 0;
    S->when = 0;
    break;
  case CODE_user_status_online:
    {
      if (S->online != 1) {
        S->when = DS_LVAL (DS_US->expires);
        if (S->online) {
            tgl_insert_status_update (U);
            if (S->online == 1) {
                tgl_remove_status_expire (U);
            }
        }
        S->online = 0;
        S->when = 0;
        break;
    case CODE_user_status_online:
        *expires = DS_LVAL (DS_US->expires);
        return tgl_user_status_online;
    case CODE_user_status_offline:
        return tgl_user_status_offline;
    case CODE_user_status_recently:
        return tgl_user_status_recently;
    case CODE_user_status_last_week:
        return tgl_user_status_last_week;
    case CODE_user_status_last_month:
        return tgl_user_status_offline;
    default: break;
    }
    return tgl_user_status_offline;
}

struct tgl_user *tglf_fetch_alloc_user (struct tl_ds_user *DS_U) {
  if (!DS_U) { return 0; }
  if (DS_U->magic == CODE_user_empty) {
    return 0;
  } 
  
  tgl_peer_id_t user_id = TGL_MK_USER (DS_LVAL (DS_U->id));  
  user_id.access_hash = DS_LVAL (DS_U->access_hash);
  
  struct tgl_user *U = (struct tgl_user *)tgl_peer_get (user_id);
  if (!U) {
    tgl_state::instance()->users_allocated ++;
    U = talloc0 (sizeof (tgl_peer_t));
    U->id = user_id;
    tgl_state::instance()->peer_tree = tree_insert_peer (tgl_state::instance()->peer_tree, (tgl_peer_t *)U, rand ());
    increase_peer_size ();
    tgl_state::instance()->Peers[tgl_state::instance()->peer_num ++] = (tgl_peer_t *)U;
  }

  int flags = U->flags;

  if (DS_LVAL (DS_U->flags) & (1 << 10)) {
    //bl_do_set_our_id (U->id);
    tgl_state::instance()->set_our_id (user_id);
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
  
  
  if (DS_LVAL (DS_U->flags) & (1 << 14)) {
    flags |= TGLUF_BOT;
  } else {
    flags &= ~TGLUF_BOT;
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
  bl_do_user (tgl_get_peer_id (U->id), 
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
    if (tgl_state::instance()->callback.user_deleted) {
      tgl_state::instance()->callback.user_deleted (user_id);
    }
    return U;
  } else {
    DS_CSTR(firstname, DS_U->first_name);
    DS_CSTR(lastname, DS_U->last_name);
    DS_CSTR(phone, DS_U->phone);
    DS_CSTR(username, DS_U->username);

    tgl_state::instance()->callback.new_user(user_id, phone, firstname, lastname, username);

    free(firstname);
    free(lastname);
    free(phone);
    free(username);

    if (DS_U->photo) {
      tgl_file_location photo_big = tglf_fetch_file_location_new(DS_U->photo->photo_big);
      tgl_file_location photo_small = tglf_fetch_file_location_new(DS_U->photo->photo_small);

      tgl_state::instance()->callback.avatar_update(user_id, photo_small, photo_big);
    }
    return U;
  }
}

struct tgl_user *tglf_fetch_alloc_user_full (struct tl_ds_user_full *DS_UF) {
  if (!DS_UF) { return NULL; }

  struct tgl_user *U = tglf_fetch_alloc_user (DS_UF->user);
  if (!U) { return NULL; }

  int flags = U->flags;
  
  if (DS_BVAL (DS_UF->blocked)) {
    flags |= TGLUF_BLOCKED;
  } else {
    flags &= ~TGLUF_BLOCKED;
  }

#if 0
  bl_do_user (tgl_get_peer_id (U->id), 
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

    tgl_state::instance()->callback.new_user(user_id, "", "", "", "");

    if (DS_UF->user->photo) {
        tgl_file_location photo_big = tglf_fetch_file_location_new(DS_UF->user->photo->photo_big);
        tgl_file_location photo_small = tglf_fetch_file_location_new(DS_UF->user->photo->photo_small);
        tgl_state::instance()->callback.profile_picture_update(user_id, DS_LVAL(DS_UF->user->photo->photo_id), &photo_small, &photo_big);
    }

  return U;
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

#ifdef ENABLE_SECRET_CHAT

struct tgl_secret_chat *tglf_fetch_alloc_encrypted_chat (struct tl_ds_encrypted_chat *DS_EC) {
  if (!DS_EC) { return NULL; }
  if (DS_EC->magic == CODE_encrypted_chat_empty) {
    return NULL;
  }

  tgl_peer_id_t chat_id = TGL_MK_ENCR_CHAT (DS_LVAL (DS_EC->id));  
  chat_id.access_hash = DS_LVAL (DS_EC->access_hash);
  
  struct tgl_secret_chat *U = (void *)tgl_peer_get (chat_id);
  if (!U) {
    tgl_state::instance()->encr_chats_allocated ++;
    U = talloc0 (sizeof (tgl_peer_t));
    U->id = chat_id;
    tgl_state::instance()->peer_tree = tree_insert_peer (tgl_state::instance()->peer_tree, (tgl_peer_t *)U, rand ());
    increase_peer_size ();
    tgl_state::instance()->Peers[tgl_state::instance()->peer_num ++] = (tgl_peer_t *)U;
  }
  
  int new = !(U->flags & TGLPF_CREATED);
 
  if (DS_EC->magic == CODE_encrypted_chat_discarded) {
    if (new) {
      vlogprintf (E_WARNING, "Unknown chat in deleted state. May be we forgot something...\n");
      return U;
    }
    bl_do_peer_delete (U->id);
    //write_secret_chat_file ();
    return U;
  }

  static unsigned char g_key[256];
  if (new) {
    if (DS_EC->magic != CODE_encrypted_chat_requested) {
      vlogprintf (E_WARNING, "Unknown chat. May be we forgot something...\n");
      return U;
    }

    str_to_256 (g_key, DS_STR (DS_EC->g_a));
 
    int user_id =  DS_LVAL (DS_EC->participant_id) + DS_LVAL (DS_EC->admin_id) - tgl_get_peer_id (tgl_state::instance()->our_id());
    int r = sc_request;
    bl_do_encr_chat (tgl_get_peer_id (U->id), 
      DS_EC->access_hash,
      DS_EC->date,
      DS_EC->admin_id,
      &user_id,
      NULL, 
      (void *)g_key,
      NULL,
      &r, 
      NULL, NULL, NULL, NULL, NULL, 
      NULL, 
      TGLECF_CREATE | TGLECF_CREATED,
      NULL, 0
    );
  } else {
    if (DS_EC->magic == CODE_encrypted_chat_waiting) {
      int r = sc_waiting;
      bl_do_encr_chat (tgl_get_peer_id (U->id), 
        DS_EC->access_hash,
        DS_EC->date,
        NULL,
        NULL,
        NULL, 
        NULL,
        NULL,
        &r, 
        NULL, NULL, NULL, NULL, NULL, 
        NULL, 
        TGL_FLAGS_UNCHANGED,
        NULL, 0
      );
      return U; // We needed only access hash from here
    }
    
    str_to_256 (g_key, DS_STR (DS_EC->g_a_or_b));
    
    //write_secret_chat_file ();
    int r = sc_ok;
    bl_do_encr_chat (tgl_get_peer_id (U->id), 
      DS_EC->access_hash,
      DS_EC->date,
      NULL,
      NULL,
      NULL, 
      g_key,
      NULL,
      &r, 
      NULL, NULL, NULL, NULL, NULL, 
      DS_EC->key_fingerprint,
      TGL_FLAGS_UNCHANGED,
      NULL, 0
    );
  }

  return U;
}
#endif

struct tgl_chat *tglf_fetch_alloc_chat (struct tl_ds_chat *DS_C) {
  if (!DS_C) { return NULL; }
  if (DS_C->magic == CODE_chat_empty) { 
    return NULL;
  }
  if (DS_C->magic == CODE_channel || DS_C->magic == CODE_channel_forbidden) {
    return (void *)tglf_fetch_alloc_channel (DS_C);
  }
  tgl_peer_id_t chat_id = TGL_MK_CHAT (DS_LVAL (DS_C->id));  
  chat_id.access_hash = 0; // chats don't have access hash
  
  struct tgl_chat *C = (void *)tgl_peer_get (chat_id);
  if (!C) {
    tgl_state::instance()->chats_allocated ++;
    C = (struct tgl_chat *)talloc0 (sizeof (tgl_peer_t));
    C->id = chat_id;
    tgl_state::instance()->peer_tree = tree_insert_peer (tgl_state::instance()->peer_tree, (tgl_peer_t *)C, rand ());
    increase_peer_size ();
    tgl_state::instance()->Peers[tgl_state::instance()->peer_num ++] = (tgl_peer_t *)C;
  }
  
  C->id = chat_id;
  
  int flags = C->flags;
  if (!(flags & TGLCF_CREATED)) {
    flags |= TGLCF_CREATE | TGLCF_CREATED;
  }

  if (DS_LVAL (DS_C->flags) & 1) {
    flags |= TGLCF_CREATOR;
  } else {
    flags &= ~TGLCF_CREATOR;
  }

  if (DS_LVAL (DS_C->flags) & 2) {
    flags |= TGLCF_KICKED;
  } else {
    flags &= ~TGLCF_KICKED;
  }

  if (DS_LVAL (DS_C->flags) & 4) {
    flags |= TGLCF_LEFT;
  } else {
    flags &= ~TGLCF_LEFT;
  }

  if (DS_LVAL (DS_C->flags) & 8) {
    flags |= TGLCF_ADMINS_ENABLED;
  } else {
    flags &= ~TGLCF_ADMINS_ENABLED;
  }

  if (DS_LVAL (DS_C->flags) & 16) {
    flags |= TGLCF_ADMIN;
  } else {
    flags &= ~TGLCF_ADMIN;
  }

  if (DS_LVAL (DS_C->flags) & 32) {
    flags |= TGLCF_DEACTIVATED;
  } else {
    flags &= ~TGLCF_DEACTIVATED;
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

  C->photo_big = tglf_fetch_file_location_new(DS_C->photo->photo_big);
  C->photo_small = tglf_fetch_file_location_new(DS_C->photo->photo_small);

  tgl_state::instance()->callback.chat_update(tgl_get_peer_id (C->id), *DS_C->participants_count, -1, C->photo, time(0), DS_C->title->data, DS_C->title->len);

  return C;
}

struct tgl_chat *tglf_fetch_alloc_chat_full (struct tl_ds_messages_chat_full *DS_MCF) {
  if (!DS_MCF) { return NULL; }
  if (DS_MCF->full_chat->magic == CODE_channel_full) {
    return (void *)tglf_fetch_alloc_channel_full (DS_MCF);
  }
 
  if (DS_MCF->users) {
    int i;
    for (i = 0; i < DS_LVAL (DS_MCF->users->cnt); i++) {
      tglf_fetch_alloc_user (DS_MCF->users->data[i]);
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
      struct tl_ds_bot_info *DS_BI = DS_CF->bot_info->data[i];

      tgl_peer_t *P = tgl_peer_get (TGL_MK_USER (DS_LVAL (DS_BI->user_id)));
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
    }
  }

  tgl_peer_id_t chat_id = TGL_MK_CHAT (DS_LVAL (DS_CF->id));  
  struct tgl_chat *C = (void *)tgl_peer_get (chat_id);
  assert (C);

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

  if (*DS_CF->chat_photo->sizes->cnt > 1) {
    C->photo_big = tglf_fetch_file_location_new(DS_CF->chat_photo->sizes->data[1]->location);
  }
  if (*DS_CF->chat_photo->sizes->cnt > 0) {
    C->photo_small = tglf_fetch_file_location_new(DS_CF->chat_photo->sizes->data[0]->location);
  }

  tgl_state::instance()->callback.chat_update(tgl_get_peer_id (C->id), *DS_CF->participants->participants->cnt, *DS_CF->participants->admin_id,
      C->photo, *DS_CF->chat_photo->date, DS_C->title->data, DS_C->title->len);
  //TODO update users

  return C;
}

struct tgl_channel *tglf_fetch_alloc_channel (struct tl_ds_chat *DS_C) {
  if (!DS_C) { return NULL; }
  
  tgl_peer_id_t chat_id = TGL_MK_CHANNEL (DS_LVAL (DS_C->id));  
  chat_id.access_hash = DS_LVAL (DS_C->access_hash); 

  struct tgl_channel *C = (void *)tgl_peer_get (chat_id);
  if (!C) {
    tgl_state::instance()->channels_allocated ++;
    C = talloc0 (sizeof (tgl_peer_t));
    C->id = chat_id;
    tgl_state::instance()->peer_tree = tree_insert_peer (tgl_state::instance()->peer_tree, (tgl_peer_t *)C, rand ());
    increase_peer_size ();
    tgl_state::instance()->Peers[tgl_state::instance()->peer_num ++] = (tgl_peer_t *)C;
  }
  
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

  return C;
}

struct tgl_channel *tglf_fetch_alloc_channel_full (struct tl_ds_messages_chat_full *DS_MCF) {
  if (!DS_MCF) { return NULL; }
  
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

  struct tgl_channel *C = (void *)tgl_peer_get (chat_id);
  assert (C);

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

  return C;
}

void tglf_fetch_photo_size (struct tgl_photo_size *S, struct tl_ds_photo_size *DS_PS) {
  memset (S, 0, sizeof (*S));

  S->type = DS_STR_DUP (DS_PS->type);
  S->w = DS_LVAL (DS_PS->w);
  S->h = DS_LVAL (DS_PS->h);
  S->size = DS_LVAL (DS_PS->size);
  if (DS_PS->bytes) {
    S->size = DS_PS->bytes->len;
  }

  tglf_fetch_file_location (&S->loc, DS_PS->location); 
}

void tglf_fetch_geo (struct tgl_geo *G, struct tl_ds_geo_point *DS_GP) {
  G->longitude = DS_LVAL (DS_GP->longitude);
  G->latitude = DS_LVAL (DS_GP->latitude);
}

struct tgl_photo *tglf_fetch_alloc_photo (struct tl_ds_photo *DS_P) {
  if (!DS_P) { return NULL; }
  if (DS_P->magic == CODE_photo_empty) { return NULL; }
  
  struct tgl_photo *P = tgl_photo_get (DS_LVAL (DS_P->id));
  if (P) {
    P->refcnt ++;
    return P;
  }

  P = (struct tgl_photo *)talloc0 (sizeof (*P));
  P->id = DS_LVAL (DS_P->id);
  P->refcnt = 1;

  tgl_photo_insert (P);

  P->access_hash = DS_LVAL (DS_P->access_hash);
  P->user_id = DS_LVAL (DS_P->user_id);
  P->date = DS_LVAL (DS_P->date);
  P->caption = NULL;//DS_STR_DUP (DS_P->caption);
  if (DS_P->geo) {
    tglf_fetch_geo (&P->geo, DS_P->geo);
  }

  P->sizes_num = DS_LVAL (DS_P->sizes->cnt);
  P->sizes = (struct tgl_photo_size *)talloc (sizeof (struct tgl_photo_size) * P->sizes_num);
  int i;
  for (i = 0; i < P->sizes_num; i++) {
    tglf_fetch_photo_size (&P->sizes[i], DS_P->sizes->data[i]);
  }

  return P;
}

struct tgl_document *tglf_fetch_alloc_video (struct tl_ds_video *DS_V) {
  if (!DS_V) { return NULL; }
  
  if (DS_V->magic == CODE_video_empty) { return NULL; }
  
  struct tgl_document *D = tgl_document_get (DS_LVAL (DS_V->id));
  if (D) {
    D->refcnt ++;
    return D;
  }

  D = (struct tgl_document *)calloc(1, sizeof(struct tgl_document));
  D->id = DS_LVAL (DS_V->id);

  D->flags = TGLDF_VIDEO;

  D->access_hash = DS_LVAL (DS_V->access_hash);
  D->user_id = DS_LVAL (DS_V->user_id);
  D->date = DS_LVAL (DS_V->date);
  D->caption = NULL;//DS_STR_DUP (DS_V->caption);
  D->duration = DS_LVAL (DS_V->duration);
  D->mime_type = tstrdup ("video/");//DS_STR_DUP (DS_V->mime_type);
  D->size = DS_LVAL (DS_V->size);
  tglf_fetch_photo_size (&D->thumb, DS_V->thumb);

    D->dc_id = DS_LVAL (DS_V->dc_id);
    D->w = DS_LVAL (DS_V->w);
    D->h = DS_LVAL (DS_V->h);
    return D;
}

struct tgl_document *tglf_fetch_alloc_audio (struct tl_ds_audio *DS_A) {
  if (!DS_A) { return NULL; }
  
  if (DS_A->magic == CODE_audio_empty) { return NULL; }
  
  struct tgl_document *D = tgl_document_get (DS_LVAL (DS_A->id));
  if (D) {
    D->refcnt ++;
    return D;
  }

  D = (struct tgl_document *)talloc0(sizeof struct tgl_document);
  D->id = DS_LVAL (DS_A->id);
  D->flags = TGLDF_AUDIO;

  D->access_hash = DS_LVAL (DS_A->access_hash);
  D->user_id = DS_LVAL (DS_A->user_id);
  D->date = DS_LVAL (DS_A->date);
  D->duration = DS_LVAL (DS_A->duration);
  D->mime_type = DS_STR_DUP (DS_A->mime_type);
  D->size = DS_LVAL (DS_A->size);
  D->dc_id = DS_LVAL (DS_A->dc_id);

  return D;
}

void tglf_fetch_document_attribute (struct tgl_document *D, struct tl_ds_document_attribute *DS_DA) {
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
    D->caption = DS_STR_DUP (DS_DA->file_name);
    return;
  default:
    assert (0);
  }
}

struct tgl_document *tglf_fetch_alloc_document (struct tl_ds_document *DS_D) {
  if (!DS_D) { return NULL; }
  
  if (DS_D->magic == CODE_document_empty) { return NULL; }
  
  struct tgl_document *D = tgl_document_get (DS_LVAL (DS_D->id));
  if (D) {
    D->refcnt ++;
    return D;
  }

  D = (struct tgl_document *)talloc0 (sizeof (struct tgl_document));
  D->id = DS_LVAL (DS_D->id);
  D->access_hash = DS_LVAL (DS_D->access_hash);
  D->user_id = DS_LVAL (DS_D->user_id);
  D->date = DS_LVAL (DS_D->date);
  D->caption = DS_STR_DUP (DS_D->file_name);
  D->mime_type = DS_STR_DUP (DS_D->mime_type);
  D->size = DS_LVAL (DS_D->size);
  D->dc_id = DS_LVAL (DS_D->dc_id);

  tglf_fetch_photo_size (&D->thumb, DS_D->thumb);

  if (DS_D->attributes) {
    int i;
    for (i = 0; i < DS_LVAL (DS_D->attributes->cnt); i++) {
      tglf_fetch_document_attribute (D, DS_D->attributes->data[i]);
    }
  }
  return D;
}

struct tgl_webpage *tglf_fetch_alloc_webpage (struct tl_ds_web_page *DS_W) {
  if (!DS_W) { return NULL; }
  
  struct tgl_webpage *W = tgl_webpage_get (DS_LVAL (DS_W->id));
  if (W) {
    W->refcnt ++;
  } else {
    W = (struct tgl_webpage *)calloc(1, sizeof (struct tgl_webpage));
    W->id = DS_LVAL (DS_W->id);
    W->refcnt = 1;
  
    tgl_webpage_insert (W);
  }

  // TODO make thos \0 terminated
  if (!W->url) {
    W->url = DS_STR_DUP (DS_W->url);
  }

  if (!W->display_url) {
    W->display_url = DS_STR_DUP (DS_W->display_url);
  }

  if (!W->type) {
    W->type = DS_STR_DUP (DS_W->type);
  }

  if (!W->title) {
    W->title = DS_STR_DUP (DS_W->title);
  }

  if (!W->photo) {
    W->photo = tglf_fetch_alloc_photo_new (DS_W->photo);
  }

  if (!W->description) {
    W->description = DS_STR_DUP (DS_W->description);
  }

  if (!W->embed_url) {
    W->embed_url = DS_STR_DUP (DS_W->embed_url);
  }

  if (!W->embed_type) {
    W->embed_type = DS_STR_DUP (DS_W->embed_type);
  }

  W->embed_width = DS_LVAL (DS_W->embed_width);

  W->embed_height = DS_LVAL (DS_W->embed_height);

  W->duration = DS_LVAL (DS_W->duration);

  if (!W->author) {
    W->author = DS_STR_DUP (DS_W->author);
  }
  return W;
}

void tglf_fetch_message_action (struct tgl_message_action *M, struct tl_ds_message_action *DS_MA) {
  if (!DS_MA) { return; }
  memset (M, 0, sizeof (*M));
  
  switch (DS_MA->magic) {
  case CODE_message_action_empty:
    M->type = tgl_message_action_none;
    break;
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
      M->type = tgl_message_action_chat_create;
      M->title = DS_STR_DUP (DS_MA->title);
    
      M->user_num = DS_LVAL (DS_MA->users->cnt);
      M->users = (int *)talloc (M->user_num * 4);
      int i;
      for (i = 0; i < M->user_num; i++) {
        M->users[i] = DS_LVAL (DS_MA->users->data[i]);
      }
    }
    break;
  case CODE_message_action_chat_edit_title:
    M->type = tgl_message_action_chat_edit_title;
    M->new_title = DS_STR_DUP (DS_MA->title);
    break;
  case CODE_message_action_chat_edit_photo:
    M->type = tgl_message_action_chat_edit_photo;
    M->photo = tglf_fetch_alloc_photo (DS_MA->photo);
    break;
  case CODE_message_action_chat_delete_photo:
    M->type = tgl_message_action_chat_delete_photo;
    break;
  case CODE_message_action_chat_add_user:
    M->type = tgl_message_action_chat_add_users;
    M->user_num = DS_LVAL (DS_MA->users->cnt);
    M->users = talloc (4 * M->user_num);
    {
      int i;
      for (i = 0; i < M->user_num; i++) {
        M->users[i] = DS_LVAL (DS_MA->users->data[i]);
      }
    }
    break;
  case CODE_message_action_chat_delete_user:
    M->type = tgl_message_action_chat_delete_user;
    M->user = DS_LVAL (DS_MA->user_id);
    break;
  case CODE_message_action_chat_joined_by_link:
    M->type = tgl_message_action_chat_add_user_by_link;
    M->user = DS_LVAL (DS_MA->inviter_id);
    break;
  case CODE_message_action_channel_create:
    M->type = tgl_message_action_channel_create;
    M->title = DS_STR_DUP (DS_MA->title);
    break;
  case CODE_message_action_chat_migrate_to:
    M->type = tgl_message_action_migrated_to;
    break;
  case CODE_message_action_channel_migrate_from:
    M->type = tgl_message_action_migrated_from;
    M->title = DS_STR_DUP (DS_MA->title);
    break;
  default:
    assert (0);
  }
}

struct tgl_message *tglf_fetch_alloc_message_short (struct tl_ds_updates *DS_U) {
  tgl_peer_t *P = tgl_peer_get (TGL_MK_USER (DS_LVAL (DS_U->user_id)));
  if (!P || !(P->flags & TGLPF_CREATED)) {
    tgl_do_get_difference (0, 0, 0);
    return NULL;
  }
  
  tgl_message_id_t msg_id = tgl_peer_id_to_msg_id (P->id, DS_LVAL (DS_U->id));
  struct tgl_message *M = tgl_message_get (&msg_id);
  if (!M) {
    M = talloc0 (sizeof (*M));
    M->permanent_id = msg_id;
    tglm_message_insert_tree (M);
    tgl_state::instance()->messages_allocated ++;

    assert (tgl_message_get (&msg_id) == M);
  }

  int flags = M->flags & 0xffff;

  if (M->flags & TGLMF_PENDING) {
    M->flags ^= TGLMF_PENDING;
  }

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
  int type = TGL_PEER_USER;

  tgl_peer_id_t our_id = tgl_state::instance()->our_id();
  tgl_peer_id_t peer_id = P->id;

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
  tglm_message_create (DS_LVAL (DS_U->id),
          (f & 2) ? &our_id : &peer_id,
          &type, (f & 2) ? &peer_id : &our_id,
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

  return M;
}

struct tgl_message *tglf_fetch_alloc_message_short_chat (struct tl_ds_updates *DS_U) {
  tgl_peer_t *F = tgl_peer_get (TGL_MK_USER (DS_LVAL (DS_U->from_id)));
  if (!F || !(F->flags & TGLPF_CREATED)) {
    tgl_do_get_difference (0, 0, 0);
    return NULL;
  }
  tgl_peer_t *T = tgl_peer_get (TGL_MK_CHAT (DS_LVAL (DS_U->chat_id)));
  if (!T || !(T->flags & TGLPF_CREATED)) {
    tgl_do_get_difference (0, 0, 0);
    return NULL;
  }
  
  tgl_message_id_t msg_id = tgl_peer_id_to_msg_id (T->id, DS_LVAL (DS_U->id));
  struct tgl_message *M = tgl_message_get (&msg_id);
  if (!M) {
    M = talloc0 (sizeof (*M));
    M->permanent_id = msg_id;
    tglm_message_insert_tree (M);
    tgl_state::instance()->messages_allocated ++;
  }

  int flags = M->flags & 0xffff;
  
  if (M->flags & TGLMF_PENDING) {
    M->flags ^= TGLMF_PENDING;
  }

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

  tgl_peer_id_t from_id = F->id;
  tgl_peer_id_t to_id = T->id;
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

  int type = TGL_PEER_CHAT;
  DS_CSTR (msg_text, DS_U->message);
  tglm_message_create (DS_LVAL (DS_U->id),
      DS_U->from_id,
      &type, DS_U->chat_id,
      DS_U->fwd_from_id,
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
  return M;
}


void tglf_fetch_message_media (struct tgl_message_media *M, struct tl_ds_message_media *DS_MM) {
  if (!DS_MM) { return; }
  memset (M, 0, sizeof (*M));
  switch (DS_MM->magic) {
  case CODE_message_media_empty:
    M->type = tgl_message_media_none;
    break;
  case CODE_message_media_photo:
  case CODE_message_media_photo_l27:
    M->type = tgl_message_media_photo;
    M->photo = tglf_fetch_alloc_photo (DS_MM->photo);
    M->caption = DS_STR_DUP (DS_MM->caption);
    break;
  case CODE_message_media_video:
  case CODE_message_media_video_l27:
    M->type = tgl_message_media_video;
    M->document = tglf_fetch_alloc_video (DS_MM->video);
    M->caption = DS_STR_DUP (DS_MM->caption);
    break;
  case CODE_message_media_audio:
    M->type = tgl_message_media_audio;
    M->document = tglf_fetch_alloc_audio (DS_MM->audio);
    M->caption = DS_STR_DUP (DS_MM->caption);
    break;
  case CODE_message_media_document:
    M->type = tgl_message_media_document;
    M->document = tglf_fetch_alloc_document (DS_MM->document);
    M->caption = DS_STR_DUP (DS_MM->caption);
    break;
  case CODE_message_media_geo:
    M->type = tgl_message_media_geo;
    tglf_fetch_geo (&M->geo, DS_MM->geo);
    break;
  case CODE_message_media_contact:
    M->type = tgl_message_media_contact;
    M->phone = DS_STR_DUP (DS_MM->phone_number);
    M->first_name = DS_STR_DUP (DS_MM->first_name);
    M->last_name = DS_STR_DUP (DS_MM->last_name);
    M->user_id = DS_LVAL (DS_MM->user_id);
    break;
  case CODE_message_media_web_page:
    M->type = tgl_message_media_webpage;
    M->webpage = tglf_fetch_alloc_webpage (DS_MM->webpage);
    break;
  case CODE_message_media_venue:
    M->type = tgl_message_media_venue;
    tglf_fetch_geo (&M->venue.geo, DS_MM->geo);
    M->venue.title = DS_STR_DUP (DS_MM->title);
    M->venue.address = DS_STR_DUP (DS_MM->address);
    M->venue.provider = DS_STR_DUP (DS_MM->provider);
    M->venue.venue_id = DS_STR_DUP (DS_MM->venue_id);   
    break;
  case CODE_message_media_unsupported:
    M->type = tgl_message_media_unsupported;
    break;
  default:
    assert (0);
  }
}

void tglf_fetch_message_media_encrypted (struct tgl_message_media *M, struct tl_ds_decrypted_message_media *DS_DMM) {
  if (!DS_DMM) { return; }

  memset (M, 0, sizeof (*M));
  switch (DS_DMM->magic) {
  case CODE_decrypted_message_media_empty:
    M->type = tgl_message_media_none;
    //M->type = CODE_message_media_empty;
    break;
  case CODE_decrypted_message_media_photo:
  case CODE_decrypted_message_media_video:
  case CODE_decrypted_message_media_video_l12:
  case CODE_decrypted_message_media_document:
  case CODE_decrypted_message_media_audio:
    //M->type = CODE_decrypted_message_media_video;
    M->type = tgl_message_media_document_encr;
    
    M->encr_document = talloc0 (sizeof (*M->encr_document));
  
    switch (DS_DMM->magic) {
    case CODE_decrypted_message_media_empty:
        M->type = tgl_message_media_none;
        //M->type = CODE_message_media_empty;
        break;
    case CODE_decrypted_message_media_photo:
    case CODE_decrypted_message_media_video:
    case CODE_decrypted_message_media_video_l12:
    case CODE_decrypted_message_media_document:
    case CODE_decrypted_message_media_audio:
        //M->type = CODE_decrypted_message_media_video;
        M->type = tgl_message_media_document_encr;

        M->encr_document = talloc0 (sizeof (*M->encr_document));

        switch (DS_DMM->magic) {
        case CODE_decrypted_message_media_photo:
            M->encr_document->flags = TGLDF_IMAGE;
            break;
        case CODE_decrypted_message_media_video:
        case CODE_decrypted_message_media_video_l12:
            M->encr_document->flags = TGLDF_VIDEO;
            break;
        case CODE_decrypted_message_media_document:
            //M->encr_document->flags = TGLDF_DOCUMENT;
            break;
        case CODE_decrypted_message_media_audio:
            M->encr_document->flags = TGLDF_AUDIO;
            break;
        }

        M->encr_document->w = DS_LVAL (DS_DMM->w);
        M->encr_document->h = DS_LVAL (DS_DMM->h);
        M->encr_document->size = DS_LVAL (DS_DMM->size);
        M->encr_document->duration = DS_LVAL (DS_DMM->duration);
        M->encr_document->mime_type = DS_STR_DUP (DS_DMM->mime_type);

        M->encr_document->key = talloc (32);
        str_to_32 (M->encr_document->key, DS_STR (DS_DMM->key));
        M->encr_document->iv = talloc (32);
        str_to_32 (M->encr_document->iv, DS_STR (DS_DMM->iv));
        break;
    case CODE_decrypted_message_media_geo_point:
        M->type = tgl_message_media_geo;
        M->geo.latitude = DS_LVAL (DS_DMM->latitude);
        M->geo.longitude = DS_LVAL (DS_DMM->longitude);
        break;
    case CODE_decrypted_message_media_contact:
        M->type = tgl_message_media_contact;
        M->phone = DS_STR_DUP (DS_DMM->phone_number);
        M->first_name = DS_STR_DUP (DS_DMM->first_name);
        M->last_name = DS_STR_DUP (DS_DMM->last_name);
        M->user_id = DS_LVAL (DS_DMM->user_id);
        break;
    default:
        assert (0);
    }
}

void tglf_fetch_message_action_encrypted (struct tgl_message_action *M, struct tl_ds_decrypted_message_action *DS_DMA) {
  if (!DS_DMA) { return; }
  
  switch (DS_DMA->magic) {
  case CODE_decrypted_message_action_set_message_t_t_l:
    M->type = tgl_message_action_set_message_ttl;
    M->ttl = DS_LVAL (DS_DMA->ttl_seconds);
    break;
  case CODE_decrypted_message_action_read_messages: 
    M->type = tgl_message_action_read_messages;
    { 
      M->read_cnt = DS_LVAL (DS_DMA->random_ids->cnt);
      
      int i;
      for (i = 0; i < M->read_cnt; i++) {
        tgl_message_id_t id;
        id.peer_type = TGL_PEER_RANDOM_ID;
        id.id = DS_LVAL (DS_DMA->random_ids->data[i]);
        struct tgl_message *N = tgl_message_get (&id);
        if (N) {
          N->flags &= ~TGLMF_UNREAD;
        }
      }
    }
    break;
  case CODE_decrypted_message_action_delete_messages: 
    M->type = tgl_message_action_delete_messages;
    break;
  case CODE_decrypted_message_action_screenshot_messages: 
    M->type = tgl_message_action_screenshot_messages;
    { 
      M->screenshot_cnt = DS_LVAL (DS_DMA->random_ids->cnt);
    }
    break;
  case CODE_decrypted_message_action_notify_layer: 
    M->type = tgl_message_action_notify_layer;
    M->layer = DS_LVAL (DS_DMA->layer);
    break;
  case CODE_decrypted_message_action_flush_history:
    M->type = tgl_message_action_flush_history;
    break;
  case CODE_decrypted_message_action_typing:
    M->type = tgl_message_action_typing;
    M->typing = tglf_fetch_typing (DS_DMA->action);
    break;
  case CODE_decrypted_message_action_resend:
    M->type = tgl_message_action_resend;
    M->start_seq_no = DS_LVAL (DS_DMA->start_seq_no);
    M->end_seq_no = DS_LVAL (DS_DMA->end_seq_no);
    break;
  case CODE_decrypted_message_action_noop:
    M->type = tgl_message_action_noop;
    break;
  case CODE_decrypted_message_action_request_key:
    M->type = tgl_message_action_request_key;
    
    M->exchange_id = DS_LVAL (DS_DMA->exchange_id);
    M->g_a = talloc (256);
    str_to_256 (M->g_a, DS_STR (DS_DMA->g_a));
    break;
  case CODE_decrypted_message_action_accept_key:
    M->type = tgl_message_action_accept_key;
    
    M->exchange_id = DS_LVAL (DS_DMA->exchange_id);
    M->g_a = talloc (256);
    str_to_256 (M->g_a, DS_STR (DS_DMA->g_b));
    M->key_fingerprint = DS_LVAL (DS_DMA->key_fingerprint);
    break;
  case CODE_decrypted_message_action_commit_key:
    M->type = tgl_message_action_commit_key;
    
    M->exchange_id = DS_LVAL (DS_DMA->exchange_id);
    M->key_fingerprint = DS_LVAL (DS_DMA->key_fingerprint);
    break;
  case CODE_decrypted_message_action_abort_key:
    M->type = tgl_message_action_abort_key;
    
    M->exchange_id = DS_LVAL (DS_DMA->exchange_id);
    break;
  default:
    assert (0);
  }
}

void tglf_fetch_message_entity (struct tgl_message_entity *E, struct tl_ds_message_entity *DS_ME) {
  E->start = DS_LVAL (DS_ME->offset);
  E->length = DS_LVAL (DS_ME->length);
  switch (DS_ME->magic) {
  case CODE_message_entity_unknown:
    E->type = tgl_message_entity_unknown;
    break;
  case CODE_message_entity_mention:
    E->type = tgl_message_entity_mention;
    break;
  case CODE_message_entity_hashtag:
    E->type = tgl_message_entity_hashtag;
    break;
  case CODE_message_entity_bot_command:
    E->type = tgl_message_entity_bot_command;
    break;
  case CODE_message_entity_url:
    E->type = tgl_message_entity_url;
    break;
  case CODE_message_entity_email:
    E->type = tgl_message_entity_email;
    break;
  case CODE_message_entity_bold:
    E->type = tgl_message_entity_bold;
    break;
  case CODE_message_entity_italic:
    E->type = tgl_message_entity_italic;
    break;
  case CODE_message_entity_code:
    E->type = tgl_message_entity_code;
    break;
  case CODE_message_entity_pre:
    E->type = tgl_message_entity_pre;
    break;
  case CODE_message_entity_text_url:
    E->type = tgl_message_entity_text_url;
    E->extra = DS_STR_DUP (DS_ME->url);
    break;
  default:
    assert (0);
  }
}

void tglf_fetch_message_entities (struct tgl_message *M, struct tl_ds_vector *DS) {
  M->entities_num = DS_LVAL (DS->f1);
  M->entities = talloc0 (M->entities_num * sizeof (struct tgl_message_entity));
  int i;
  for (i = 0; i < M->entities_num; i++) {
    struct tl_ds_message_entity *D = DS->f2[i];
    tglf_fetch_message_entity (&M->entities[i], D);
  }
}

struct tgl_message *tglf_fetch_alloc_message (struct tl_ds_message *DS_M, int *new_msg) {
  if (new_msg) {
    *new_msg = 0;
  }
  //assert (0);
  if (!DS_M || DS_M->magic == CODE_message_empty) { 
    TGL_NOTICE("empty message");
    return NULL; 
  }
  
  tgl_peer_id_t to_id = tglf_fetch_peer_id (DS_M->to_id);
  tgl_peer_t *T = tgl_peer_get (to_id);
  if (!T || !(T->flags & TGLPF_CREATED)) {
    tgl_do_get_difference (0, 0, 0);
    TGL_NOTICE("unknown to_id");
    return NULL;
  }
  tgl_peer_t *P = T;

  tgl_peer_t *F = NULL;
  if (DS_M->from_id) {
    F = tgl_peer_get (TGL_MK_USER (DS_LVAL (DS_M->from_id)));
    if (!F || !(F->flags & TGLPF_CREATED)) {
      tgl_do_get_difference (0, 0, 0);
      TGL_NOTICE("unknown from_id " << DS_LVAL (DS_M->from_id));
      return NULL;
    }
    if (!tgl_cmp_peer_id (to_id, tgl_state::instance()->our_id())) {
      P = F;
    }
  }
  
  tgl_peer_t *FF = NULL;

  if (DS_M->fwd_from_id) {
    tgl_peer_id_t FF_id = tglf_fetch_peer_id (DS_M->fwd_from_id); 
    FF = tgl_peer_get (FF_id);    
    if (!FF) {
      tgl_do_get_difference (0, 0, 0);
      TGL_NOTICE("unknown fwd_id");
      return NULL;
    }
  }

  tgl_message_id_t msg_id = tgl_peer_id_to_msg_id (P->id, DS_LVAL (DS_M->id));
  struct tgl_message *M = tgl_message_get (&msg_id);

  if (!M) {
    M = talloc0 (sizeof (*M));
    M->permanent_id = msg_id;
    tglm_message_insert_tree (M);
    tgl_state::instance()->messages_allocated ++;

    assert (tgl_message_get (&msg_id) == M);
  }
  int new = !(M->flags & TGLMF_CREATED);

  if (new_msg) {
    *new_msg = new;
  }
  if (new) {
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
  
    tgl_peer_id_t from_id;
    if (DS_M->from_id) {
      from_id = F->id;
    } else {
      from_id = TGL_MK_USER (0);
    }
  
    tgl_peer_id_t to_id = T->id;

    tgl_peer_id_t fwd_from_id;
    if (DS_M->fwd_from_id) {
      fwd_from_id = FF->id;
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
    tglm_message_create (DS_LVAL (DS_M->id),
        DS_M->from_id,
        &to_id,
        DS_M->fwd_from_id ? &fwd_from_id : NULL,
        DS_M->fwd_date,
        DS_M->date,
        DS_STR (DS_M->message),
        DS_M->media,
        DS_M->action,
        DS_M->reply_to_msg_id,
        DS_M->reply_markup,
        flags | TGLMF_CREATE | TGLMF_CREATED
        );
  }
  return M;
}

#ifdef ENABLE_SECRET_CHAT
static int decrypt_encrypted_message (struct tgl_secret_chat *E) {
  int *msg_key = decr_ptr;
  decr_ptr += 4;
  assert (decr_ptr < decr_end);
  static unsigned char sha1a_buffer[20];
  static unsigned char sha1b_buffer[20];
  static unsigned char sha1c_buffer[20];
  static unsigned char sha1d_buffer[20];
 
  static unsigned char buf[64];

  int *e_key = E->exchange_state != tgl_sce_committed ? E->key : E->exchange_key;

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
  TGLC_aes_ige_encrypt ((void *)decr_ptr, (void *)decr_ptr, 4 * (decr_end - decr_ptr), &aes_key, iv, 0);
  memset (&aes_key, 0, sizeof (aes_key));

  int x = *(decr_ptr);
  if (x < 0 || (x & 3)) {
    return -1;
  }
  assert (x >= 0 && !(x & 3));
  TGLC_sha1 ((void *)decr_ptr, 4 + x, sha1a_buffer);

    if (memcmp (sha1a_buffer + 4, msg_key, 16)) {
        return -1;
    }
    return 0;
}

struct tgl_message *tglf_fetch_encrypted_message (struct tl_ds_encrypted_message *DS_EM) {
  if (!DS_EM) { return NULL; }
  
  tgl_peer_t *P = tgl_peer_get (TGL_MK_ENCR_CHAT (DS_LVAL (DS_EM->chat_id)));
  if (!P || P->encr_chat.state != sc_ok) {
    vlogprintf (E_WARNING, "Encrypted message to unknown chat. Dropping\n");
    return NULL;
  }

  tgl_message_id_t msg_id = tgl_peer_id_to_msg_id (P->id, DS_LVAL (DS_EM->random_id));
  struct tgl_message *M = tgl_message_get (&msg_id);
  if (!M) {
    M = talloc0 (sizeof (*M));
    M->permanent_id = msg_id;
    tglm_message_insert_tree (M);
    tgl_state::instance()->messages_allocated ++;
    assert (tgl_message_get (&msg_id) == M);
  }

  int new = !(M->flags & TGLMF_CREATED);
  if (!new) {
    return M;
  }

  decr_ptr = (void *)DS_EM->bytes->data;
  decr_end = decr_ptr + (DS_EM->bytes->len / 4);
  
  if (P->encr_chat.exchange_state == tgl_sce_committed && P->encr_chat.key_fingerprint == *(long long *)decr_ptr) {
    tgl_do_confirm_exchange ((void *)P, 0);
    assert (P->encr_chat.exchange_state == tgl_sce_none);
  }
  
  long long key_fingerprint = P->encr_chat.exchange_state != tgl_sce_committed ? P->encr_chat.key_fingerprint : P->encr_chat.exchange_key_fingerprint;
  if (*(long long *)decr_ptr != key_fingerprint) {
    TGL_WARNING("Encrypted message with bad fingerprint to chat " << P->print_name);
    return M;
  }
  
  decr_ptr += 2;

  if (decrypt_encrypted_message (&P->encr_chat) < 0) {
    TGL_WARNING("can not decrypt message");
    return M;
  }
  
  int *save_in_ptr = in_ptr;
  int *save_in_end = in_end;
    
  in_ptr = decr_ptr;
  int ll = *in_ptr;
  in_end = in_ptr + ll / 4 + 1;  
  assert (fetch_int () == ll);

  if (skip_type_decrypted_message_layer (TYPE_TO_PARAM (decrypted_message_layer)) < 0 || in_ptr != in_end) {
    TGL_WARNING("can not fetch message");
    in_ptr = save_in_ptr;
    in_end = save_in_end;
    return M;
  }

  in_ptr = decr_ptr;
  assert (fetch_int () == ll);

  struct tl_ds_decrypted_message_layer *DS_DML = fetch_ds_type_decrypted_message_layer (TYPE_TO_PARAM (decrypted_message_layer));
  assert (DS_DML);

  in_ptr = save_in_ptr;
  in_end = save_in_end;

  //bl_do_encr_chat_set_layer ((void *)P, DS_LVAL (DS_DML->layer));
  bl_do_encr_chat (tgl_get_peer_id (P->id),
    NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL,
    NULL, DS_DML->layer, NULL, NULL, NULL, NULL,
    TGL_FLAGS_UNCHANGED,
    NULL, 0
  );

  int in_seq_no = DS_LVAL (DS_DML->out_seq_no);
  int out_seq_no = DS_LVAL (DS_DML->in_seq_no);

  if (in_seq_no / 2 != P->encr_chat.in_seq_no) {
    TGL_WARNING("Hole in seq in secret chat. in_seq_no = " << in_seq_no / 2 << ", expect_seq_no = " << P->encr_chat.in_seq_no);
    free_ds_type_decrypted_message_layer (DS_DML, TYPE_TO_PARAM(decrypted_message_layer));
    return M;
  }
  
  if ((in_seq_no & 1)  != 1 - (P->encr_chat.admin_id == tgl_get_peer_id (tgl_state::instance()->our_id())) ||
      (out_seq_no & 1) != (P->encr_chat.admin_id == tgl_get_peer_id (tgl_state::instance()->our_id()))) {
    vlogprintf (E_WARNING, "Bad msg admin\n");
    free_ds_type_decrypted_message_layer (DS_DML, TYPE_TO_PARAM(decrypted_message_layer));
    return M;
  }
  if (out_seq_no / 2 > P->encr_chat.out_seq_no) {
    TGL_WARNING("In seq no is bigger than our's out seq no (out_seq_no = " << out_seq_no / 2 << ", our_out_seq_no = " << P->encr_chat.out_seq_no << "). Drop");
    free_ds_type_decrypted_message_layer (DS_DML, TYPE_TO_PARAM(decrypted_message_layer));
    return M;
  }
  if (out_seq_no / 2 < P->encr_chat.last_in_seq_no) {
    TGL_WARNING("Clients in_seq_no decreased (out_seq_no = " << out_seq_no / 2 << ", last_out_seq_no = " << P->encr_chat.last_in_seq_no << "). Drop");
    free_ds_type_decrypted_message_layer (DS_DML, TYPE_TO_PARAM(decrypted_message_layer));
    return M;
  }

  struct tl_ds_decrypted_message *DS_DM = DS_DML->message;
  if (M->permanent_id.id != DS_LVAL (DS_DM->random_id)) {
    TGL_ERROR("Incorrect message: id = " << M->permanent_id.id << ", new_id = " << DS_LVAL (DS_DM->random_id));
    free_ds_type_decrypted_message_layer (DS_DML, TYPE_TO_PARAM(decrypted_message_layer));
    return M;
  }

  tgl_peer_id_t from_id = TGL_MK_USER (P->encr_chat.user_id);
  bl_do_edit_message_encr (&M->permanent_id, &from_id, &P->id, DS_EM->date, DS_STR (DS_DM->message), DS_DM->media, DS_DM->action, DS_EM->file, TGLMF_CREATE | TGLMF_CREATED | TGLMF_ENCRYPTED);

  if (in_seq_no >= 0 && out_seq_no >= 0) {
    //bl_do_encr_chat_update_seq ((void *)P, in_seq_no / 2 + 1, out_seq_no / 2);
    in_seq_no = in_seq_no / 2 + 1;
    out_seq_no = out_seq_no / 2;
    bl_do_encr_chat (tgl_get_peer_id (P->id),
      NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL,
      NULL, NULL, &in_seq_no, &out_seq_no, NULL, NULL,
      TGL_FLAGS_UNCHANGED,
      NULL, 0
    );
    assert (P->encr_chat.in_seq_no == in_seq_no);
  }
  
  free_ds_type_decrypted_message_layer (DS_DML, TYPE_TO_PARAM(decrypted_message_layer));
  return M;
}

void tglf_fetch_encrypted_message_file (struct tgl_message_media *M, struct tl_ds_encrypted_file *DS_EF) {
  if (DS_EF->magic == CODE_encrypted_file_empty) {
    assert (M->type != tgl_message_media_document_encr);
  } else {
    assert (M->type == tgl_message_media_document_encr);
    assert (M->encr_document);

    M->encr_document->id = DS_LVAL (DS_EF->id);
    M->encr_document->access_hash = DS_LVAL (DS_EF->access_hash);
    if (!M->encr_document->size) {
      M->encr_document->size = DS_LVAL (DS_EF->size);
    }
    M->encr_document->dc_id = DS_LVAL (DS_EF->dc_id);
    M->encr_document->key_fingerprint = DS_LVAL (DS_EF->key_fingerprint);
  }
}

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

struct tgl_message *tglf_fetch_alloc_encrypted_message (struct tl_ds_encrypted_message *DS_EM) {
  struct tgl_message *M = tglf_fetch_encrypted_message (DS_EM);
  if (!M) { return M; }

  if (M->flags & TGLMF_CREATED) {
    tgl_peer_t *_E = tgl_peer_get (M->to_id);
    assert (_E);
    struct tgl_secret_chat *E = &_E->encr_chat;
    if (M->action.type == tgl_message_action_request_key) {
      if (E->exchange_state == tgl_sce_none || (E->exchange_state == tgl_sce_requested && E->exchange_id > M->action.exchange_id )) {
        tgl_do_accept_exchange (E, M->action.exchange_id, M->action.g_a);
      } else {
        TGL_WARNING("Exchange: Incorrect state (received request, state = " << E->exchange_state << ")");
      }
    }
    if (M->action.type == tgl_message_action_accept_key) {
      if (E->exchange_state == tgl_sce_requested && E->exchange_id == M->action.exchange_id) {
        tgl_do_commit_exchange (E, M->action.g_a);
      } else {
        TGL_WARNING("Exchange: Incorrect state (received accept, state = " << E->exchange_state << ")");
      }
    }
    if (M->action.type == tgl_message_action_commit_key) {
      if (E->exchange_state == tgl_sce_accepted && E->exchange_id == M->action.exchange_id) {
        tgl_do_confirm_exchange (E, 1);
      } else {
        TGL_WARNING("Exchange: Incorrect state (received commit, state = " << E->exchange_state << ")");
      }
    }
    if (M->action.type == tgl_message_action_abort_key) {
      if (E->exchange_state != tgl_sce_none && E->exchange_id == M->action.exchange_id) {
        tgl_do_abort_exchange (E);
      } else {
        TGL_WARNING("Exchange: Incorrect state (received abort, state = " << E->exchange_state << ")");
      }
    }
    if (M->action.type == tgl_message_action_notify_layer) {
      bl_do_encr_chat (tgl_get_peer_id (E->id),
        NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL,
        NULL, &M->action.layer, NULL, NULL, NULL, NULL,
        TGL_FLAGS_UNCHANGED,
        NULL, 0
      );
    }
    if (M->action.type == tgl_message_action_set_message_ttl) {
      //bl_do_encr_chat_set_ttl (E, M->action.ttl);      
      bl_do_encr_chat (tgl_get_peer_id (E->id),
        NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL,
        &M->action.ttl, NULL, NULL, NULL, NULL, NULL,
        TGL_FLAGS_UNCHANGED,
        NULL, 0
      );
    }
  }
}
#endif

struct tgl_bot_info *tglf_fetch_alloc_bot_info (struct tl_ds_bot_info *DS_BI) {
    if (!DS_BI || DS_BI->magic == CODE_bot_info_empty) { return NULL; }
    struct tgl_bot_info *B = (struct tgl_bot_info *)malloc (sizeof (*B));
    B->version = DS_LVAL (DS_BI->version);
    B->share_text = DS_STR_DUP (DS_BI->share_text);
    B->description = DS_STR_DUP (DS_BI->description);

    B->commands_num = DS_LVAL (DS_BI->commands->cnt);
    B->commands = (struct tgl_bot_command *)malloc (sizeof (struct tgl_bot_command) * B->commands_num);
    int i;
    for (i = 0; i < B->commands_num; i++) {
        struct tl_ds_bot_command *BC = DS_BI->commands->data[i];
        B->commands[i].command = DS_STR_DUP (BC->command);
        B->commands[i].description = DS_STR_DUP (BC->description);
    }
    return B;
}

struct tgl_message_reply_markup *tglf_fetch_alloc_reply_markup (struct tgl_message *M, struct tl_ds_reply_markup *DS_RM) {
    if (!DS_RM) { return NULL; }

    struct tgl_message_reply_markup *R = (struct tgl_message_reply_markup *)talloc0(sizeof (struct tgl_message_reply_markup));
    R->flags = DS_LVAL (DS_RM->flags);
    R->refcnt = 1;

    R->rows = DS_RM->rows ? DS_LVAL (DS_RM->rows->cnt) : 0;

    int total = 0;
    R->row_start = (int *)malloc ((R->rows + 1) * 4);
    R->row_start[0] = 0;
    int i;
    for (i = 0; i < R->rows; i++) {
        struct tl_ds_keyboard_button_row *DS_K = DS_RM->rows->data[i];
        total += DS_LVAL (DS_K->buttons->cnt);
        R->row_start[i + 1] = total;
    }
    R->buttons = (char **)malloc (sizeof (void *) * total);
    int r = 0;
    for (i = 0; i < R->rows; i++) {
        struct tl_ds_keyboard_button_row *DS_K = DS_RM->rows->data[i];
        int j;
        for (j = 0; j < DS_LVAL (DS_K->buttons->cnt); j++) {
            struct tl_ds_keyboard_button *DS_KB = DS_K->buttons->data[j];
            R->buttons[r ++] = DS_STR_DUP (DS_KB->text);
        }
    }
    assert (r == total);
    return R;
}
/* }}} */

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
    tgl_peer_t *P = talloc0 (sizeof (*P));
    P->id = id;
    tglp_insert_user (P);
}

void tgl_insert_empty_chat (int cid) {
    tgl_peer_id_t id = TGL_MK_CHAT (cid);
    if (tgl_peer_get (id)) { return; }
    tgl_peer_t *P = talloc0 (sizeof (*P));
    P->id = id;
    tglp_insert_chat (P);
}

/* {{{ Free */

void tgls_free_photo_size (struct tgl_photo_size *S) {
    tfree_str (S->type);
    if (S->data) {
        tfree (S->data);
    }
}

void tgls_free_photo (struct tgl_photo *P) {
    if (P->caption) { free (P->caption); }
    if (P->sizes) {
        int i;
        for (i = 0; i < P->sizes_num; i++) {
            tgls_free_photo_size (&P->sizes[i]);
        }
        free (P->sizes);
    }
    free (P);
}

void tgls_free_document (struct tgl_document *D) {
    if (D->mime_type) { free (D->mime_type);}
    if (D->caption) { free (D->caption);}
    tgls_free_photo_size (&D->thumb);

    free (D);
}

void tgls_free_webpage (struct tgl_webpage *W) {
    if (--W->refcnt) {
        assert (W->refcnt);
        return;
    }
    if (W->url) { tfree_str (W->url); }
    if (W->display_url) { tfree_str (W->display_url); }
    if (W->title) { tfree_str (W->title); }
    if (W->site_name) { tfree_str (W->site_name); }
    if (W->type) { tfree_str (W->type); }
    if (W->description) { tfree_str (W->description); }
    if (W->photo) { tgls_free_photo (W->photo); }
    if (W->embed_url) { tfree_str (W->embed_url); }
    if (W->embed_type) { tfree_str (W->embed_type); }
    if (W->author) { tfree_str (W->author); }

    tfree (W);
}

void tgls_free_message_media (struct tgl_message_media *M) {
  switch (M->type) {
  case tgl_message_media_none:
  case tgl_message_media_geo:
    return;
  case tgl_message_media_photo:
    tgls_free_photo (M->photo);
    if (M->caption) { tfree_str (M->caption); }
    M->photo = NULL;
    return;
  case tgl_message_media_contact:
    tfree_str (M->phone);
    tfree_str (M->first_name);
    tfree_str (M->last_name);
    return;
  case tgl_message_media_document:
  case tgl_message_media_video:
  case tgl_message_media_audio:
    tgls_free_document (M->document);
    if (M->caption) { tfree_str (M->caption); }
    return;
  case tgl_message_media_unsupported:
    return;
  case tgl_message_media_document_encr:
    tfree_secure (M->encr_document->key, 32);
    tfree_secure (M->encr_document->iv, 32);
    tfree (M->encr_document, sizeof (*M->encr_document));
    return;
  case tgl_message_media_webpage:
    tgls_free_webpage (M->webpage);
    return;
  case tgl_message_media_venue:
    if (M->venue.title) { tfree_str (M->venue.title); }
    if (M->venue.address) { tfree_str (M->venue.address); }
    if (M->venue.provider) { tfree_str (M->venue.provider); }
    if (M->venue.venue_id) { tfree_str (M->venue.venue_id); }
    return;
  default:
    TGL_ERROR("type = 0x" << std::hex << M->type);
    assert (0);
  }
}

void tgls_free_message_action (struct tgl_message_action *M) {
  switch (M->type) {
  case tgl_message_action_none:
    return;
  case tgl_message_action_chat_create:
    tfree_str (M->title);
    tfree (M->users, M->user_num * 4);
    return;
  case tgl_message_action_chat_edit_title:
    tfree_str (M->new_title);
    return;
  case tgl_message_action_chat_edit_photo:
    tgls_free_photo (M->photo);
    M->photo = NULL;
    return;
  case tgl_message_action_chat_add_users:
    tfree (M->users, M->user_num * 4);
    return;
  case tgl_message_action_chat_delete_photo:
  case tgl_message_action_chat_add_user_by_link:
  case tgl_message_action_chat_delete_user:
  case tgl_message_action_geo_chat_create:
  case tgl_message_action_geo_chat_checkin:
  case tgl_message_action_set_message_ttl:
  case tgl_message_action_read_messages:
  case tgl_message_action_delete_messages:
  case tgl_message_action_screenshot_messages:
  case tgl_message_action_flush_history:
  case tgl_message_action_typing:
  case tgl_message_action_resend:
  case tgl_message_action_notify_layer:
  case tgl_message_action_commit_key:
  case tgl_message_action_abort_key:
  case tgl_message_action_noop:
  case tgl_message_action_migrated_to:
    return;
  case tgl_message_action_request_key:
  case tgl_message_action_accept_key:
    tfree (M->g_a, 256);
    return;
  case tgl_message_action_channel_create:
  case tgl_message_action_migrated_from:
    tfree_str (M->title);
    return;
  default:
    TGL_ERROR("type = 0x" << std::hex << M->type);
    assert (0);
}

void tgls_free_message_entity (struct tgl_message_entity *E) {
  if (E->extra) {
    tfree_str (E->extra);
  }
}

void tgls_clear_message (struct tgl_message *M) {
  if (!(M->flags & TGLMF_SERVICE)) {
    if (M->message) { tfree (M->message, M->message_len + 1); }
    tgls_free_message_media (&M->media);
  } else {
    tgls_free_message_action (&M->action);
  }
  int i;
  for (i = 0; i < M->entities_num; i++) {
    tgls_free_message_entity (&M->entities[i]);
  }
  tfree (M->entities, M->entities_num * sizeof (struct tgl_message_entity));
}

void tgls_free_reply_markup (struct tgl_message_reply_markup *R) {
  if (!--R->refcnt) {
    int i;
    for (i = 0; i < R->row_start[R->rows]; i++) {
      tfree_str (R->buttons[i]);
    }
    tfree (R->buttons, R->row_start[R->rows] * sizeof (void *));
    tfree (R->row_start, 4 * (R->rows + 1));
    tfree (R, sizeof (*R));
  } else {
    assert (R->refcnt > 0);
  }
}

void tgls_free_message (struct tgl_message *M) {
    tgls_clear_message(M);
    if (M->reply_markup) {
        tgls_free_reply_markup (M->reply_markup);
    }
    tfree (M);
}

void tgls_free_chat (struct tgl_chat *U) {
  if (U->title) { tfree_str (U->title); }
  if (U->print_title) { tfree_str (U->print_title); }
  if (U->user_list) {
    tfree (U->user_list, U->user_list_size * 12);
  }
  if (U->photo) { tgls_free_photo (U->photo); }
  tfree (U, sizeof (tgl_peer_t));
}

void tgls_free_user (struct tgl_user *U) {
  if (U->first_name) { tfree_str (U->first_name); }
  if (U->last_name) { tfree_str (U->last_name); }
  if (U->print_name) { tfree_str (U->print_name); }
  if (U->phone) { tfree_str (U->phone); }
  if (U->username) { tfree_str (U->username); }
  if (U->real_first_name) { tfree_str (U->real_first_name); }
  if (U->real_last_name) { tfree_str (U->real_last_name); }
  if (U->status.ev) { tgl_remove_status_expire (U); }
  if (U->photo) { tgls_free_photo (U->photo); }
  if (U->bot_info) { tgls_free_bot_info (U->bot_info); }
  tfree (U, sizeof (tgl_peer_t));
}

#ifdef ENABLE_SECRET_CHAT
void tgls_free_encr_chat (struct tgl_secret_chat *U) {
  if (U->print_name) { tfree_str (U->print_name); }
  if (U->g_key) { tfree (U->g_key, 256); } 
  tfree (U, sizeof (tgl_peer_t));
}
#endif

void tgls_free_channel (struct tgl_channel *U) {
  if (U->print_title) { tfree_str (U->print_title); }
  if (U->username) { tfree_str (U->username); }
  if (U->title) { tfree_str (U->title); }
  if (U->about) { tfree_str (U->about); }
  if (U->photo) { tgls_free_photo (U->photo); }
  tfree (U, sizeof (tgl_peer_t));
}

void tgls_free_peer (tgl_peer_t *P) {
  if (tgl_get_peer_type (P->id) == TGL_PEER_USER) {
    tgls_free_user ((void *)P);
  } else if (tgl_get_peer_type (P->id) == TGL_PEER_CHAT) {
    tgls_free_chat ((void *)P);
  } else if (tgl_get_peer_type (P->id) == TGL_PEER_ENCR_CHAT) {
    tgls_free_encr_chat ((void *)P);
  } else if (tgl_get_peer_type (P->id) == TGL_PEER_CHANNEL) {
    tgls_free_channel ((void *)P);
  } else {
    assert (0);
  }
}

void tgls_free_bot_info (struct tgl_bot_info *B) {
    if (!B) { return; }
    int i;
    for (i = 0; i < B->commands_num; i++) {
        tfree_str (B->commands[i].command);
        tfree_str (B->commands[i].description);
    }
    tfree (B->commands);
    tfree_str (B->share_text);
    tfree_str (B->description);
    tfree (B);
}
/* }}} */

/* Messages {{{ */

void tglm_message_add_peer ( struct tgl_message *M) {
  tgl_peer_id_t id;
  if (!tgl_cmp_peer_id (M->to_id, tgl_state::instance()->our_id())) {
    id = M->from_id;
  } else {
    id = M->to_id;
  }
  tgl_peer_t *P = tgl_peer_get (id);
  if (!P) {
    P = talloc0 (sizeof (*P));
    P->id = id;
    switch (tgl_get_peer_type (id)) {
    case TGL_PEER_USER:
      tgl_state::instance()->users_allocated ++;
      break;
    case TGL_PEER_CHAT:
      tgl_state::instance()->chats_allocated ++;
      break;
    case TGL_PEER_GEO_CHAT:
      tgl_state::instance()->geo_chats_allocated ++;
      break;
    case TGL_PEER_ENCR_CHAT:
      tgl_state::instance()->encr_chats_allocated ++;
      break;
    }
    tgl_state::instance()->peer_tree = tree_insert_peer (tgl_state::instance()->peer_tree, P, rand ());
    increase_peer_size ();
    tgl_state::instance()->Peers[tgl_state::instance()->peer_num ++] = P;
  }
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
        if (tgl_get_peer_type (P->id) != TGL_PEER_ENCR_CHAT) {
            struct tgl_message *N = P->last;
            struct tgl_message *NP = 0;
            while (N && N->id > M->id) {
                NP = N;
                N = N->next;
            }
            if (N) {
                assert (N->id < M->id);
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

struct tgl_message *tglm_message_alloc (tgl_message_id_t *id) {
  struct tgl_message *M = (struct tgl_message *)calloc(1, sizeof (struct tgl_message));
  M->permanent_id = *id;
  tglm_message_insert_tree (M);
  tgl_state::instance()->messages_allocated ++;
  return M;
}

void tglm_message_insert_tree (struct tgl_message *M) {
  assert (M->permanent_id.id);
  tgl_state::instance()->message_tree = tree_insert_message (tgl_state::instance()->message_tree, M, rand ());
}

void tglm_message_remove_tree (struct tgl_message *M) {
  assert (M->permanent_id.id);
  tgl_state::instance()->message_tree = tree_delete_message (tgl_state::instance()->message_tree, M);
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
    if (M->id == (*it)->id) {
      tgl_state::instance()->unsent_messages.erase(it);
      return;
    }
  }
}

static void __send_msg (struct tgl_message *M) {
  vlogprintf (E_NOTICE, "Resending message...\n");
  //print_message (M);

  if (M->media.type != tgl_message_media_none) {
    assert (M->flags & TGLMF_ENCRYPTED);
    //bl_do_message_delete (&M->permanent_id);
    tgl_state::instance()->callback.msg_deleted(&M->permanent_id);
  } else {
    tgl_do_send_msg (M, 0, 0);
  }
}

void tglm_send_all_unsent () {
  for (auto it = tgl_state::instance()->unsent_messages.begin(); it != tgl_state::instance()->unsent_messages.end(); it++) {
    __send_msg(*it);
  }
}
/* }}} */

struct tgl_photo *tgl_photo_get (long long id) {
    struct tgl_photo P;
    P.id = id;
    return tree_lookup_photo (tgl_state::instance()->photo_tree, &P);
}

void tgl_photo_insert (struct tgl_photo *P) {
  tgl_state::instance()->photo_tree = tree_insert_photo (tgl_state::instance()->photo_tree, P, rand ());
}

struct tgl_document *tgl_document_get (long long id) {
    struct tgl_document P;
    P.id = id;
    return tree_lookup_document (tgl_state::instance()->document_tree, &P);
}

void tgl_document_insert (struct tgl_document *P) {
  tgl_state::instance()->document_tree = tree_insert_document (tgl_state::instance()->document_tree, P, rand ());
}

struct tgl_webpage *tgl_webpage_get (long long id) {
    struct tgl_webpage P;
    P.id = id;
    return tree_lookup_webpage (tgl_state::instance()->webpage_tree, &P);
}

void tgl_webpage_insert (struct tgl_webpage *P) {
  tgl_state::instance()->webpage_tree = tree_insert_webpage (tgl_state::instance()->webpage_tree, P, rand ());
}

void tglp_peer_insert_name (tgl_peer_t *P) {
  tgl_state::instance()->peer_by_name_tree = tree_insert_peer_by_name (tgl_state::instance()->peer_by_name_tree, P, rand ());
}

void tglp_peer_delete_name (tgl_peer_t *P) {
    tgl_state::instance()->peer_by_name_tree = tree_delete_peer_by_name (tgl_state::instance()->peer_by_name_tree, P);
}

tgl_peer_t *tgl_peer_get (tgl_peer_id_t id) {
    tgl_peer_t U;
    U.id = id;
    return tree_lookup_peer (tgl_state::instance()->peer_tree, &U);
}

struct tgl_message *tgl_message_get (tgl_message_id_t *msg_id) {
  struct tgl_message M;
  if (msg_id->peer_type == TGL_PEER_RANDOM_ID) {
    msg_id = tgls_get_local_by_random (msg_id->id);
  } else if (msg_id->peer_type == TGL_PEER_TEMP_ID) {
    msg_id = tgls_get_local_by_temp (msg_id->id);
  }
  if (!msg_id) {
    return NULL;
  }
  M.permanent_id = *msg_id;
  return tree_lookup_message (tgl_state::instance()->message_tree, &M);
}

tgl_peer_t *tgl_peer_get_by_name (const char *s) {
    static tgl_peer_t P;
    P.print_name = (void *)s;
    tgl_peer_t *R = tree_lookup_peer_by_name (tgl_state::instance()->peer_by_name_tree, &P);
    return R;
}

void tgl_peer_iterator_ex (void (*it)(tgl_peer_t *P, void *extra), void *extra) {
    tree_act_ex_peer (tgl_state::instance()->peer_tree, it, extra);
}

int tgl_complete_user_list (int index, const char *text, int len, char **R) {
    index ++;
    while (index < tgl_state::instance()->peer_num && (!tgl_state::instance()->Peers[index]->print_name || strncmp (tgl_state::instance()->Peers[index]->print_name, text, len) || tgl_get_peer_type (tgl_state::instance()->Peers[index]->id) != TGL_PEER_USER)) {
        index ++;
    }
    if (index < tgl_state::instance()->peer_num) {
        *R = strdup (tgl_state::instance()->Peers[index]->print_name);
        assert (*R);
        return index;
    } else {
        return -1;
    }
}

int tgl_complete_chat_list (int index, const char *text, int len, char **R) {
    index ++;
    while (index < tgl_state::instance()->peer_num && (!tgl_state::instance()->Peers[index]->print_name || strncmp (tgl_state::instance()->Peers[index]->print_name, text, len) || tgl_get_peer_type (tgl_state::instance()->Peers[index]->id) != TGL_PEER_CHAT)) {
        index ++;
    }
    if (index < tgl_state::instance()->peer_num) {
        *R = strdup (tgl_state::instance()->Peers[index]->print_name);
        assert (*R);
        return index;
    } else {
        return -1;
    }
}

int tgl_complete_channel_list (int index, const char *text, int len, char **R) {
  index ++;
  while (index < tgl_state::instance()->peer_num && (!tgl_state::instance()->Peers[index]->print_name || strncmp (tgl_state::instance()->Peers[index]->print_name, text, len) || tgl_get_peer_type (tgl_state::instance()->Peers[index]->id) != TGL_PEER_CHANNEL)) {
    index ++;
  }
  if (index < tgl_state::instance()->peer_num) {
    *R = strdup (tgl_state::instance()->Peers[index]->print_name);
    assert (*R);
    return index;
  } else {
    return -1;
  }
}

int tgl_complete_encr_chat_list (int index, const char *text, int len, char **R) {
    index ++;
    while (index < tgl_state::instance()->peer_num && (!tgl_state::instance()->Peers[index]->print_name || strncmp (tgl_state::instance()->Peers[index]->print_name, text, len) || tgl_get_peer_type (tgl_state::instance()->Peers[index]->id) != TGL_PEER_ENCR_CHAT)) {
        index ++;
    }
    if (index < tgl_state::instance()->peer_num) {
        *R = strdup (tgl_state::instance()->Peers[index]->print_name);
        assert (*R);
        return index;
    } else {
        return -1;
    }
}

int tgl_complete_peer_list (int index, const char *text, int len, char **R) {
    index ++;
    while (index < tgl_state::instance()->peer_num && (!tgl_state::instance()->Peers[index]->print_name || strncmp (tgl_state::instance()->Peers[index]->print_name, text, len))) {
        index ++;
    }
    if (index < tgl_state::instance()->peer_num) {
        *R = strdup (tgl_state::instance()->Peers[index]->print_name);
        assert (*R);
        return index;
    } else {
        return -1;
    }
}

int tgl_secret_chat_for_user (tgl_peer_id_t user_id) {
  int index = 0;
  while (index < tgl_state::instance()->peer_num && (tgl_get_peer_type (tgl_state::instance()->Peers[index]->id) != TGL_PEER_ENCR_CHAT || tgl_state::instance()->Peers[index]->encr_chat.user_id != tgl_get_peer_id (user_id) || tgl_state::instance()->Peers[index]->encr_chat.state != sc_ok)) {
    index ++;
  }
  if (index < tgl_state::instance()->peer_num) {
    return tgl_get_peer_id (tgl_state::instance()->Peers[index]->encr_chat.id);
  } else {
    return -1;
  }
}

void tgls_free_peer_gw (tgl_peer_t *P) {
    tgls_free_peer (P);
}

void tgls_free_message_gw (struct tgl_message *M) {
    tgls_free_message (M);
}

void tgl_free_all () {
  tree_act_ex_peer (tgl_state::instance()->peer_tree, tgls_free_peer_gw);
  tgl_state::instance()->peer_tree = tree_clear_peer (tgl_state::instance()->peer_tree);
  tgl_state::instance()->peer_by_name_tree = tree_clear_peer_by_name (tgl_state::instance()->peer_by_name_tree);
  tree_act_ex_message (tgl_state::instance()->message_tree, tgls_free_message_gw);
  tgl_state::instance()->message_tree = tree_clear_message (tgl_state::instance()->message_tree);
  tree_act_ex_message (tgl_state::instance()->message_unsent_tree, tgls_free_message_gw);
  tgl_state::instance()->message_unsent_tree = tree_clear_message (tgl_state::instance()->message_unsent_tree);
  tglq_query_free_all ();
  tgl_state::instance()->random_id_tree = tree_clear_random_id (tgl_state::instance()->random_id_tree);
  tgl_state::instance()->temp_id_tree = tree_clear_temp_id (tgl_state::instance()->temp_id_tree);

  if (tgl_state::instance()->encr_prime) { tfree (tgl_state::instance()->encr_prime, 256); }

  if (tgl_state::instance()->binlog_name) { tfree_str (tgl_state::instance()->binlog_name); }
  if (tgl_state::instance()->auth_file) { tfree_str (tgl_state::instance()->auth_file); }
  if (tgl_state::instance()->downloads_directory) { tfree_str (tgl_state::instance()->downloads_directory); }
  if (tgl_state::instance()->app_hash) { tfree_str (tgl_state::instance()->app_hash); }
  if (tgl_state::instance()->app_version) { tfree_str (tgl_state::instance()->app_version); }

  if (tgl_state::instance()->error) {
    tfree_str (tgl_state::instance()->error);
  }
  int i;
  for (i = 0; i < tgl_state::instance()->rsa_key_num; i++) {
    if (tgl_state::instance()->rsa_key_list[i]) {
      tfree_str (tgl_state::instance()->rsa_key_list[i]);
    }
  }

  for (i = 0; i <= tgl_state::instance()->max_dc_num; i++) if (tgl_state::instance()->DC_list[i]) {
    tgls_free_dc (tgl_state::instance()->DC_list[i]);
  }
  TGLC_bn_ctx_free (tgl_state::instance()->TGLC_bn_ctx);
  tgls_free_pubkey ();

  if (tgl_state::instance()->ev_login) { tgl_state::instance()->timer_methods->free (tgl_state::instance()->ev_login); }
  if (tgl_state::instance()->online_updates_timer) { tgl_state::instance()->timer_methods->free (tgl_state::instance()->online_updates_timer); }

  tfree (tgl_state::instance()->Peers, tgl_state::instance()->peer_size * sizeof (void *));
}

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

void tgls_messages_mark_read (struct tgl_message *M, int out, int seq) {
  while (M && M->permanent_id.id > seq) { 
    if ((M->flags & TGLMF_OUT) == out) {
      if (!(M->flags & TGLMF_UNREAD)) {
        return;
      }
    }
    while (M) {
        if ((M->flags & TGLMF_OUT) == out) {
            if (M->flags & TGLMF_UNREAD) {
                M->flags &= ~TGLMF_UNREAD;
                tgl_state::instance()->callback.marked_read (1, &M);
            } else {
                return;
            }
        }
        M = M->next;
    }
}
 
/*
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
}*/

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

tgl_message_id_t tgl_convert_temp_msg_id (tgl_message_id_t msg_id) {
  struct tgl_message M;
  M.temp_id = msg_id.id;
  struct tgl_message *N = tree_lookup_temp_id (tgl_state::instance()->temp_id_tree, &M);
  if (N) {
    return N->permanent_id;
  } else {
    return msg_id;
  }
}

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
