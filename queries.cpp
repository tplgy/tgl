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

#define _FILE_OFFSET_BITS 64
#include <errno.h>
#include <string.h>
#include <memory.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifndef WIN32
#include <sys/utsname.h>
#endif

#include "mtproto-client.h"
#include "queries.h"
#include "tgl-log.h"
#include "tgl-structures.h"
#include "tgl_download_manager.h"
#include "tgl-timer.h"
#include "types/tgl_chat.h"
#include "types/tgl_update_callback.h"
#include "types/tgl_peer_id.h"

#include "updates.h"
#include "auto.h"
#include "auto/auto-types.h"
#include "auto/auto-fetch-ds.h"
#include "auto/auto-free-ds.h"
#include "auto/auto-skip.h"
#include "auto/auto-store.h"
#include "auto/auto-print-ds.h"
#include "crypto/bn.h"
#include "crypto/rand.h"
#include "crypto/aes.h"
#include "crypto/sha.h"
#include "crypto/md5.h"
#include "mtproto-common.h"
#include "mtproto-utils.h"

#include "tgl.h"
#include "tg-mime-types.h"
#include "tgl-methods-in.h"
#include "tgl-queries.h"

#ifndef EPROTO
// BSD doesn't define EPROTO, even though it is POSIX:
// https://lists.freebsd.org/pipermail/freebsd-standards/2003-June/000124.html
#define EPROTO EIO
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#ifndef O_BINARY
#define O_BINARY 0
#endif

#define memcmp8(a,b) memcmp ((a), (b), 8)

struct paramed_type bool_type = TYPE_TO_PARAM(bool);

static int mystreq1 (const char *a, const char *b, int l) {
    if ((int)strlen (a) != l) { return 1; }
    return memcmp (a, b, l);
}

/* {{{ COMMON */

std::shared_ptr<query> tglq_query_get(long long id)
{
    for (auto it = tgl_state::instance()->queries_tree.begin(); it != tgl_state::instance()->queries_tree.end(); it++) {
        if (id == (*it)->msg_id) {
            return *it;
        }
    }
    return NULL;
}

void tglq_query_remove (std::shared_ptr<query> q)
{
    for (auto it = tgl_state::instance()->queries_tree.begin(); it != tgl_state::instance()->queries_tree.end(); it++) {
        if (q == (*it)) {
            tgl_state::instance()->queries_tree.erase(it);
            return;
        }
    }
}

static int alarm_query (std::shared_ptr<query> q) {
  assert (q);
  TGL_DEBUG("Alarm query " << q->msg_id << " (type '" << (q->methods->name ? q->methods->name : "") << "')");

  assert(q->ev);
  assert(q->methods);
  q->ev->start(q->methods->timeout ? q->methods->timeout : DEFAULT_QUERY_TIMEOUT);

  if (q->session && q->session_id && q->DC && q->DC->sessions[0] == q->session && q->session->session_id == q->session_id) {
    clear_packet ();
    out_int (CODE_msg_container);
    out_int (1);
    out_long (q->msg_id);
    out_int (q->seq_no);
    out_int (4 * q->data_len);
    out_ints ((int*)q->data, q->data_len);

    tglmp_encrypt_send_message (q->session->c, packet_buffer, packet_ptr - packet_buffer, q->flags & QUERY_FORCE_SEND);
  } else if (q->DC->sessions[0]) {
    q->flags &= ~QUERY_ACK_RECEIVED;
    tglq_query_remove(q);
    q->session = q->DC->sessions[0];
    long long old_id = q->msg_id;
    q->msg_id = tglmp_encrypt_send_message (q->session->c, (int*)q->data, q->data_len, (q->flags & QUERY_FORCE_SEND) | 1);
    TGL_NOTICE("Resent query #" << old_id << " as #" << q->msg_id << " of size " << 4 * q->data_len << " to DC " << q->DC->id);
    tgl_state::instance()->queries_tree.push_back(q);
    q->session_id = q->session->session_id;
    auto dc = q->session->dc.lock();
    if (dc && !(dc->flags & TGLDCF_CONFIGURED) && !(q->flags & QUERY_FORCE_SEND)) {
      q->session_id = 0;
    }
  } else {
    // we don't have a valid session with the DC, so defer query until we do
    q->ev->cancel();
    q->DC->add_pending_query(q);
  }
  return 0;
}

void tglq_regen_query (long long id) {
  std::shared_ptr<query> q = tglq_query_get (id);
  if (!q) { return; }
  q->flags &= ~QUERY_ACK_RECEIVED;

  if (!(q->session && q->session_id && q->DC && q->DC->sessions[0] == q->session && q->session->session_id == q->session_id)) {
    q->session_id = 0;
  } else {
    auto dc = q->session->dc.lock();
    if (dc && !(dc->flags & TGLDCF_CONFIGURED) && !(q->flags & QUERY_FORCE_SEND)) {
      q->session_id = 0;
    }
  }
  TGL_NOTICE("regen query " << id);
  q->ev->start(0.001);
}

#if 0
struct regen_tmp_struct {
  struct tgl_dc *DC;
  struct tgl_session *S;
};

void tglq_regen_query_from_old_session (struct query *q, void *ex) {
  struct regen_tmp_struct *T = ex;
  if (q->DC == T->DC) {
    if (!q->session || q->session_id != T->S->session_id || q->session != T->S) {
      q->session_id = 0;
      TGL_NOTICE("regen query from old session " << q->msg_id);
      q->ev->start(q->methods->timeout ? 0.001 : 0.1);
    }
  }
}

void tglq_regen_queries_from_old_session (struct tgl_dc *DC, struct tgl_session *S) {
  struct regen_tmp_struct T;
  T.DC = DC;
  T.S = S;
  tree_act_ex_query (tgl_state::instance()->queries_tree, tglq_regen_query_from_old_session, &T);
}
#endif

void tglq_query_restart (long long id) {
  std::shared_ptr<query> q = tglq_query_get(id);
  if (q) {
    TGL_NOTICE("restarting query " << id);
    q->ev->cancel();
    alarm_query (q);
  }
}

static void alarm_query_gateway(std::shared_ptr<query> q) {
    alarm_query(q);
}

void tgl_transfer_auth_callback (std::shared_ptr<void> arg, bool success);
void tgl_do_transfer_auth (int num, void (*callback) (std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra);

std::shared_ptr<query> tglq_send_query_ex(std::shared_ptr<tgl_dc> DC, int ints, void *data, struct query_methods *methods, std::shared_ptr<void> extra, void *callback, std::shared_ptr<void> callback_extra, int flags) {
  assert (DC);
  bool pending = false;
  if (!DC->sessions[0]) {
    tglmp_dc_create_session (DC);
    pending = true;
  }
  if (!(DC->flags & TGLDCF_CONFIGURED) && !(flags & QUERY_FORCE_SEND)) {
    pending = true;
  }
  if (!tgl_signed_dc(DC) && !(flags & QUERY_LOGIN) && !(flags & QUERY_FORCE_SEND)) {
    pending = true;
    if (DC != tgl_state::instance()->DC_working && !(flags & QUERY_FORCE_SEND)) {
      tgl_do_transfer_auth(DC->id, tgl_transfer_auth_callback, DC);
    }
  }
  TGL_DEBUG("Sending query \"" << (methods->name ? methods->name : "") << "\" of size " << 4 * ints << " to DC " << DC->id << (pending ? " (pending)" : ""));
  std::shared_ptr<query> q = std::make_shared<query>();
  q->data_len = ints;
  q->data = talloc (4 * ints);
  memcpy (q->data, data, 4 * ints);
  if (pending) {
    q->msg_id = 0;
    q->session = 0;
    q->seq_no = 0;
    q->session_id = 0;
  } else {
    q->msg_id = tglmp_encrypt_send_message (DC->sessions[0]->c, (int*)data, ints, 1 | (flags & QUERY_FORCE_SEND));
    q->session = DC->sessions[0];
    q->seq_no = q->session->seq_no - 1;
    q->session_id = q->session->session_id;
    TGL_DEBUG("Sent query \"" << (methods->name ? methods->name : "") << "\" of size " << 4 * ints << " to DC " << DC->id << ": #" << q->msg_id);
  }
  q->methods = methods;
  q->type = &methods->type;
  q->DC = DC;
  q->flags = flags & ~QUERY_ACK_RECEIVED;
  tgl_state::instance()->queries_tree.push_back(q);

  q->ev = tgl_state::instance()->timer_factory()->create_timer(std::bind(&alarm_query_gateway, q));
  if (!pending) {
    q->ev->start(q->methods->timeout ? q->methods->timeout : DEFAULT_QUERY_TIMEOUT);
  }

  q->extra = extra;
  q->callback = callback;
  q->callback_extra = callback_extra;
  tgl_state::instance()->active_queries ++;
  DC->add_query(q);

  if (pending) {
    DC->add_pending_query(q);
  }
  return q;
}

std::shared_ptr<query> tglq_send_query (std::shared_ptr<tgl_dc> DC, int ints, void *data, struct query_methods *methods, std::shared_ptr<void> extra, void *callback, std::shared_ptr<void> callback_extra) {
  return tglq_send_query_ex(DC, ints, data, methods, extra, (void*)callback, callback_extra, 0);
}

static int fail_on_error(std::shared_ptr<query> q, int error_code, const std::string &error) {
  TGL_UNUSED(q);
  TGL_WARNING("error " << error_code << error);
  assert (0);
  return 0;
}

void tglq_query_ack (long long id) {
    std::shared_ptr<query> q = tglq_query_get (id);
    if (q && !(q->flags & QUERY_ACK_RECEIVED)) {
        assert (q->msg_id == id);
        q->flags |= QUERY_ACK_RECEIVED;
        q->ev->cancel();
    }
}

void tglq_query_delete(long long id) {
    std::shared_ptr<query> q = tglq_query_get (id);
    if (!q) {
        return;
    }

    free (q->data);
    if (q->ev) {
        q->ev->cancel();
        q->ev = nullptr;
    }
    tglq_query_remove(q);
    tgl_state::instance()->active_queries --;
    q->DC->remove_query(q);
}

static void resend_query_cb (std::shared_ptr<void> _q, bool success);

void tglq_free_query (std::shared_ptr<query> q) {
    free (q->data);
    if (q->ev) {
        q->ev->cancel();
        q->ev = nullptr;
    }
}

void tglq_query_free_all () {
    for (auto it = tgl_state::instance()->queries_tree.begin(); it != tgl_state::instance()->queries_tree.end(); it++) {
        tglq_free_query(*it);
    }
    tgl_state::instance()->queries_tree.clear();
}

int tglq_query_error (long long id) {
  assert (fetch_int () == CODE_rpc_error);
  int error_code = fetch_int ();
  int error_len = prefetch_strlen ();
  std::string error = std::string(fetch_str (error_len), error_len);
  std::shared_ptr<query> q = tglq_query_get (id);
  if (!q) {
    TGL_WARNING("error for unknown query #" << id << " #" << error_code << ": " << error);
  } else {
    TGL_WARNING("error for query '" << (q->methods->name ? q->methods->name : "") << "' #" << id << " #" << error_code << ": " << error);
    if (!(q->flags & QUERY_ACK_RECEIVED)) {
      q->ev->cancel();
    }

    tglq_query_remove(q);
    int res = 0;

    int error_handled = 0;

    switch (error_code) {
      case 303:
        // migrate
        {
          int offset = -1;
          if (error_len >= 15 && !memcmp (error.data(), "PHONE_MIGRATE_", 14)) {
            offset = 14;
            //} else if (error_len >= 14 && !memcmp (error, "FILE_MIGRATE_", 13)) {
            //    offset = 13;
        }
        if (error_len >= 17 && !memcmp (error.data(), "NETWORK_MIGRATE_", 16)) {
          offset = 16;
        }
        if (error_len >= 14 && !memcmp (error.data(), "USER_MIGRATE_", 13)) {
          offset = 13;
        }
        if (offset >= 0) {
          int i = 0;
          while (offset < error_len && error.data()[offset] >= '0' && error.data()[offset] <= '9') {
            i = i * 10 + error[offset] - '0';
            offset ++;
          }
          TGL_WARNING("Trying to handle error...");
          if (i > 0 && i < TGL_MAX_DC_NUM) {
            tgl_state::instance()->set_working_dc(i);
            tgl_state::instance()->login();
            q->flags &= ~QUERY_ACK_RECEIVED;
            //q->session_id = 0;
            //struct tgl_dc *DC = q->DC;
            //if (!(DC->flags & 4) && !(q->flags & QUERY_FORCE_SEND)) {
            q->session_id = 0;
            //}
            q->DC = tgl_state::instance()->DC_working;
            q->ev->start(0);
            error_handled = 1;
            res = 1;
            TGL_WARNING("handled");
          }
          if (!error_handled) {
            TGL_WARNING("failed");
          }
        } else {
          TGL_WARNING("wrong offset");
        }
        }
        break;
      case 400:
        // nothing to handle
        // bad user input probably
        break;
      case 401:
        if (!mystreq1 ("SESSION_PASSWORD_NEEDED", error.data(), error_len)) {
          if (!(tgl_state::instance()->locks & TGL_LOCK_PASSWORD)) {
            tgl_state::instance()->locks |= TGL_LOCK_PASSWORD;
            tgl_do_check_password(resend_query_cb, q); // TODO make that a shared_ptr
          }
          res = 1;
          error_handled = 1;
        }
        // TODO: handle AUTH_KEY_INVALID and AUTH_KEY_UNREGISTERED
        break;
      case 403:
        // privacy violation
        break;
      case 404:
        // not found
        break;
      case 420:
        // flood
      case 500:
        // internal error
      default:
        // anything else. Treated as internal error
        {
          int wait;
          if (strncmp (error.data(), "FLOOD_WAIT_", 11)) {
            if (error_code == 420) {
              TGL_ERROR("error = " << error);
            }
            wait = 10;
          } else {
            wait = atoll (error.data() + 11);
          }
          q->flags &= ~QUERY_ACK_RECEIVED;
          q->ev->start(wait);
          std::shared_ptr<tgl_dc> DC = q->DC;
          if (!(DC->flags & 4) && !(q->flags & QUERY_FORCE_SEND)) {
            q->session_id = 0;
          }
          error_handled = 1;
        }
        break;
    }

    if (error_handled) {
      TGL_NOTICE("error for query #" << id << " error:" << error_code << " " << error << " (HANDLED)");
    } else {
      TGL_WARNING("error for query #"<< id << " error:" << error_code << " " << error);
      if (q->methods && q->methods->on_error) {
        res = q->methods->on_error (q, error_code, error);
      }
    }

    q->DC->remove_query(q);

    if (res <= 0) {
      free (q->data);
      if (q->ev) {
          q->ev->cancel();
          q->ev = nullptr;
      }
    }

    if (res == -11) {
      tgl_state::instance()->active_queries --;
      return -1;

    }
  }
  tgl_state::instance()->active_queries --;
  return 0;
}

#define MAX_PACKED_SIZE (1 << 24)
static int packed_buffer[MAX_PACKED_SIZE / 4];

int tglq_query_result (long long id) {
  int op = prefetch_int ();
  int *end = 0;
  int *eend = 0;
  if (op == CODE_gzip_packed) {
    fetch_int ();
    int l = prefetch_strlen ();
    char *s = fetch_str (l);
    int total_out = tgl_inflate (s, l, packed_buffer, MAX_PACKED_SIZE);
    TGL_DEBUG("inflated " << total_out << " bytes");
    end = in_ptr;
    eend = in_end;
    in_ptr = packed_buffer;
    in_end = in_ptr + total_out / 4;
  }
  std::shared_ptr<query> q = tglq_query_get(id);
  if (!q) {
    TGL_WARNING("result for unknown query #" << id);
    in_ptr = in_end;
  } else {
    TGL_DEBUG2("result for query #" << id << ". Size " << (long)4 * (in_end - in_ptr) << " bytes");
    if (!(q->flags & QUERY_ACK_RECEIVED)) {
      q->ev->cancel();
    }
    if (q->methods && q->methods->on_answer) {
      //assert (q->type);
      int *save = in_ptr;
      TGL_DEBUG("in_ptr = " << in_ptr << ", end_ptr = " << in_end);
      if (skip_type_any (q->type) < 0) {
        TGL_ERROR("Skipped " << (long)(in_ptr - save) << " int out of " << (long)(in_end - save) << " (type " << q->type->type->id << ") (query type " << q->methods->name << ")");
        TGL_ERROR("0x" << std::hex << *(save - 1) << " 0x" << *(save) << " 0x" << *(save + 1) << " 0x" << *(save + 2));
        assert (0);
      }

      assert (in_ptr == in_end);
      in_ptr = save;

      void *DS = fetch_ds_type_any (q->type);
      assert (DS);

      q->methods->on_answer(q, DS);
      free_ds_type_any (DS, q->type);

      assert (in_ptr == in_end);
    }
    free (q->data);
    if (q->ev) {
        q->ev->cancel();
        q->ev = nullptr;
    }
    tglq_query_remove(q);

  }
  if (end) {
    in_ptr = end;
    in_end = eend;
  }
  tgl_state::instance()->active_queries --;
  return 0;
}

void tgl_do_insert_header () {
  out_int (CODE_invoke_with_layer);
  out_int (TGL_SCHEME_LAYER);
  out_int (CODE_init_connection);
  out_int (tgl_state::instance()->app_id());

  out_string ("x86");
  out_string ("OSX");
  std::string buf = tgl_state::instance()->app_version() + " (TGL " + TGL_VERSION + ")";
  out_string (buf.c_str());
  out_string ("en");
#if 0
#ifndef WIN32
  if (allow_send_linux_version) {
    struct utsname st;
    uname (&st);
    out_string (st.machine);
    static char buf[4096];
    tsnprintf (buf, sizeof (buf) - 1, "%.999s %.999s %.999s", st.sysname, st.release, st.version);
    out_string (buf);
    tsnprintf (buf, sizeof (buf) - 1, "%s (TGL %s)", tgl_state::instance()->app_version, TGL_VERSION);
    out_string (buf);
    out_string ("En");
  } else {
    out_string ("x86");
    out_string ("OSX");
    std::string buf = tgl_state::instance()->app_version() + " (TGL " + TGL_VERSION + ")";
    out_string (buf.c_str());
    out_string ("en");
  }
#else
    out_string ("x86");
    out_string ("Windows");
    static char buf[4096];
    tsnprintf (buf, sizeof (buf) - 1, "%s (TGL %s)", tgl_state::instance()->app_version, TGL_VERSION);
    out_string (buf);
    out_string ("en");
#endif
#endif
}

void tgl_set_query_error (int error_code, const char *format, ...) __attribute__ ((format (printf, 2, 3)));
void tgl_set_query_error (int error_code, const char *format, ...) {
  static char s[1001];

  va_list ap;
  va_start (ap, format);
  vsnprintf (s, 1000, format, ap);
  va_end (ap);

#if 0
  if (tgl_state::instance()->error) {
    tfree_str (tgl_state::instance()->error);
  }
  tgl_state::instance()->error = tstrdup (s);
  tgl_state::instance()->error_code = error_code;
#endif
}
/* }}} */

/* {{{ Default on error */

static int q_void_on_error (std::shared_ptr<query> q, int error_code, const std::string &error) {
    TGL_ERROR("RPC_CALL_FAIL " <<  error_code << " " << std::string(error));
    if (q->callback) {
        ((void (*)(std::shared_ptr<void>, int))(q->callback))(q->callback_extra, 0);
    }
    return 0;
}

static int q_ptr_on_error (std::shared_ptr<query> q, int error_code, const std::string &error) {
    TGL_ERROR("RPC_CALL_FAIL " <<  error_code << " " << std::string(error));
    if (q->callback) {
        ((void (*)(std::shared_ptr<void>, bool, void *))(q->callback))(q->callback_extra, false, NULL);
    }
    return 0;
}

static int q_list_on_error (std::shared_ptr<query> q, int error_code, const std::string &error) {
    TGL_ERROR("RPC_CALL_FAIL " <<  error_code << " " << std::string(error));
    if (q->callback) {
        ((void (*)(std::shared_ptr<void>, int, int, void *))(q->callback))(q->callback_extra, 0, 0, NULL);
    }
    return 0;
}
/* }}} */

struct msg_callback_extra
{
    msg_callback_extra(long long old_msg_id, tgl_peer_id_t to_id) : old_msg_id(old_msg_id), to_id(to_id) {}
    long long old_msg_id;
    tgl_peer_id_t to_id;
};

#include "queries-encrypted.cpp"

static void increase_ent (int *ent_size, int **ent, int s) {
  *ent = (int *)trealloc (*ent, (*ent_size) * 4, (*ent_size) * 4 + 4 * s);
  (*ent_size) +=s;
}

int utf8_len (const char *s, int len) {
  int i;
  int r = 0;
  for (i = 0; i < len; i++) {
    if ((s[i] & 0xc0) != 0x80) {
      r ++;
    }
  }
  return r;
}

static char *process_html_text (const char *text, int text_len, int *ent_size, int **ent) {
  char *new_text = (char *)talloc (2 * text_len + 1);
  int stpos[100];
  int sttype[100];
  int stp = 0;
  int p;
  int cur_p = 0;
  *ent = (int *)talloc (8);
  *ent_size = 2;
  (*ent)[0] = CODE_vector;
  (*ent)[1] = 0;
  int total = 0;
  for (p = 0; p < text_len; p++) {
    assert (cur_p <= 2 * text_len);
    if (text[p] == '<') {
      if (stp == 99) {
        tgl_set_query_error (EINVAL, "Too nested tags...");
        tfree (new_text, 2 * text_len + 1);
        return NULL;
      }
      int old_p = *ent_size;
      if (text_len - p >= 3 && !memcmp (text + p, "<b>", 3)) {
        increase_ent (ent_size, ent, 3);
        total ++;
        (*ent)[old_p] = CODE_message_entity_bold;
        (*ent)[old_p + 1] = utf8_len (new_text, cur_p);
        stpos[stp] = old_p + 2;
        sttype[stp] = 0;
        stp ++;
        p += 2;
        continue;
      }
      if (text_len - p >= 4 && !memcmp (text + p, "</b>", 4)) {
        if (stp == 0 || sttype[stp - 1]  != 0) {
          tgl_set_query_error (EINVAL, "Invalid tag nest");
          tfree (new_text, 2 * text_len + 1);
          return NULL;
        }
        (*ent)[stpos[stp - 1]] = utf8_len (new_text, cur_p) - (*ent)[stpos[stp - 1] - 1];
        stp --;
        p += 3;
        continue;
      }
      if (text_len - p >= 3 && !memcmp (text + p, "<i>", 3)) {
        increase_ent (ent_size, ent, 3);
        total ++;
        (*ent)[old_p] = CODE_message_entity_italic;
        (*ent)[old_p + 1] = utf8_len (new_text, cur_p);
        stpos[stp] = old_p + 2;
        sttype[stp] = 1;
        stp ++;
        p += 2;
        continue;
      }
      if (text_len - p >= 4 && !memcmp (text + p, "</i>", 4)) {
        if (stp == 0 || sttype[stp - 1]  != 1) {
          tgl_set_query_error (EINVAL, "Invalid tag nest");
          tfree (new_text, 2 * text_len + 1);
          return NULL;
        }
        (*ent)[stpos[stp - 1]] = utf8_len (new_text, cur_p) - (*ent)[stpos[stp - 1] - 1];
        stp --;
        p += 3;
        continue;
      }
      if (text_len - p >= 6 && !memcmp (text + p, "<code>", 6)) {
        increase_ent (ent_size, ent, 3);
        total ++;
        (*ent)[old_p] = CODE_message_entity_code;
        (*ent)[old_p + 1] = utf8_len (new_text, cur_p);
        stpos[stp] = old_p + 2;
        sttype[stp] = 2;
        stp ++;
        p += 5;
        continue;
      }
      if (text_len - p >= 7 && !memcmp (text + p, "</code>", 7)) {
        if (stp == 0 || sttype[stp - 1]  != 2) {
          tgl_set_query_error (EINVAL, "Invalid tag nest");
          tfree (new_text, 2 * text_len + 1);
          return NULL;
        }
        (*ent)[stpos[stp - 1]] = utf8_len (new_text, cur_p) - (*ent)[stpos[stp - 1] - 1];
        stp --;
        p += 6;
        continue;
      }
      if (text_len - p >= 9 && !memcmp (text + p, "<a href=\"", 9)) {
        int pp = p + 9;
        while (pp < text_len && text[pp] != '"') {
          pp ++;
        }
        if (pp == text_len || pp == text_len - 1 || text[pp + 1] != '>') {
          tgl_set_query_error (EINVAL, "<a> tag did not close");
          tfree (new_text, 2 * text_len + 1);
          return NULL;
        }
        int len = pp - p - 9;
        assert (len >= 0);
        if (len >= 250) {
          tgl_set_query_error (EINVAL, "too long link");
          tfree (new_text, 2 * text_len + 1);
          return NULL;
        }

        increase_ent (ent_size, ent, 3 + (len + 1 + ((-len-1) & 3)) / 4);
        total ++;
        (*ent)[old_p] = CODE_message_entity_text_url;
        (*ent)[old_p + 1] = utf8_len (new_text, cur_p);
        stpos[stp] = old_p + 2;
        sttype[stp] = 3;
        stp ++;

        unsigned char *r = (unsigned char *)((*ent) + old_p + 3);
        r[0] = len;
        memcpy (r + 1, text + p + 9, len);
        memset (r + 1 + len, 0, (-len-1) & 3);

        p = pp + 1;
        continue;
      }
      if (text_len - p >= 4 && !memcmp (text + p, "</a>", 4)) {
        if (stp == 0 || sttype[stp - 1]  != 3) {
          tgl_set_query_error (EINVAL, "Invalid tag nest");
          tfree (new_text, 2 * text_len + 1);
          return NULL;
        }
        (*ent)[stpos[stp - 1]] = utf8_len (new_text, cur_p) - (*ent)[stpos[stp - 1] - 1];
        stp --;
        p += 3;
        continue;
      }
      if (text_len - p >= 4 && !memcmp (text + p, "<br>", 4)) {
        new_text[cur_p ++] = '\n';
        p += 3;
        continue;
      }
      tgl_set_query_error (EINVAL, "Unknown tag");
      tfree (new_text, 2 * text_len + 1);
      return NULL;
    } else if (text_len - p >= 4  && !memcmp (text + p, "&gt;", 4)) {
      p += 3;
      new_text[cur_p ++] = '>';
    } else if (text_len - p >= 4  && !memcmp (text + p, "&lt;", 4)) {
      p += 3;
      new_text[cur_p ++] = '<';
    } else if (text_len - p >= 5  && !memcmp (text + p, "&amp;", 5)) {
      p += 4;
      new_text[cur_p ++] = '&';
    } else if (text_len - p >= 6  && !memcmp (text + p, "&nbsp;", 6)) {
      p += 5;
      new_text[cur_p ++] = 0xc2;
      new_text[cur_p ++] = 0xa0;
    } else if (text_len - p >= 3  && text[p] == '&' && text[p + 1] == '#') {
      p += 2;
      int num = 0;
      int ok = 0;
      while (p < text_len) {
        if (text[p] >= '0' && text[p] <= '9') {
          num = num * 10 + text[p] - '0';
          if (num >= 127) {
            tgl_set_query_error (EINVAL, "Too big number in &-sequence");
            tfree (new_text, text_len + 1);
            return NULL;
          }
          p ++;
        } else if (text[p] == ';') {
          new_text[cur_p ++] =  num;
          ok = 1;
          break;
        } else {
          tgl_set_query_error (EINVAL, "Bad &-sequence");
          tfree (new_text, text_len + 1);
          return NULL;
        }
      }
      if (ok) { continue; }
      tgl_set_query_error (EINVAL, "Unterminated &-sequence");
      tfree (new_text, text_len + 1);
      return NULL;
    } else {
      new_text[cur_p ++] = text[p];
    }
  }
  if (stp != 0) {
    tgl_set_query_error (EINVAL, "Invalid tag nest");
    tfree (new_text, text_len + 1);
    return NULL;
  }
  (*ent)[1] = total;
  char *n = (char *)talloc (cur_p + 1);
  memcpy (n, new_text, cur_p);
  n[cur_p] = 0;
  tfree (new_text, 2 * text_len + 1);
  return n;
}

/* {{{ Get config */

static void fetch_dc_option (struct tl_ds_dc_option *DS_DO) {
  //bl_do_dc_option (DS_LVAL (DS_DO->flags), DS_LVAL (DS_DO->id), NULL, 0, DS_STR (DS_DO->ip_address), DS_LVAL (DS_DO->port));
  tgl_state::instance()->set_dc_option (DS_LVAL (DS_DO->flags), DS_LVAL (DS_DO->id), std::string(DS_DO->ip_address->data, DS_DO->ip_address->len), DS_LVAL (DS_DO->port));
}

static int help_get_config_on_answer (std::shared_ptr<query> q, void *DS) {
  struct tl_ds_config *DS_C = (struct tl_ds_config *) DS;

  int i;
  for (i = 0; i < DS_LVAL (DS_C->dc_options->cnt); i++) {
    fetch_dc_option (DS_C->dc_options->data[i]);
  }

  int max_chat_size = DS_LVAL (DS_C->chat_size_max);
  int max_bcast_size = 0;//DS_LVAL (DS_C->broadcast_size_max);
  TGL_DEBUG("chat_size = " << max_chat_size << ", bcast_size = " << max_bcast_size);

  if (q->callback) {
    ((void (*)(std::shared_ptr<void>, bool))(q->callback))(q->callback_extra, 1);
  }
  return 0;
}

static struct query_methods help_get_config_methods  = {
  .on_answer = help_get_config_on_answer,
  .on_error = q_void_on_error,
  .on_timeout = NULL,
  .type = TYPE_TO_PARAM(config),
  .name = "get config",
  .timeout = 1
};

void tgl_do_help_get_config (void (*callback)(std::shared_ptr<void>, bool), std::shared_ptr<void> callback_extra) {
    clear_packet ();
    tgl_do_insert_header ();
    out_int (CODE_help_get_config);
    tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &help_get_config_methods, 0, (void*)callback, callback_extra);
}

static void set_dc_configured (std::shared_ptr<void> _D, bool success);
void tgl_do_help_get_config_dc (std::shared_ptr<tgl_dc> D) {
    clear_packet ();
    tgl_do_insert_header();
    out_int (CODE_help_get_config);
    tglq_send_query_ex (D, packet_ptr - packet_buffer, packet_buffer, &help_get_config_methods, 0, (void*)set_dc_configured, D, QUERY_FORCE_SEND);
}
/* }}} */

/* {{{ Send code */
static int send_code_on_answer (std::shared_ptr<query> q, void *D) {
    struct tl_ds_auth_sent_code *DS_ASC = (struct tl_ds_auth_sent_code *)D;

    char *phone_code_hash = (char*)DS_STR_DUP (DS_ASC->phone_code_hash);
    int registered = DS_BVAL (DS_ASC->phone_registered);;

    if (q->callback) {
        ((void (*)(std::shared_ptr<void>, int, int, const char *))(q->callback)) (q->callback_extra, 1, registered, phone_code_hash);
    }
    free (phone_code_hash);
    return 0;
}

static struct query_methods send_code_methods  = {
  .on_answer = send_code_on_answer,
  .on_error = q_list_on_error,
  .on_timeout = NULL,
  .type = TYPE_TO_PARAM(auth_sent_code),
  .name = "send code",
  .timeout = 0,
};

void tgl_do_send_code (const char *phone, int phone_len, void (*callback)(std::shared_ptr<void>, bool success, int registered, const char *hash), std::shared_ptr<void> callback_extra) {
    TGL_NOTICE("requesting confirmation code from dc " << tgl_state::instance()->DC_working->id);

    clear_packet ();
    tgl_do_insert_header ();
    out_int (CODE_auth_send_code);
    out_cstring (phone, phone_len);
    out_int (0);
    out_int (tgl_state::instance()->app_id());
    out_string (tgl_state::instance()->app_hash().c_str());
    out_string ("en");

    tglq_send_query_ex(tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_code_methods, NULL, (void*)callback, callback_extra, QUERY_LOGIN);
}


static int phone_call_on_answer(std::shared_ptr<query> q, void *D) {
    TGL_UNUSED(D);
    if (q->callback) {
        ((void (*)(std::shared_ptr<void>, int))(q->callback))(q->callback_extra, 1);
    }
    return 0;
}

static struct query_methods phone_call_methods  = {
  .on_answer = phone_call_on_answer,
  .on_error = q_void_on_error,
  .on_timeout = NULL,
  .type = TYPE_TO_PARAM(bool),
  .name = "phone call",
  .timeout = 0,
};

void tgl_do_phone_call (const char *phone, int phone_len, const char *hash, int hash_len, void (*callback)(std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra) {
    TGL_DEBUG("calling user");

    clear_packet ();
    tgl_do_insert_header ();
    out_int (CODE_auth_send_call);
    out_cstring (phone, phone_len);
    out_cstring (hash, hash_len);

    tglq_send_query(tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &phone_call_methods, NULL, (void*)callback, callback_extra);
}
/* }}} */

/* {{{ Sign in / Sign up */
static int sign_in_on_answer (std::shared_ptr<query> q, void *D) {
    TGL_DEBUG2("sign_in_on_answer");
    struct tl_ds_auth_authorization *DS_AA = (struct tl_ds_auth_authorization *)D;

    std::shared_ptr<struct tgl_user> U = tglf_fetch_alloc_user (DS_AA->user);

    tgl_state::instance()->set_dc_signed (tgl_state::instance()->DC_working->id);

    if (q->callback) {
        ((void (*)(std::shared_ptr<void>, int, std::shared_ptr<struct tgl_user>))q->callback)(q->callback_extra, 1, U);
    }

    return 0;
}

static int sign_in_on_error (std::shared_ptr<query> q, int error_code, const std::string &error) {
    TGL_ERROR("RPC_CALL_FAIL " <<  error_code << " " << error);
    if (q->callback) {
        ((void (*)(std::shared_ptr<void>, int))q->callback) (q->callback_extra, 0);
    }
    return 0;
}

static struct query_methods sign_in_methods  = {
  .on_answer = sign_in_on_answer,
  .on_error = sign_in_on_error,
  .on_timeout = NULL,
  .type = TYPE_TO_PARAM(auth_authorization),
  .name = "sign in",
  .timeout = 0,
};

int tgl_do_send_code_result (const char *phone, int phone_len, const char *hash, int hash_len, const char *code, int code_len, void (*callback)(std::shared_ptr<void>, bool success, struct tgl_user *U), std::shared_ptr<void> callback_extra) {
    clear_packet ();
    out_int (CODE_auth_sign_in);
    out_cstring (phone, phone_len);
    out_cstring (hash, hash_len);
    out_cstring (code, code_len);
    tglq_send_query_ex(tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &sign_in_methods, 0, (void*)callback, callback_extra, QUERY_LOGIN);
    return 0;
}

int tgl_do_send_code_result_auth (const char *phone, int phone_len, const char *hash, int hash_len, const char *code, int code_len, const char *first_name, int first_name_len, const char *last_name, int last_name_len, void (*callback)(std::shared_ptr<void>, bool success, struct tgl_user *Self), std::shared_ptr<void> callback_extra) {
    clear_packet ();
    out_int (CODE_auth_sign_up);
    out_cstring (phone, phone_len);
    out_cstring (hash, hash_len);
    out_cstring (code, code_len);
    out_cstring (first_name, first_name_len);
    out_cstring (last_name, last_name_len);
    tglq_send_query_ex(tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &sign_in_methods, 0, (void*)callback, callback_extra, QUERY_LOGIN);
    return 0;
}

int tgl_do_send_bot_auth (const char *code, int code_len, void (*callback)(std::shared_ptr<void>, bool success, struct tgl_user *Self), std::shared_ptr<void> callback_extra) {
    clear_packet ();
    out_int (CODE_auth_import_bot_authorization);
    out_int (0);
    out_int (tgl_state::instance()->app_id());
    out_string (tgl_state::instance()->app_hash().c_str());
    out_cstring (code, code_len);
    tglq_send_query_ex(tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &sign_in_methods, 0, (void*)callback, callback_extra, QUERY_LOGIN);
    return 0;
}
/* }}} */

/* {{{ Get contacts */
static int get_contacts_on_answer (std::shared_ptr<query> q, void *D) {
    TGL_UNUSED(q);
    struct tl_ds_contacts_contacts *DS_CC = (struct tl_ds_contacts_contacts *)D;

    int n = DS_CC->users ? DS_LVAL (DS_CC->users->cnt) : 0;

  int i;
  std::vector<std::shared_ptr<tgl_user>> users(n);
  for (i = 0; i < n; i++) {
    users[i] = tglf_fetch_alloc_user (DS_CC->users->data[i]);
  }
  if (q->callback) {
    ((void (*)(std::shared_ptr<void>, int, int, const std::vector<std::shared_ptr<tgl_user>>&))q->callback) (q->callback_extra, 1, n, users);
  }
  return 0;
}

static struct query_methods get_contacts_methods = {
  .on_answer = get_contacts_on_answer,
  .on_error = q_list_on_error,
  .on_timeout = NULL,
  .type = TYPE_TO_PARAM(contacts_contacts),
  .name = "get contacts",
  .timeout = 0,
};


void tgl_do_update_contact_list () {
    clear_packet ();
    out_int (CODE_contacts_get_contacts);
    out_string ("");
    tglq_send_query(tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &get_contacts_methods, NULL, NULL, NULL);
}
/* }}} */

/* {{{ Send msg (plain text) */
static int msg_send_on_answer (std::shared_ptr<query> q, void *D) {
  struct tl_ds_updates *DS_U = (struct tl_ds_updates *)D;

  std::shared_ptr<msg_callback_extra> old_msg_id = std::static_pointer_cast<msg_callback_extra>(q->extra);

  if (old_msg_id) {
    tgl_state::instance()->callback()->message_sent(old_msg_id->old_msg_id, DS_LVAL(DS_U->id), old_msg_id->to_id);
  }

#if 0
  tgl_message_id_t id;
  id.peer_type = TGL_PEER_RANDOM_ID;
  id.id = old_msg_id->old_msg_id;

  struct tgl_message *M = tgl_message_get (&id);

  if (M && M->permanent_id.id == id.id) {
    tglu_work_any_updates (1, DS_U, M);
    tglu_work_any_updates (0, DS_U, M);
  } else {
#endif
    tglu_work_any_updates (1, DS_U, NULL);
    tglu_work_any_updates (0, DS_U, NULL);
#if 0
  }

  if (q->callback) {
    ((void (*)(std::shared_ptr<void>, int, struct tgl_message *))q->callback) (q->callback_extra, 1, M);
  }
#endif
  return 0;
}

static int msg_send_on_error (std::shared_ptr<query> q, int error_code, const std::string &error) {
  TGL_ERROR("RPC_CALL_FAIL " <<  error_code << " " << error);

#if 0
  tgl_message_id_t id;
  id.peer_type = TGL_PEER_RANDOM_ID;
  id.id = *(long long *)q->extra;
  tfree (q->extra, 8);

  struct tgl_message *M = tgl_message_get (&id);
  if (q->callback) {
    ((void (*)(struct tgl_state *,void *, int, struct tgl_message *))q->callback) (q->callback_extra, 0, M);
  }
  if (M) {
    bl_do_message_delete (TLS, &M->permanent_id);
  }
#endif

  auto x = std::static_pointer_cast<msg_callback_extra>(q->extra);
  if (q->callback) {
    ((void (*)(std::shared_ptr<void>, int, struct tgl_message *))q->callback) (q->callback_extra, 0, NULL);
  }
  tgl_state::instance()->callback()->message_deleted(x->old_msg_id);
  return 0;
}

static struct query_methods msg_send_methods = {
  .on_answer = msg_send_on_answer,
  .on_error = msg_send_on_error,
  .on_timeout = NULL,
  .type = TYPE_TO_PARAM(updates),
  .name = "send message",
  .timeout = 0,
};

void tgl_do_send_msg (struct tgl_message *M, void (*callback)(std::shared_ptr<void>, bool success, struct tgl_message *M), std::shared_ptr<void> callback_extra) {
#ifdef ENABLE_SECRET_CHAT
    if (tgl_get_peer_type (M->to_id) == TGL_PEER_ENCR_CHAT) {
        tgl_do_send_encr_msg (M, callback, callback_extra);
        return;
    }
#endif
  clear_packet ();
  out_int (CODE_messages_send_message);

  unsigned f = ((M->flags & TGLMF_DISABLE_PREVIEW) ? 2 : 0) | (M->reply_id ? 1 : 0) | (M->reply_markup ? 4 : 0) | (M->entities_num > 0 ? 8 : 0);
  if (tgl_get_peer_type (M->from_id) == TGL_PEER_CHANNEL) {
    f |= 16;
  }
  out_int (f);
  out_peer_id (M->to_id);
  if (M->reply_id) {
    out_int (M->reply_id);
  }
  out_cstring (M->message, M->message_len);
  out_long (M->permanent_id.id);

  //TODO
  //long long *x = (long long *)malloc (12);
  //*x = M->id;
  //*(int*)(x+1) = M->to_id.id;

  std::shared_ptr<msg_callback_extra> extra = std::make_shared<msg_callback_extra>(M->permanent_id.id, M->to_id);

  if (M->reply_markup) {
    if (M->reply_markup->rows) {
      out_int (CODE_reply_keyboard_markup);
      out_int (M->reply_markup->flags);
      out_int (CODE_vector);
      out_int (M->reply_markup->rows);
      int i;
      for (i = 0; i < M->reply_markup->rows; i++) {
        out_int (CODE_keyboard_button_row);
        out_int (CODE_vector);
        out_int (M->reply_markup->row_start[i + 1] - M->reply_markup->row_start[i]);
        int j;
        for (j = 0; j < M->reply_markup->row_start[i + 1] - M->reply_markup->row_start[i]; j++) {
          out_int (CODE_keyboard_button);
          out_string (M->reply_markup->buttons[j + M->reply_markup->row_start[i]]);
        }
      }
    } else {
      out_int (CODE_reply_keyboard_hide);
    }
  }

  if (M->entities_num > 0) {
    out_int (CODE_vector);
    out_int (M->entities_num);
    int i;
    for (i = 0; i < M->entities_num; i++) {
      struct tgl_message_entity *E = &M->entities[i];
      switch (E->type) {
      case tgl_message_entity_bold:
        out_int (CODE_message_entity_bold);
        out_int (E->start);
        out_int (E->length);
        break;
      case tgl_message_entity_italic:
        out_int (CODE_message_entity_italic);
        out_int (E->start);
        out_int (E->length);
        break;
      case tgl_message_entity_code:
        out_int (CODE_message_entity_code);
        out_int (E->start);
        out_int (E->length);
        break;
      case tgl_message_entity_text_url:
        out_int (CODE_message_entity_text_url);
        out_int (E->start);
        out_int (E->length);
        out_string (E->extra);
        break;
      default:
        assert (0);
      }
    }
  }

  tglq_send_query(tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &msg_send_methods, extra, (void*)callback, callback_extra);
}

void tgl_do_send_message (tgl_peer_id_t peer_id, const char *text, int text_len, unsigned long long flags, struct tl_ds_reply_markup *reply_markup, void (*callback)(std::shared_ptr<void>, bool success, struct tgl_message *M), std::shared_ptr<void> callback_extra) {
  if (tgl_get_peer_type (peer_id) == TGL_PEER_ENCR_CHAT) {
#ifdef ENABLE_SECRET_CHAT
    std::shared_ptr<tgl_secret_chat> secret_chat = tgl_state::instance()->secret_chat_for_id(peer_id);
    if (!secret_chat) {
      tgl_set_query_error (EINVAL, "unknown secret chat");
      if (callback) {
        callback (callback_extra, 0, 0);
      }
      return;
    }
    if (secret_chat->state != sc_ok) {
      tgl_set_query_error (EINVAL, "secret chat not in ok state");
      if (callback) {
        callback (callback_extra, 0, 0);
      }
      return;
    }
#endif
  }

  int date = time (0);

  struct tgl_message_id id = tgl_peer_id_to_random_msg_id (peer_id);

  struct tgl_message *M = NULL;

  if (tgl_get_peer_type (peer_id) != TGL_PEER_ENCR_CHAT) {
    //int reply = (flags >> 32);
    int disable_preview = flags & TGL_SEND_MSG_FLAG_DISABLE_PREVIEW;
    //if (!(flags & TGL_SEND_MSG_FLAG_ENABLE_PREVIEW) && tgl_state::instance()->disable_link_preview) {
      //disable_preview = 1;
    //}
    if (disable_preview) {
      disable_preview = TGLMF_DISABLE_PREVIEW;
    }
    struct tl_ds_message_media TDSM;
    TDSM.magic = CODE_message_media_empty;

    tgl_peer_id_t from_id;
    if (flags & TGLMF_POST_AS_CHANNEL) {
      from_id = peer_id;
    } else {
      from_id = tgl_state::instance()->our_id();
    }

    //struct tl_ds_vector *EN = NULL;
    char *new_text = NULL;

    if (flags & TGLMF_HTML) {
      int ent_size = 0;
      int *ent = NULL;
      text = new_text = process_html_text (text, text_len, &ent_size, &ent);
      if (!text) {
        tfree (ent, ent_size);
        if (callback) {
          callback (callback_extra, 0, 0);
        }
        return;    
      }
      text_len = strlen (new_text);
      int *save_ptr = in_ptr;
      int *save_end = in_end;
      in_ptr = ent;
      in_end = ent + ent_size;
      //EN = fetch_ds_type_any (TYPE_TO_PARAM_1 (vector, TYPE_TO_PARAM (message_entity)));
      //assert (EN);
      TGL_DEBUG("in_ptr = " << in_ptr << ", in_end = " << in_end);
      assert (in_ptr == in_end);
      in_ptr = save_ptr;
      in_end = save_end;
      tfree (ent, 4 * ent_size);
    }


    //bl_do_edit_message (&id, &from_id, &peer_id, NULL, NULL, &date, text, text_len, &TDSM, NULL, reply ? &reply : NULL, reply_markup, EN, TGLMF_UNREAD | TGLMF_OUT | TGLMF_PENDING | TGLMF_CREATE | TGLMF_CREATED | TGLMF_SESSION_OUTBOUND | disable_preview);
    M = tglm_message_create (&id, &from_id, &peer_id, NULL, NULL, &date, text, &TDSM, NULL, NULL,
        reply_markup, TGLMF_UNREAD | TGLMF_OUT | TGLMF_PENDING | TGLMF_CREATE | TGLMF_CREATED | TGLMF_SESSION_OUTBOUND | TGLMF_TEMP_MSG_ID);

    if (flags & TGLMF_HTML) {
      tfree_str (new_text);
      //free_ds_type_any (EN, TYPE_TO_PARAM_1 (vector, TYPE_TO_PARAM (message_entity)));
    }

  } else {
    struct tl_ds_decrypted_message_media TDSM;
    TDSM.magic = CODE_decrypted_message_media_empty;

    tgl_peer_id_t from_id = tgl_state::instance()->our_id();
    //bl_do_edit_message_encr (&id, &from_id, &peer_id, &date, text, text_len, &TDSM, NULL, NULL, TGLMF_UNREAD | TGLMF_OUT | TGLMF_PENDING | TGLMF_CREATE | TGLMF_CREATED | TGLMF_SESSION_OUTBOUND | TGLMF_ENCRYPTED);
    M = tglm_create_encr_message(&id, &from_id, &peer_id, &date, text, text_len, &TDSM, NULL, NULL, TGLMF_UNREAD | TGLMF_OUT | TGLMF_PENDING | TGLMF_CREATE | TGLMF_CREATED | TGLMF_SESSION_OUTBOUND | TGLMF_ENCRYPTED);
  }

  tgl_do_send_msg (M, callback, callback_extra);
  tgls_free_message(M);
}

void tgl_do_reply_message (tgl_message_id_t *_reply_id, const char *text, int text_len, unsigned long long flags, void (*callback)(std::shared_ptr<void>, bool success, struct tgl_message *M), std::shared_ptr<void> callback_extra) {
  tgl_message_id_t reply_id = *_reply_id;
  if (reply_id.peer_type == TGL_PEER_TEMP_ID) {
    reply_id = tgl_convert_temp_msg_id (reply_id);
  }
  if (reply_id.peer_type == TGL_PEER_TEMP_ID) {
    tgl_set_query_error (EINVAL, "unknown message");
    if (callback) {
      callback (callback_extra, 0, 0);
    }
    return;
  }
  if (reply_id.peer_type == TGL_PEER_ENCR_CHAT) {
    tgl_set_query_error (EINVAL, "can not reply on message from secret chat");
    if (callback) {
      callback (callback_extra, 0, 0);
    }

    tgl_peer_id_t peer_id = tgl_msg_id_to_peer_id (reply_id);

    tgl_do_send_message (peer_id, text, text_len, flags | TGL_SEND_MSG_FLAG_REPLY (reply_id.id), NULL, callback, callback_extra);
  }
}
/* }}} */

/* {{{ Send text file */
void tgl_do_send_text (tgl_peer_id_t id, const char *file_name, unsigned long long flags, void (*callback)(std::shared_ptr<void>, bool success, struct tgl_message *M), std::shared_ptr<void> callback_extra) {
  int fd = open (file_name, O_RDONLY | O_BINARY);
  if (fd < 0) {
    tgl_set_query_error (EBADF, "Can not open file: %s", strerror(errno));
    if (callback) {
      callback (callback_extra, 0, NULL);
    }
    return;
  }
  static char buf[(1 << 20) + 1];
  int x = read (fd, buf, (1 << 20) + 1);
  if (x < 0) {
    tgl_set_query_error (EBADF, "Can not read from file: %s", strerror(errno));
    close (fd);
    if (callback) {
      callback (callback_extra, 0, NULL);
    }

    assert (x >= 0);
    close (fd);
    if (x == (1 << 20) + 1) {
        tgl_set_query_error (E2BIG, "text file is too big");
        if (callback) {
            callback (callback_extra, 0, NULL);
        }
    } else {
        tgl_do_send_message (id, buf, x, flags, NULL, callback, callback_extra);
    }
  }
}

void tgl_do_reply_text (tgl_message_id_t *_reply_id, const char *file_name, unsigned long long flags, void (*callback)(std::shared_ptr<void>, bool success, struct tgl_message *M), std::shared_ptr<void> callback_extra) {
  tgl_message_id_t reply_id = *_reply_id;
  if (reply_id.peer_type == TGL_PEER_TEMP_ID) {
    reply_id = tgl_convert_temp_msg_id (reply_id);
  }
  if (reply_id.peer_type == TGL_PEER_TEMP_ID) {
    tgl_set_query_error (EINVAL, "unknown message");
    if (callback) {
      callback (callback_extra, 0, 0);
    }
    return;
  }
  if (reply_id.peer_type == TGL_PEER_ENCR_CHAT) {
    tgl_set_query_error (EINVAL, "can not reply on message from secret chat");
    if (callback) {
      callback (callback_extra, 0, 0);
    }

    tgl_peer_id_t peer_id = tgl_msg_id_to_peer_id (reply_id);

    tgl_do_send_text (peer_id, file_name, flags | TGL_SEND_MSG_FLAG_REPLY (reply_id.id), callback, callback_extra);
  }
}
/* }}} */

/* {{{ Mark read */

struct mark_read_extra {
    tgl_peer_id_t id;
    int max_id;
};

void tgl_do_messages_mark_read (tgl_peer_id_t id, int max_id, int offset, void (*callback)(std::shared_ptr<void> , int), std::shared_ptr<void> );

static int mark_read_channels_on_receive (std::shared_ptr<query> q, void *D) {
  std::shared_ptr<mark_read_extra> E = std::static_pointer_cast<mark_read_extra>(q->extra);

  //bl_do_channel (tgl_get_peer_id (E->id), NULL, NULL, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL,
    //&E->max_id, TGL_FLAGS_UNCHANGED);
  
  if (q->callback) {
    ((void (*)(std::shared_ptr<void>, bool))q->callback)(q->callback_extra, 1);
  }
  return 0;
}

static int mark_read_on_receive (std::shared_ptr<query> q, void *D) {
  struct tl_ds_messages_affected_messages *DS_MAM = (struct tl_ds_messages_affected_messages *)D;

  int r = tgl_check_pts_diff (DS_LVAL (DS_MAM->pts), DS_LVAL (DS_MAM->pts_count));

  if (r > 0) {
    //bl_do_set_pts (DS_LVAL (DS_MAM->pts));
    tgl_state::instance()->set_pts(DS_LVAL(DS_MAM->pts));
  }

  std::shared_ptr<mark_read_extra> E = std::static_pointer_cast<mark_read_extra>(q->extra);

  if (tgl_get_peer_type (E->id) == TGL_PEER_USER) {
    //bl_do_user (tgl_get_peer_id (E->id), NULL, NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, &E->max_id, NULL, NULL, TGL_FLAGS_UNCHANGED);
    tgl_state::instance()->callback()->new_user(tgl_get_peer_id (E->id), "", "", "", "", 0, 0);
  } else {
    assert (tgl_get_peer_type (E->id) == TGL_PEER_CHAT);
    //bl_do_chat (tgl_get_peer_id (E->id), NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &E->max_id, NULL, TGL_FLAGS_UNCHANGED);
    //tgl_state::instance()->callback()->chat_update (tgl_get_peer_id (E->id), &E->max_id, 0);
  }
  if (q->callback) {
    ((void (*)(std::shared_ptr<void>, int))q->callback)(q->callback_extra, 1);
  }

  return 0;
}

static int mark_read_on_error (std::shared_ptr<query> q, int error_code, const std::string &error) {
    TGL_ERROR("RPC_CALL_FAIL " <<  error_code << " " << error);

    std::shared_ptr<mark_read_extra> E = std::static_pointer_cast<mark_read_extra>(q->extra);
    if (q->callback) {
        ((void (*)(std::shared_ptr<void>, int))q->callback)(q->callback_extra, 0);
    }
    return 0;
}

static struct query_methods mark_read_methods = {
  .on_answer = mark_read_on_receive,
  .on_error = mark_read_on_error,
  .on_timeout = NULL,
  .type = TYPE_TO_PARAM(messages_affected_history),
  .name = "mark read",
  .timeout = 0,
};

static struct query_methods mark_read_channels_methods = {
  .on_answer = mark_read_channels_on_receive,
  .on_error = q_void_on_error,
  .on_timeout = NULL,
  .type = TYPE_TO_PARAM(bool),
  .name = "mark read (channels)",
  .timeout = 0,
};

void tgl_do_messages_mark_read (tgl_peer_id_t id, int max_id, int offset, void (*callback)(std::shared_ptr<void>, bool), std::shared_ptr<void> callback_extra) {
  //if (tgl_state::instance()->is_bot) { return; }
  if (tgl_get_peer_type (id) == TGL_PEER_ENCR_CHAT) {
    //tgl_do_mark_read (id, callback, callback_extra);
    return;
  }
  clear_packet ();
  if (tgl_get_peer_type (id) != TGL_PEER_CHANNEL) {
    out_int (CODE_messages_read_history);
    out_peer_id(id);
    out_int (max_id);
    //out_int (offset);

    std::shared_ptr<mark_read_extra> E = std::make_shared<mark_read_extra>();
    E->id = id;
    E->max_id = max_id;

    tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &mark_read_methods, E, (void*)callback, callback_extra);
  } else {
    out_int (CODE_channels_read_history);

    out_int (CODE_input_channel);
    out_int (tgl_get_peer_id (id));
    out_long (id.access_hash);
    
    out_int (max_id);

    std::shared_ptr<mark_read_extra> E = std::make_shared<mark_read_extra>();
    E->id = id;
    E->max_id = max_id;
    
    tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &mark_read_channels_methods, E, (void*)callback, callback_extra);
  }
}

void tgl_do_mark_read (tgl_peer_id_t id, void (*callback)(std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra) {
  if (tgl_get_peer_type (id) == TGL_PEER_USER || tgl_get_peer_type (id) == TGL_PEER_CHAT || tgl_get_peer_type (id) == TGL_PEER_CHANNEL) {
    tgl_do_messages_mark_read (id, 0, 0, callback, callback_extra);
    return;
  }
#ifdef ENABLE_SECRET_CHAT
  assert (tgl_get_peer_type (id) == TGL_PEER_ENCR_CHAT);
  std::shared_ptr<tgl_secret_chat> secret_chat = tgl_state::instance()->secret_chat_for_id(id);
  if (!secret_chat) {
    tgl_set_query_error (EINVAL, "unknown secret chat");
    if (callback) {
      callback (callback_extra, 0);
    }
    return;
  }
  if (secret_chat->last) {
    tgl_do_messages_mark_read_encr (id, secret_chat->access_hash, secret_chat->last->date, callback, callback_extra);
  } else {
    tgl_do_messages_mark_read_encr (id, secret_chat->access_hash, time (0) - 10, callback, callback_extra);
  }
#endif
}
/* }}} */

/* {{{ Get history */
struct get_history_extra {
    std::vector<tgl_message*> ML;
    tgl_peer_id_t id;
    int limit;
    int offset;
    int max_id;
};

static void _tgl_do_get_history (std::shared_ptr<get_history_extra> E, void (*callback)(std::shared_ptr<void>, bool success, std::vector<tgl_message*> list), std::shared_ptr<void> );


static int get_history_on_answer (std::shared_ptr<query> q, void *D) {
  struct tl_ds_messages_messages *DS_MM = (struct tl_ds_messages_messages *)D;

  int i;
  for (i = 0; i < DS_LVAL (DS_MM->chats->cnt); i++) {
    tglf_fetch_alloc_chat (DS_MM->chats->data[i]);
  }

  for (i = 0; i < DS_LVAL (DS_MM->users->cnt); i++) {
    tglf_fetch_alloc_user (DS_MM->users->data[i]);
  }

  std::shared_ptr<get_history_extra> E = std::static_pointer_cast<get_history_extra>(q->extra);

  int n = DS_LVAL (DS_MM->messages->cnt);

  for (i = 0; i < n; i++) {
    E->ML.push_back(tglf_fetch_alloc_message (DS_MM->messages->data[i], NULL));
  }
  E->offset += n;
  E->limit -= n;

  int count = DS_LVAL (DS_MM->count);
  if (count >= 0 && E->limit + E->offset >= count) {
    E->limit = count - E->offset;
    if (E->limit < 0) { E->limit = 0; }
  }
  assert (E->limit >= 0);


  if (E->limit <= 0 || DS_MM->magic == CODE_messages_messages || DS_MM->magic == CODE_messages_channel_messages) {
    if (q->callback) {
      ((void (*)(std::shared_ptr<void>, int, const std::vector<tgl_message*> &))q->callback) (q->callback_extra, 1, E->ML);
    }
    /*if (E->ML.size() > 0) {
      tgl_do_messages_mark_read (E->id, E->ML[0]->id, 0, 0, 0);
    }*/
  } else {
    E->offset = 0;
    E->max_id = E->ML[E->ML.size()-1]->permanent_id.id;
    _tgl_do_get_history (E, (void (*)(std::shared_ptr<void>, bool, std::vector<tgl_message*> list))q->callback, q->callback_extra);
  }
  return 0;
}

static int get_history_on_error (std::shared_ptr<query> q, int error_code, const std::string &error) {
    TGL_ERROR("RPC_CALL_FAIL " <<  error_code << " " << error);

    std::shared_ptr<get_history_extra> E = std::static_pointer_cast<get_history_extra>(q->extra);

    if (q->callback) {
        ((void (*)(std::shared_ptr<void>, int, int, struct tgl_message **))q->callback) (q->callback_extra, 0, 0, NULL);
    }
    return 0;
}

static struct query_methods get_history_methods = {
  .on_answer = get_history_on_answer,
  .on_error = get_history_on_error,
  .on_timeout = NULL,
  .type = TYPE_TO_PARAM(messages_messages),
  .name = "get history",
  .timeout = 0,
};


static void _tgl_do_get_history (std::shared_ptr<get_history_extra> E, void (*callback)(std::shared_ptr<void>, bool success, std::vector<tgl_message*> list), std::shared_ptr<void> callback_extra) {
  clear_packet ();
  //tgl_peer_t *C = tgl_peer_get (E->id);
  if (tgl_get_peer_type (E->id) != TGL_PEER_CHANNEL) {// || (C && (C->flags & TGLCHF_MEGAGROUP))) {
    out_int (CODE_messages_get_history);
    out_peer_id (E->id);
  } else {    
    out_int (CODE_channels_get_important_history);
    
    out_int (CODE_input_channel);
    out_int (tgl_get_peer_id (E->id));
    out_long (E->id.access_hash);
  }
  out_int (E->max_id);
  out_int (E->offset);
  out_int (E->limit);
  out_int (0);
  out_int (0);
  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &get_history_methods, E, (void*)callback, callback_extra);
}

void tgl_do_get_history (tgl_peer_id_t id, int offset, int limit, int offline_mode,
    void (*callback)(std::shared_ptr<void>, bool success, std::vector<tgl_message*> list), std::shared_ptr<void> callback_extra) {
  if (tgl_get_peer_type (id) == TGL_PEER_ENCR_CHAT || offline_mode) {
#ifdef ENABLE_SECRET_CHAT
    // FIXME
    //tgl_do_get_local_history (id, offset, limit, callback, callback_extra);
    //tgl_do_mark_read (id, 0, 0);
#endif
    return;
  }
  std::shared_ptr<get_history_extra> E = std::make_shared<get_history_extra>();
  E->id = id;
  E->limit = limit;
  E->offset = offset;
  _tgl_do_get_history (E, callback, callback_extra);
}
/* }}} */

/* {{{ Get dialogs */
struct get_dialogs_extra {
  tgl_peer_id_t *PL;
  int *UC = NULL;
  tgl_message_id_t **LM = NULL;
  tgl_message_id_t *LMD;
  int *LRM = NULL;

  int list_offset = 0;
  int list_size = 0;
  int limit = 0;
  int offset = 0;
  int offset_date;
  int max_id = 0;
  tgl_peer_id_t offset_peer;

  int channels;
};

static void _tgl_do_get_dialog_list (std::shared_ptr<get_dialogs_extra> E, void (*callback)(std::shared_ptr<void>, bool success, int size, tgl_peer_id_t peers[], tgl_message_id_t *last_msg_id[], int unread_count[]), std::shared_ptr<void> );

static int get_dialogs_on_answer (std::shared_ptr<query> q, void *D) {
  struct tl_ds_messages_dialogs *DS_MD = (struct tl_ds_messages_dialogs *)D;

  std::shared_ptr<get_dialogs_extra> E = std::static_pointer_cast<get_dialogs_extra>(q->extra);

  int dl_size = DS_LVAL (DS_MD->dialogs->cnt);

  int i;
  for (i = 0; i < DS_LVAL (DS_MD->chats->cnt); i++) {
    tglf_fetch_alloc_chat (DS_MD->chats->data[i]);
  }

  for (i = 0; i < DS_LVAL (DS_MD->users->cnt); i++) {
    tglf_fetch_alloc_user (DS_MD->users->data[i]);
  }

  if (E->list_offset + dl_size > E->list_size) {
    int new_list_size = E->list_size * 2;
    if (new_list_size < E->list_offset + dl_size) {
      new_list_size = E->list_offset + dl_size;
    }

    E->PL = (tgl_peer_id_t *)trealloc (E->PL, E->list_size * sizeof (tgl_peer_id_t), new_list_size * sizeof (tgl_peer_id_t));
    assert (E->PL);
    E->UC = (int *)trealloc (E->UC, E->list_size * sizeof (int), new_list_size * sizeof (int));
    assert (E->UC);
    E->LM = (tgl_message_id_t **)trealloc (E->LM, E->list_size * sizeof (void *), new_list_size * sizeof (void *));
    assert (E->LM);
    E->LMD = (tgl_message_id_t *)trealloc (E->LMD, E->list_size * sizeof (tgl_message_id_t), new_list_size * sizeof (tgl_message_id_t));
    assert (E->LMD);
    E->LRM = (int *)trealloc (E->LRM, E->list_size * sizeof (int), new_list_size * sizeof (int));
    assert (E->LRM);

    E->list_size = new_list_size;

    int i;
    for (i = 0; i < E->list_offset; i++) {
      E->LM[i] = &E->LMD[i];
    }
  }

  for (i = 0; i < dl_size; i++) {
    struct tl_ds_dialog *DS_D = DS_MD->dialogs->data[i];
    tgl_peer_id_t peer_id = tglf_fetch_peer_id (DS_D->peer);
    E->PL[E->list_offset + i] = peer_id;
    E->LMD[E->list_offset + i] = tgl_peer_id_to_msg_id (E->PL[E->list_offset + i], DS_LVAL (DS_D->top_message));
    E->LM[E->list_offset + i] = &E->LMD[E->list_offset + i];
    E->UC[E->list_offset + i] = DS_LVAL (DS_D->unread_count);
    E->LRM[E->list_offset + i] = DS_LVAL (DS_D->read_inbox_max_id);
  }
  E->list_offset += dl_size;

  for (i = 0; i < DS_LVAL (DS_MD->messages->cnt); i++) {
    tglf_fetch_alloc_message (DS_MD->messages->data[i], NULL);
  }

  TGL_DEBUG("dl_size = " << dl_size << ", total = " << E->list_offset);
  if (dl_size && E->list_offset < E->limit && DS_MD->magic == CODE_messages_dialogs_slice && E->list_offset < DS_LVAL (DS_MD->count)) {
    E->offset += dl_size;
    if (E->list_offset > 0) {
      E->offset_peer = E->PL[E->list_offset - 1];
    
      int p = E->list_offset - 1;
      while (p >= 0) {
#if 0
        struct tgl_message *M = tgl_message_get (E->LM[p]);
        if (M) {
          E->offset_date = M->date;
          break;
        }
#endif
        p --;
      }
    }
    _tgl_do_get_dialog_list(E, (void (*)(std::shared_ptr<void>, bool , int , tgl_peer_id_t [], tgl_message_id_t *[], int []))q->callback, q->callback_extra);
  } else {
    if (q->callback) {
      ((void (*)(std::shared_ptr<void>, int, int, tgl_peer_id_t *, tgl_message_id_t **, int *))q->callback) (q->callback_extra, 1, E->list_offset, E->PL, E->LM, E->UC);
    }
    tfree (E->PL, sizeof (tgl_peer_id_t) * E->list_size);
    tfree (E->UC, 4 * E->list_size);
    tfree (E->LM, sizeof (void *) * E->list_size);
    tfree (E->LMD, sizeof (tgl_message_id_t) * E->list_size);
    tfree (E->LRM, 4 * E->list_size);
  }

  return 0;
}

static int get_dialogs_on_error (std::shared_ptr<query> q, int error_code, const std::string &error) {
  TGL_ERROR("RPC_CALL_FAIL " <<  error_code << " " << error);

  std::shared_ptr<get_dialogs_extra> E = std::static_pointer_cast<get_dialogs_extra>(q->extra);
  tfree (E->PL, sizeof (tgl_peer_id_t) * E->list_size);
  tfree (E->UC, 4 * E->list_size);
  tfree (E->LM, sizeof (void *) * E->list_size);
  tfree (E->LMD, sizeof (tgl_message_id_t) * E->list_size);
  tfree (E->LRM, 4 * E->list_size);
  if (q->callback) {
    ((void (*)(std::shared_ptr<void>, int, int, tgl_peer_id_t *, tgl_message_id_t **, int *))q->callback) (q->callback_extra, 0, 0, NULL, NULL, NULL);
  }
  return 0;
}

static struct query_methods get_dialogs_methods = {
  .on_answer = get_dialogs_on_answer,
  .on_error = get_dialogs_on_error,
  .on_timeout = NULL,
  .type = TYPE_TO_PARAM(messages_dialogs),
  .name = "get dialogs",
  .timeout = 0,
};

static void _tgl_do_get_dialog_list (std::shared_ptr<get_dialogs_extra> E,  void (*callback)(std::shared_ptr<void>, bool success, int size, tgl_peer_id_t peers[], tgl_message_id_t *last_msg_id[], int unread_count[]), std::shared_ptr<void> callback_extra) {
  clear_packet ();
  if (E->channels) {
    out_int (CODE_channels_get_dialogs);
    out_int (E->offset);
    out_int (E->limit - E->list_offset);
  } else {
    out_int (CODE_messages_get_dialogs);
    out_int (E->offset_date);
    out_int (E->offset);
    //out_int (0);
    if (E->offset_peer.peer_type) {
      out_peer_id (E->offset_peer);
    } else {
      out_int (CODE_input_peer_empty);
    }
    out_int (E->limit - E->list_offset);
  }

  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &get_dialogs_methods, E, (void*)callback, callback_extra);
}

void tgl_do_get_dialog_list (int limit, int offset, void (*callback)(std::shared_ptr<void>, bool success, int size, tgl_peer_id_t peers[], tgl_message_id_t *last_msg_id[], int unread_count[]), std::shared_ptr<void> callback_extra) {
  std::shared_ptr<get_dialogs_extra> E = std::make_shared<get_dialogs_extra>();
  E->limit = limit;
  E->offset = offset;
  E->channels = 0;
  _tgl_do_get_dialog_list (E, callback, callback_extra);
}

void tgl_do_get_channels_dialog_list (int limit, int offset, void (*callback)(std::shared_ptr<void>, bool success, int size, tgl_peer_id_t peers[], tgl_message_id_t *last_msg_id[], int unread_count[]), std::shared_ptr<void> callback_extra) {
  std::shared_ptr<get_dialogs_extra> E = std::make_shared<get_dialogs_extra>();
  E->limit = limit;
  E->offset = offset;
  E->channels = 1;
  E->offset_date = 0;
  E->offset_peer.peer_type = 0;
  _tgl_do_get_dialog_list (E, callback, callback_extra);
}
/* }}} */

/* {{{ Send document file */

void out_peer_id (tgl_peer_id_t id) {
  switch (tgl_get_peer_type (id)) {
  case TGL_PEER_CHAT:
    out_int (CODE_input_peer_chat);
    out_int (tgl_get_peer_id (id));
    break;
  case TGL_PEER_USER:
    out_int (CODE_input_peer_user);
    out_int (tgl_get_peer_id (id));
    out_long (id.access_hash);
    break;
  case TGL_PEER_CHANNEL:
    out_int (CODE_input_peer_channel);
    out_int (tgl_get_peer_id (id));
    out_long (id.access_hash);
    break;
  default:
    assert (0);
  }
}

/* }}} */

/* {{{ Profile name */

int set_profile_name_on_answer (std::shared_ptr<query> q, void *D) {
  TGL_UNUSED(q);
  struct tl_ds_user *DS_U = (struct tl_ds_user *)D;
  std::shared_ptr<tgl_user> user = tglf_fetch_alloc_user (DS_U);
  if (q->callback) {
    ((void (*)(std::shared_ptr<void>, bool, const std::shared_ptr<tgl_user>&))q->callback) (q->callback_extra, true, user);
  }
  return 0;
}

static struct query_methods set_profile_name_methods = {
  .on_answer = set_profile_name_on_answer,
  .on_error = q_ptr_on_error,
  .on_timeout = NULL,
  .type = TYPE_TO_PARAM(user),
  .name = "set profile name",
  .timeout = 0,
};

void tgl_do_set_profile_name (const char *first_name, const char *last_name) {
    clear_packet ();
    out_int (CODE_account_update_profile);
    out_cstring (first_name, strlen(last_name));
    out_cstring (last_name, strlen(last_name));

    tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &set_profile_name_methods, 0, NULL, NULL);
}

void tgl_do_set_username (const char *username, int username_len, void (*callback)(std::shared_ptr<void>, bool success, struct tgl_user *U), std::shared_ptr<void> callback_extra) {
    clear_packet ();
    out_int (CODE_account_update_username);
    out_cstring (username, username_len);

    tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &set_profile_name_methods, 0, (void*)callback, callback_extra);
}
/* }}} */

/* {{{ Contacts search */

int contact_search_on_answer (std::shared_ptr<query> q, void *D) {
  struct tl_ds_contacts_resolved_peer *DS_CRU = (struct tl_ds_contacts_resolved_peer *)D;

  //tgl_peer_id_t peer_id = tglf_fetch_peer_id (DS_CRU->peer);

  int i;
  for (i = 0; i < DS_LVAL (DS_CRU->users->cnt); i++) {
    tglf_fetch_alloc_user (DS_CRU->users->data[i]);
  }
  
  for (i = 0; i < DS_LVAL (DS_CRU->chats->cnt); i++) {
    tglf_fetch_alloc_chat (DS_CRU->chats->data[i]);
  }

#if 0
  tgl_peer_t *P = tgl_peer_get (peer_id);

  if (q->callback) {
    ((void (*)(std::shared_ptr<void>, int, tgl_peer_t *))q->callback) (q->callback_extra, 1, P);
  }
#endif

  return 0;
}

static struct query_methods contact_search_methods = {
  .on_answer = contact_search_on_answer,
  .on_error = q_list_on_error,
  .on_timeout = NULL,
  .type = TYPE_TO_PARAM(contacts_resolved_peer),
  .name = "contacts search",
  .timeout = 0,
};

void tgl_do_contact_search (const char *name, int name_len, void (*callback)(std::shared_ptr<void>, bool success, tgl_peer_t *U), std::shared_ptr<void> callback_extra) {
  clear_packet ();
  out_int (CODE_contacts_resolve_username);
  out_cstring (name, name_len);

  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &contact_search_methods, 0, (void*)callback, callback_extra);
}
/* }}} */

/* {{{ Forward */

static int send_msgs_on_answer (std::shared_ptr<query> q, void *D) {
    tglu_work_any_updates (1, (tl_ds_updates *)D, NULL);
    tglu_work_any_updates (0, (tl_ds_updates *)D, NULL);

    std::shared_ptr<messages_send_extra> E = std::static_pointer_cast<messages_send_extra>(q->extra);

    if (!E) {
        if (q->callback) {
            ((void (*)(std::shared_ptr<void>, int))q->callback) (q->callback_extra, 1);
        }
    } else if (E->multi) {
        struct tgl_message **ML = 0;//(struct tgl_message **)malloc (sizeof (void *) * E->count);
        int count = E->count;
        //int i;
//        for (i = 0; i < count; i++) {
//            int y = tgls_get_local_by_random (E->list[i]);
//            ML[i] = tgl_message_get (y);
//        }
        free (E->list);
        if (q->callback) {
            ((void (*)(std::shared_ptr<void>, int, int, struct tgl_message **))q->callback) (q->callback_extra, 1, count, ML);
        }
        //free (ML);
    } else {
//        int y = tgls_get_local_by_random (E->id);
        struct tgl_message *M = 0;//tgl_message_get (y);
        if (q->callback) {
            ((void (*)(std::shared_ptr<void>, int, struct tgl_message *))q->callback) (q->callback_extra, 1, M);
        }
    }
  return 0;
}

static int send_msgs_on_error (std::shared_ptr<query> q, int error_code, const std::string &error) {
    TGL_ERROR("RPC_CALL_FAIL " <<  error_code << " " << error);
    std::shared_ptr<messages_send_extra> E = std::static_pointer_cast<messages_send_extra>(q->extra);

    if (!E) {
        if (q->callback) {
            ((void (*)(std::shared_ptr<void>, int))q->callback) (q->callback_extra, 0);
        }
    } else if (E->multi) {
        free (E->list);
        if (q->callback) {
            ((void (*)(std::shared_ptr<void>, int, int, struct tgl_message **))q->callback) (q->callback_extra, 0, 0, NULL);
        }
    } else {
        if (q->callback) {
            ((void (*)(std::shared_ptr<void>, int, struct tgl_message *))q->callback) (q->callback_extra, 0, NULL);
        }
    }
    return 0;
}

struct query_methods send_msgs_methods = {
  .on_answer = send_msgs_on_answer,
  .on_error = send_msgs_on_error,
  .on_timeout = NULL,
  .type = TYPE_TO_PARAM(updates),
  .name = "forward messages",
  .timeout = 0,
};

void tgl_do_forward_messages (tgl_peer_id_t id, int n, const tgl_message_id_t *_ids[], unsigned long long flags, void (*callback)(std::shared_ptr<void>, bool success, int count, struct tgl_message *ML[]), std::shared_ptr<void> callback_extra) {
  if (tgl_get_peer_type (id) == TGL_PEER_ENCR_CHAT) {
    TGL_ERROR("can not forward messages to secret chats");
    if (callback) {
      callback (callback_extra, 0, 0, 0);
    }
    return;
  }
  tgl_peer_id_t from_id = TGL_MK_USER (0);
  tgl_message_id_t *ids = (tgl_message_id_t *)talloc (sizeof (tgl_message_id_t) * n);
  int i;
  for (i = 0; i < n; i++) {
    tgl_message_id_t msg_id = *_ids[i];
    if (msg_id.peer_type == TGL_PEER_TEMP_ID) {
      msg_id = tgl_convert_temp_msg_id (msg_id);
    }
    if (msg_id.peer_type == TGL_PEER_TEMP_ID) {
      tgl_set_query_error (EINVAL, "unknown message");
      if (callback) {
        callback (callback_extra, 0, 0, NULL);
      }
      tfree (ids, n * sizeof (tgl_message_id_t));
      return;
    }

    if (msg_id.peer_type == TGL_PEER_ENCR_CHAT) {
      tgl_set_query_error (EINVAL, "can not forward message from secret chat");
      if (callback) {
        callback (callback_extra, 0, 0, NULL);
      }
      tfree (ids, n * sizeof (tgl_message_id_t));
      return;
    }

    ids[i] = msg_id;

    if (i == 0) {      
      from_id = tgl_msg_id_to_peer_id (msg_id);
    } else {
      if (tgl_cmp_peer_id (from_id, tgl_msg_id_to_peer_id (msg_id))) {
        tgl_set_query_error (EINVAL, "can not forward messages from different dialogs");
        if (callback) {
          callback (callback_extra, 0, 0, NULL);
        }
        tfree (ids, n * sizeof (tgl_message_id_t));
        return;
      }
    }
  }
  
  
  clear_packet ();
  out_int (CODE_messages_forward_messages);

  unsigned f = 0;
  if (flags & TGLMF_POST_AS_CHANNEL) {
    f |= 16;
  }
  out_int (f);

  out_peer_id (from_id);

  out_int (CODE_vector);
  out_int (n);
  for (i = 0; i < n; i++) {
    out_int (ids[i].id);
  }

  std::shared_ptr<messages_send_extra> E = std::make_shared<messages_send_extra>();
  E->multi = 1;
  E->count = n;
  E->list = (tgl_message_id_t *)talloc (sizeof (tgl_message_id_t) * n);
  out_int (CODE_vector);
  out_int (n);
  for (i = 0; i < n; i++) {
    E->list[i] = tgl_peer_id_to_random_msg_id (id);
    assert (E->list[i].id);
    out_long (E->list[i].id);
  }

  out_peer_id (id);

  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_msgs_methods, E, (void*)callback, callback_extra);
        
  tfree (ids, n * sizeof (tgl_message_id_t));
}

void tgl_do_forward_message (tgl_peer_id_t peer_id, tgl_message_id_t *_msg_id, unsigned long long flags, void (*callback)(std::shared_ptr<void>, bool success, struct tgl_message *M), std::shared_ptr<void> callback_extra) {
  tgl_message_id_t msg_id = *_msg_id;
  if (msg_id.peer_type == TGL_PEER_TEMP_ID) {
    msg_id = tgl_convert_temp_msg_id (msg_id);
  }
  if (msg_id.peer_type == TGL_PEER_TEMP_ID) {
    tgl_set_query_error (EINVAL, "unknown message");
    if (callback) {
      callback (callback_extra, 0, 0);
    }
    return;
  }
  if (msg_id.peer_type == TGL_PEER_ENCR_CHAT) {
    tgl_set_query_error (EINVAL, "can not forward messages from secret chat");
    if (callback) {
      callback (callback_extra, 0, 0);
    }
    return;
  }
  if (peer_id.peer_type == TGL_PEER_ENCR_CHAT) {
    TGL_ERROR("can not forward messages to secret chats");
    if (callback) {
      callback (callback_extra, 0, 0);
    }
    return;
  }
  
  clear_packet ();
  out_int (CODE_messages_forward_message);
  tgl_peer_id_t from_peer = tgl_msg_id_to_peer_id (msg_id);
  out_peer_id (from_peer);
  out_int (msg_id.id);

  std::shared_ptr<messages_send_extra> E = std::make_shared<messages_send_extra>();
  E->id = tgl_peer_id_to_random_msg_id (peer_id);
  out_long (E->id.id);

  out_peer_id (peer_id);
  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_msgs_methods, E, (void*)callback, callback_extra);
}

void tgl_do_send_contact (tgl_peer_id_t id, const char *phone, int phone_len,
    const char *first_name, int first_name_len, const char *last_name, int last_name_len,
    unsigned long long flags, void (*callback)(std::shared_ptr<void>, bool success, struct tgl_message *M), std::shared_ptr<void> callback_extra) {
  if (tgl_get_peer_type (id) == TGL_PEER_ENCR_CHAT) {
    TGL_ERROR("can not send contact to secret chat");
    if (callback) {
      callback (callback_extra, 0, 0);
    }
    return;
  }

  int reply_id = flags >> 32;

  clear_packet ();
  out_int (CODE_messages_send_media);
  out_int (reply_id ? 1 : 0);
  if (reply_id) { out_int (reply_id); }
  out_peer_id(id);
  out_int (CODE_input_media_contact);
  out_cstring (phone, phone_len);
  out_cstring (first_name, first_name_len);
  out_cstring (last_name, last_name_len);

  std::shared_ptr<messages_send_extra> E = std::make_shared<messages_send_extra>();
  tglt_secure_random ((unsigned char*)&E->id, 8);
  out_long (E->id.id);

  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_msgs_methods, E, (void*)callback, callback_extra);
}


void tgl_do_reply_contact (tgl_message_id_t *_reply_id, const char *phone, int phone_len, const char *first_name, int first_name_len, const char *last_name, int last_name_len, unsigned long long flags, void (*callback)(std::shared_ptr<void>, bool success, struct tgl_message *M), std::shared_ptr<void> callback_extra) {
  tgl_message_id_t reply_id = *_reply_id;
  if (reply_id.peer_type == TGL_PEER_TEMP_ID) {
    reply_id = tgl_convert_temp_msg_id (reply_id);
  }
  if (reply_id.peer_type == TGL_PEER_TEMP_ID) {
    tgl_set_query_error (EINVAL, "unknown message");
    if (callback) {
      callback (callback_extra, 0, 0);
    }
    return;
  }
  if (reply_id.peer_type == TGL_PEER_ENCR_CHAT) {
    tgl_set_query_error (EINVAL, "can not reply on message from secret chat");
    if (callback) {
      callback (callback_extra, 0, 0);
    }

    tgl_peer_id_t peer_id = tgl_msg_id_to_peer_id (reply_id);

    tgl_do_send_contact (peer_id, phone, phone_len, first_name, first_name_len, last_name, last_name_len, flags | TGL_SEND_MSG_FLAG_REPLY (reply_id.id), callback, callback_extra);
  }
}

void tgl_do_forward_media (tgl_peer_id_t peer_id, tgl_message_id_t *_msg_id, unsigned long long flags, void (*callback)(std::shared_ptr<void>, bool success, struct tgl_message *M), std::shared_ptr<void> callback_extra) {
  if (tgl_get_peer_type (peer_id) == TGL_PEER_ENCR_CHAT) {
    tgl_set_query_error (EINVAL, "can not forward messages to secret chats");
    if (callback) {
      callback (callback_extra, 0, 0);
    }
    return;
  }
  tgl_message_id_t msg_id = *_msg_id;
  if (msg_id.peer_type == TGL_PEER_TEMP_ID) {
    msg_id = tgl_convert_temp_msg_id (msg_id);
  }
  if (msg_id.peer_type == TGL_PEER_TEMP_ID) {
    tgl_set_query_error (EINVAL, "unknown message");
    if (callback) {
      callback (callback_extra, 0, 0);
    }
    return;
  }
  if (msg_id.peer_type == TGL_PEER_ENCR_CHAT) {
    tgl_set_query_error (EINVAL, "can not forward message from secret chat");
    if (callback) {
      callback (callback_extra, 0, 0);
    }
    return;
  }
#if 0
  struct tgl_message *M = tgl_message_get (&msg_id);
  if (!M || !(M->flags & TGLMF_CREATED) || (M->flags & TGLMF_ENCRYPTED)) {
    if (!M || !(M->flags & TGLMF_CREATED)) {
      tgl_set_query_error (EINVAL, "unknown message");
    } else {
      tgl_set_query_error (EINVAL, "can not forward message from secret chat");
    }
    if (callback) {
      callback (callback_extra, 0, 0);
    }
    return;
  }
  if (M->media.type != tgl_message_media_photo && M->media.type != tgl_message_media_document && M->media.type != tgl_message_media_audio && M->media.type != tgl_message_media_video) {
    tgl_set_query_error (EINVAL, "can only forward photo/document");
    if (callback) {
      callback (callback_extra, 0, 0);
    }
    return;
  }
#endif
  clear_packet ();
  out_int (CODE_messages_send_media);
  int f = 0;
  if (flags & TGLMF_POST_AS_CHANNEL) {
    f |= 16;
  }
  out_int (f);
  out_peer_id (peer_id);
#if 0
  switch (M->media.type) {
  case tgl_message_media_photo:
    assert (M->media.photo);
    out_int (CODE_input_media_photo);
    out_int (CODE_input_photo);
    out_long (M->media.photo->id);
    out_long (M->media.photo->access_hash);
    out_string ("");
    break;
  case tgl_message_media_document:
  case tgl_message_media_audio:
  case tgl_message_media_video:
    assert (M->media.document);
    out_int (CODE_input_media_document);
    out_int (CODE_input_document);
    out_long (M->media.document->id);
    out_long (M->media.document->access_hash);
    out_string ("");
    break;
  default:
    assert (0);
  }
#endif

  std::shared_ptr<messages_send_extra> E = std::make_shared<messages_send_extra>();
  E->id = tgl_peer_id_to_random_msg_id (peer_id);
  out_long (E->id.id);

  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_msgs_methods, E, (void*)callback, callback_extra);
}
/* }}} */

/* {{{ Send location */

void tgl_do_send_location (tgl_peer_id_t peer_id, double latitude, double longitude, unsigned long long flags, void (*callback)(std::shared_ptr<void>, bool success, struct tgl_message *M), std::shared_ptr<void> callback_extra) {
  if (tgl_get_peer_type (peer_id) == TGL_PEER_ENCR_CHAT) {
#ifdef ENABLE_SECRET_CHAT
    tgl_do_send_location_encr (peer_id, latitude, longitude, flags, callback, callback_extra);
#endif
  } else {
    int reply_id = flags >> 32;
    clear_packet ();
    out_int (CODE_messages_send_media);
    unsigned f = reply_id ? 1 : 0;
    if (flags & TGLMF_POST_AS_CHANNEL) {
      f |= 16;
    }
    out_int (f);
    if (reply_id) { out_int (reply_id); }
    out_peer_id (peer_id);
    out_int (CODE_input_media_geo_point);
    out_int (CODE_input_geo_point);
    out_double (latitude);
    out_double (longitude);

    std::shared_ptr<messages_send_extra> E = std::make_shared<messages_send_extra>();
    E->id = tgl_peer_id_to_random_msg_id (peer_id);
    out_long (E->id.id);

    tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_msgs_methods, E, (void*)callback, callback_extra);
  }
}

#if 0
void tgl_do_reply_location (tgl_message_id_t *_reply_id, double latitude, double longitude, unsigned long long flags, void (*callback)(std::shared_ptr<void>, bool success, struct tgl_message *M), std::shared_ptr<void> callback_extra) {
  tgl_message_id_t reply_id = *_reply_id;
  if (reply_id.peer_type == TGL_PEER_TEMP_ID) {
    reply_id = tgl_convert_temp_msg_id (reply_id);
  }
  if (reply_id.peer_type == TGL_PEER_TEMP_ID) {
    tgl_set_query_error (EINVAL, "unknown message");
    if (callback) {
      callback (callback_extra, 0, 0);
    }
    return;
  }
  if (reply_id.peer_type == TGL_PEER_ENCR_CHAT) {
    tgl_set_query_error (EINVAL, "can not reply on message from secret chat");
    if (callback) {
      callback (callback_extra, 0, 0);
    }

  tgl_peer_id_t peer_id = tgl_msg_id_to_peer_id (reply_id);

  tgl_do_send_location (peer_id, latitude, longitude, flags | TGL_SEND_MSG_FLAG_REPLY (reply_id.id), callback, callback_extra);
}
#endif
/* }}} */

/* {{{ Rename chat */

void tgl_do_rename_chat (tgl_peer_id_t id, const char *name, int name_len, void (*callback)(std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra) {
    clear_packet ();
    out_int (CODE_messages_edit_chat_title);
    assert (tgl_get_peer_type (id) == TGL_PEER_CHAT);
    out_int (tgl_get_peer_id (id));
    out_cstring (name, name_len);
    tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_msgs_methods, 0, (void*)callback, callback_extra);
}
/* }}} */

 /* {{{ Rename channel */

void tgl_do_rename_channel (tgl_peer_id_t id, const char *name, int name_len, void (*callback)(std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra) {
  clear_packet ();
  out_int (CODE_channels_edit_title);
  assert (tgl_get_peer_type (id) == TGL_PEER_CHANNEL);
  out_int (CODE_input_channel);
  out_int (tgl_get_peer_id (id));
  out_long (id.access_hash);
  out_cstring (name, name_len);
  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_msgs_methods, 0, (void*)callback, callback_extra);
}
/* }}} */

 /* {{{ Join channel */

void tgl_do_join_channel (tgl_peer_id_t id, void (*callback)(std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra) {
  clear_packet ();
  out_int (CODE_channels_join_channel);
  assert (tgl_get_peer_type (id) == TGL_PEER_CHANNEL);
  out_int (CODE_input_channel);
  out_int (tgl_get_peer_id (id));
  out_long (id.access_hash);
  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_msgs_methods, 0, (void*)callback, callback_extra);
}
/* }}} */

/* {{{ Leave channel */

void tgl_do_leave_channel (tgl_peer_id_t id, void (*callback)(std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra) {
  clear_packet ();
  out_int (CODE_channels_leave_channel);
  assert (tgl_get_peer_type (id) == TGL_PEER_CHANNEL);
  out_int (CODE_input_channel);
  out_int (tgl_get_peer_id (id));
  out_long (id.access_hash);
  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_msgs_methods, 0, (void*)callback, callback_extra);
}
/* }}} */

/* {{{ channel change about */

static int channels_set_about_on_answer (std::shared_ptr<query> q, void *D) {
  if (q->callback) {
    ((void (*)(std::shared_ptr<void>, bool))q->callback)(q->callback_extra, 1);
  }
  return 0;
}

static struct query_methods channels_set_about_methods = {
  .on_answer = channels_set_about_on_answer,
  .on_error = q_void_on_error,
  .on_timeout = nullptr,
  .type = TYPE_TO_PARAM(bool),
  .name = "channels set about",
  .timeout = 0,
};

void tgl_do_channel_set_about (tgl_peer_id_t id, const char *about, int about_len, void (*callback)(std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra) {
  clear_packet ();
  out_int (CODE_channels_edit_about);
  assert (tgl_get_peer_type (id) == TGL_PEER_CHANNEL);
  out_int (CODE_input_channel);
  out_int (tgl_get_peer_id (id));
  out_long (id.access_hash);
  out_cstring (about, about_len);
  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &channels_set_about_methods, 0, (void*)callback, callback_extra);
}
/* }}} */

/* {{{ Channel set username */
void tgl_do_channel_set_username (tgl_peer_id_t id, const char *username, int username_len, void (*callback)(std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra) {
  clear_packet ();
  out_int (CODE_channels_update_username);
  assert (tgl_get_peer_type (id) == TGL_PEER_CHANNEL);
  out_int (CODE_input_channel);
  out_int (tgl_get_peer_id (id));
  out_long (id.access_hash);
  out_cstring (username, username_len);
  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &channels_set_about_methods, 0, (void*)callback, callback_extra);
}
/* }}} */

/* {{{ Channel set admin */
void tgl_do_channel_set_admin (tgl_peer_id_t channel_id, tgl_peer_id_t user_id, int type, void (*callback)(std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra) {
  clear_packet ();
  out_int (CODE_channels_edit_admin);
  assert (tgl_get_peer_type (channel_id) == TGL_PEER_CHANNEL);
  assert (tgl_get_peer_type (user_id) == TGL_PEER_USER);
  out_int (CODE_input_channel);
  out_int (tgl_get_peer_id (channel_id));
  out_long (channel_id.access_hash);
  out_int (CODE_input_user);
  out_int (tgl_get_peer_id (user_id));
  out_long (user_id.access_hash);
  switch (type) {
  case 1:
    out_int (CODE_channel_role_moderator);
    break;
  case 2:
    out_int (CODE_channel_role_editor);
    break;
  default:
    out_int (CODE_channel_role_empty);
    break;
  }
  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_msgs_methods, 0, (void*)callback, callback_extra);
}
/* }}} */

/* {{{ Channel members */
struct channel_get_members_extra {
  int size;
  int count;
  tgl_peer_id_t *UL;
  int type;
  int offset;
  int limit;
  tgl_peer_id_t id;
};

void _tgl_do_channel_get_members  (std::shared_ptr<struct channel_get_members_extra> E, void (*callback)(std::shared_ptr<void>, bool success, int size, struct tgl_user *UL[]), std::shared_ptr<void> callback_extra);

static int channels_get_members_on_answer (std::shared_ptr<query> q, void *D) {
  struct tl_ds_channels_channel_participants *DS_CP = (struct tl_ds_channels_channel_participants *)D;
  
  int count = DS_LVAL (DS_CP->participants->cnt);

  std::shared_ptr<channel_get_members_extra> E = std::static_pointer_cast<channel_get_members_extra>(q->extra);


  if (E->count + count > E->size) {
    E->UL = (tgl_peer_id_t *)trealloc (E->UL, E->size * sizeof (void *), (E->count + count) * sizeof (void *));
    E->size = E->count + count;
  }
  int i;
  for (i = 0; i < DS_LVAL (DS_CP->users->cnt); i++) {
    tglf_fetch_alloc_user (DS_CP->users->data[i]);
  }
  for (i = 0; i < count; i++) {
    //E->UL[E->count ++] = (struct tgl_user *)tgl_peer_get (TGL_MK_USER (DS_LVAL (DS_CP->participants->data[i]->user_id)));
    E->UL[E->count ++] = TGL_MK_USER (DS_LVAL (DS_CP->participants->data[i]->user_id));
  }
  E->offset += count;
  
  if (!count || E->count == E->limit) {
    ((void (*)(std::shared_ptr<void>, int, int, tgl_peer_id_t *))q->callback)(q->callback_extra, 1, E->count, E->UL);
    tfree (E->UL, E->size * sizeof (void *));
    return 0;
  }
  _tgl_do_channel_get_members (E, (void (*)(std::shared_ptr<void>, bool, int, struct tgl_user **))q->callback, q->callback_extra);
  return 0;
}

static int channels_get_members_on_error (std::shared_ptr<struct query> q, int error_code, const std::string &error) {
  TGL_ERROR("RPC_CALL_FAIL " <<  error_code << " " << std::string(error));
  if (q->callback) {
    ((void (*)(std::shared_ptr<void>, bool, int, struct tgl_user **))(q->callback))(q->callback_extra, 0, 0, NULL);
  }
  
  std::shared_ptr<channel_get_members_extra> E = std::static_pointer_cast<channel_get_members_extra>(q->extra);
  tfree (E->UL, E->size * sizeof (void *));

  return 0;
}

static struct query_methods channels_get_members_methods = {
  .on_answer = channels_get_members_on_answer,
  .on_error = channels_get_members_on_error,
  .on_timeout = nullptr,
  .type = TYPE_TO_PARAM(channels_channel_participants),
  .name = "channels get members",
  .timeout = 0,
};

void _tgl_do_channel_get_members  (std::shared_ptr<struct channel_get_members_extra> E, void (*callback)(std::shared_ptr<void>, bool success, int size, struct tgl_user *UL[]), std::shared_ptr<void> callback_extra) {
  clear_packet ();
  out_int (CODE_channels_get_participants);
  assert (tgl_get_peer_type (E->id) == TGL_PEER_CHANNEL);
  out_int (CODE_input_channel);
  out_int (E->id.peer_id);
  out_long (E->id.access_hash);

  switch (E->type) {
  case 1:
  case 2:
    out_int (CODE_channel_participants_admins);
    break;
  case 3:
    out_int (CODE_channel_participants_kicked);
    break;
  default:
    out_int (CODE_channel_participants_recent);
    break;
  }
  out_int (E->offset);
  out_int (E->limit);
  
  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &channels_get_members_methods, E, (void*)callback, callback_extra);
}

void tgl_do_channel_get_members  (tgl_peer_id_t channel_id, int limit, int offset, int type, void (*callback)(std::shared_ptr<void>, bool success, int size, struct tgl_user *UL[]), std::shared_ptr<void> callback_extra) {
  std::shared_ptr<channel_get_members_extra> E = std::make_shared<channel_get_members_extra>();
  E->type = type;
  E->id = channel_id;
  E->limit = limit;
  E->offset = offset;
  _tgl_do_channel_get_members (E, callback, callback_extra);
}
/* }}} */

/* {{{ Chat info */

static int chat_info_on_answer (std::shared_ptr<query> q, void *D) {
  std::shared_ptr<tgl_chat> C = tglf_fetch_alloc_chat_full ((struct tl_ds_messages_chat_full *)D);
  //print_chat_info (C);
  if (q->callback) {
    ((void (*)(std::shared_ptr<void>, bool, const std::shared_ptr<tgl_chat>&))q->callback) (q->callback_extra, true, C);
  }
  return 0;
}

static struct query_methods chat_info_methods = {
  .on_answer = chat_info_on_answer,
  .on_error = q_ptr_on_error,
  .on_timeout = NULL,
  .type = TYPE_TO_PARAM(messages_chat_full),
  .name = "chat info",
  .timeout = 0,
};

void tgl_do_get_chat_info (int id, int offline_mode, void (*callback)(std::shared_ptr<void>, bool success, const std::shared_ptr<tgl_chat>& C), std::shared_ptr<void> callback_extra) {
  if (offline_mode) {
#if 0
    tgl_peer_t *C = tgl_peer_get (id);
    if (!C) {
      tgl_set_query_error (EINVAL, "unknown chat id");
      if (callback) {
        callback (callback_extra, 0, 0);
      }
    } else {
      if (callback) {
        callback (callback_extra, 1, &C->chat);
      }
    }
#endif
    return;
  }
  clear_packet ();
  out_int (CODE_messages_get_full_chat);
  out_int (id);
  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &chat_info_methods, 0, (void*)callback, callback_extra);
}
/* }}} */

/* {{{ Channel info */

static int channel_info_on_answer (std::shared_ptr<query> q, void *D) {
  std::shared_ptr<tgl_channel> C = tglf_fetch_alloc_channel_full ((struct tl_ds_messages_chat_full *)D);
  //print_chat_info (C);
  if (q->callback) {
    ((void (*)(std::shared_ptr<void>, bool, const std::shared_ptr<tgl_channel>&))q->callback) (q->callback_extra, true, C);
  }
  return 0;
}

static struct query_methods channel_info_methods = {
  .on_answer = channel_info_on_answer,
  .on_error = q_ptr_on_error,
  .on_timeout = nullptr,
  .type = TYPE_TO_PARAM(messages_chat_full),
  .name = "channel info",
  .timeout = 0,
};

void tgl_do_get_channel_info (tgl_peer_id_t id, int offline_mode, void (*callback)(std::shared_ptr<void>, bool success, const std::shared_ptr<tgl_channel>& C), std::shared_ptr<void> callback_extra) {
  if (offline_mode) {
#if 0
    tgl_peer_t *C = tgl_peer_get (id);
    if (!C) {
      tgl_set_query_error (EINVAL, "unknown chat id");
      if (callback) {
        callback (callback_extra, 0, 0);
      }
    } else {
      if (callback) {
        callback (callback_extra, 1, &C->channel);
      }
    }
#endif
    return;
  }
  clear_packet ();
  out_int (CODE_channels_get_full_channel);
  assert (tgl_get_peer_type (id) == TGL_PEER_CHANNEL);
  out_int (CODE_input_channel);
  out_int (id.peer_id);
  out_long (id.access_hash);
  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &channel_info_methods, 0, (void*)callback, callback_extra);
}
/* }}} */

/* {{{ User info */

static int user_info_on_answer (std::shared_ptr<query> q, void *D) {
  TGL_UNUSED(q);
  std::shared_ptr<struct tgl_user> U = tglf_fetch_alloc_user_full ((struct tl_ds_user_full *)D);
  if (q->callback) {
    ((void (*)(std::shared_ptr<void>, int, std::shared_ptr<struct tgl_user>))q->callback) (q->callback_extra, 1, U);
  }
  return 0;
}

static struct query_methods user_info_methods = {
  .on_answer = user_info_on_answer,
  .on_error = q_ptr_on_error,
  .on_timeout = NULL,
  .type = TYPE_TO_PARAM(user_full),
  .name = "user info",
  .timeout = 0,
};

void tgl_do_get_user_info (tgl_peer_id_t id, int offline_mode, void (*callback)(std::shared_ptr<void>, bool success, struct tgl_user *U), std::shared_ptr<void> callback_extra) {
  if (tgl_get_peer_type (id) != TGL_PEER_USER) {
    tgl_set_query_error (EINVAL, "id should be user id");
    if (callback) {
      callback (callback_extra, 0, NULL);
    }
    return;
  }
  if (offline_mode) {
#if 0
    tgl_peer_t *C = tgl_peer_get (id);
    if (!C) {
      tgl_set_query_error (EINVAL, "unknown user id");
      if (callback) {
        callback (callback_extra, 0, 0);
      }
    } else {
      if (callback) {
        callback (callback_extra, 1, &C->user);
      }
    }
#endif
    return;
  }
  clear_packet ();
  out_int (CODE_users_get_full_user);
  assert (tgl_get_peer_type (id) == TGL_PEER_USER);
  out_int (CODE_input_user);
  out_int (tgl_get_peer_id (id));
  out_long (id.access_hash);
  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &user_info_methods, 0, (void*)callback, callback_extra);
}

static void resend_query_cb(std::shared_ptr<void> _q, bool success) {
    assert (success);

    TGL_DEBUG2("resend_query_cb");
    tgl_state::instance()->set_dc_signed (tgl_state::instance()->DC_working->id);

    std::shared_ptr<query> q = std::static_pointer_cast<query>(_q);

    clear_packet ();
    out_int (CODE_users_get_full_user);
    out_int (CODE_input_user_self);
    tglq_send_query (q->DC, packet_ptr - packet_buffer, packet_buffer, &user_info_methods, 0, q->callback, q->callback_extra);

    free (q->data);
    if (q->ev) {
        q->ev->cancel();
        q->ev = nullptr;
    }
}
/* }}} */

/* {{{ Export auth */

static int import_auth_on_answer (std::shared_ptr<query> q, void *D) {
  struct tl_ds_auth_authorization *DS_U = (struct tl_ds_auth_authorization *)D;
  tglf_fetch_alloc_user (DS_U->user);

  std::shared_ptr<tgl_dc> DC = std::static_pointer_cast<tgl_dc>(q->extra);
  assert(DC);
  TGL_NOTICE("auth imported from DC " << tgl_state::instance()->DC_working->id << " to DC " << DC->id);

  //bl_do_dc_signed (((struct tgl_dc *)q->extra)->id);
  tgl_state::instance()->set_dc_signed(DC->id);

  if (q->callback) {
    ((void (*)(std::shared_ptr<void>, int))q->callback) (q->callback_extra, 1);
  }
  return 0;
}

static struct query_methods import_auth_methods = {
  .on_answer = import_auth_on_answer,
  .on_error = fail_on_error,
  .on_timeout = NULL,
  .type = TYPE_TO_PARAM(auth_authorization),
  .name = "import authorization",
  .timeout = 0,
};

static int export_auth_on_answer (std::shared_ptr<query> q, void *D) {
  TGL_NOTICE("export_auth_on_answer " <<  std::static_pointer_cast<tgl_dc>(q->extra)->id);
  struct tl_ds_auth_exported_authorization *DS_EA = (struct tl_ds_auth_exported_authorization *)D;

  //bl_do_set_our_id (TGL_MK_USER (DS_LVAL (DS_EA->id)));
  tgl_state::instance()->set_our_id(DS_LVAL (DS_EA->id));

  clear_packet ();
  tgl_do_insert_header ();
  out_int (CODE_auth_import_authorization);
  out_int (tgl_get_peer_id (tgl_state::instance()->our_id()));
  out_cstring (DS_STR (DS_EA->bytes));
  tglq_send_query_ex(std::static_pointer_cast<tgl_dc>(q->extra), packet_ptr - packet_buffer, packet_buffer, &import_auth_methods, q->extra, q->callback, q->callback_extra, QUERY_LOGIN);
  return 0;
}

static struct query_methods export_auth_methods = {
  .on_answer = export_auth_on_answer,
  .on_error = fail_on_error,
  .on_timeout = NULL,
  .type = TYPE_TO_PARAM(auth_exported_authorization),
  .name = "export authorization",
  .timeout = 0,
};

// export auth from working DC and import to DC "num"
void tgl_do_transfer_auth (int num, void (*callback) (std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra) {
    std::shared_ptr<tgl_dc> DC = tgl_state::instance()->DC_list[num];
    if (DC->auth_transfer_in_process) {
        return;
    }
    DC->auth_transfer_in_process = true;
    TGL_NOTICE("Transferring auth from DC " << tgl_state::instance()->DC_working->id << " to DC " << num);
    clear_packet ();
    out_int (CODE_auth_export_authorization);
    out_int (num);
    tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &export_auth_methods, DC, (void*)callback, callback_extra);
}
/* }}} */

/* {{{ Add contact */
static int add_contact_on_answer (std::shared_ptr<query> q, void *D) {
  struct tl_ds_contacts_imported_contacts *DS_CIC = (struct tl_ds_contacts_imported_contacts *)D;

  if (DS_LVAL (DS_CIC->imported->cnt) > 0) {
    TGL_DEBUG("Added successfully");
  } else {
    TGL_DEBUG("Not added");
  }

  int n = DS_LVAL (DS_CIC->users->cnt);

  std::vector<std::shared_ptr<tgl_user>> users(n);
  for (int i = 0; i < n; i++) {
    users[i] = tglf_fetch_alloc_user (DS_CIC->users->data[i]);
  }

  if (q->callback) {
    ((void (*)(std::shared_ptr<void>, bool, const std::vector<std::shared_ptr<tgl_user>>&))q->callback) (q->callback_extra, true, users);
  }
  return 0;
}

static struct query_methods add_contact_methods = {
  .on_answer = add_contact_on_answer,
  .on_error = q_list_on_error,
  .on_timeout = NULL,
  .type = TYPE_TO_PARAM(contacts_imported_contacts),
  .name = "add contact",
  .timeout = 0,
};

void tgl_do_add_contact (const char *phone, const char *first_name, const char *last_name, int force, void (*callback)(std::shared_ptr<void>, bool success, const std::vector<std::shared_ptr<tgl_user>>& users), std::shared_ptr<void> callback_extra) {
    clear_packet ();
    out_int (CODE_contacts_import_contacts);
    out_int (CODE_vector);
    out_int (1);
    out_int (CODE_input_phone_contact);
    long long r;
    tglt_secure_random ((unsigned char*)&r, 8);
    out_long (r);
    out_cstring (phone, strlen(phone));
    out_cstring (first_name, strlen(first_name));
    out_cstring (last_name, strlen(last_name));
    out_int (force ? CODE_bool_true : CODE_bool_false);
    tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &add_contact_methods, 0, (void*)callback, callback_extra);
}
/* }}} */

/* {{{ Del contact */
static int del_contact_on_answer (std::shared_ptr<query> q, void *D) {
    TGL_UNUSED(D);
    if (q->callback) {
        ((void (*)(std::shared_ptr<void>, int))q->callback) (q->callback_extra, 1);
    }
    return 0;
}

static struct query_methods del_contact_methods = {
  .on_answer = del_contact_on_answer,
  .on_error = q_void_on_error,
  .on_timeout = NULL,
  .type = TYPE_TO_PARAM(contacts_link),
  .name = "del contact",
  .timeout = 0,
};

void tgl_do_del_contact (tgl_peer_id_t id, void (*callback)(std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra) {
    clear_packet ();
    out_int (CODE_contacts_delete_contact);

  out_int (CODE_input_user);
  out_int (tgl_get_peer_id (id));
  out_long (id.access_hash);
  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &del_contact_methods, 0, (void*)callback, callback_extra);
}
/* }}} */

/* {{{ Msg search */

struct msg_search_extra {
    msg_search_extra(tgl_peer_id_t id, int from, int to, int limit, int offset, const std::string &query) :
        id(id), from(from), to(to), limit(limit), offset(offset), query(query) {}
    std::vector<tgl_message*> ML;
    tgl_peer_id_t id;
    int from;
    int to;
    int limit;
    int offset;
    int max_id = 0;
    std::string query;
};

static void _tgl_do_msg_search(std::shared_ptr<msg_search_extra> E, void (*callback)(std::shared_ptr<void>, bool success, std::vector<tgl_message*> list), std::shared_ptr<void> );

static int msg_search_on_answer (std::shared_ptr<query> q, void *D) {
  struct tl_ds_messages_messages *DS_MM = (struct tl_ds_messages_messages *)D;
  
  int i;
  for (i = 0; i < DS_LVAL (DS_MM->chats->cnt); i++) {
    tglf_fetch_alloc_chat (DS_MM->chats->data[i]);
  }
  for (i = 0; i < DS_LVAL (DS_MM->users->cnt); i++) {
    tglf_fetch_alloc_user (DS_MM->users->data[i]);
  }

  std::shared_ptr<msg_search_extra> E = std::static_pointer_cast<msg_search_extra>(q->extra);

  int n = DS_LVAL (DS_MM->messages->cnt);

  for (i = 0; i < n; i++) {
    E->ML.push_back(tglf_fetch_alloc_message (DS_MM->messages->data[i], NULL));
  }
  E->offset += n;
  E->limit -= n;
  if (E->limit + E->offset >= DS_LVAL (DS_MM->count)) {
    E->limit = DS_LVAL (DS_MM->count) - E->offset;
    if (E->limit < 0) { E->limit = 0; }
  }
  assert (E->limit >= 0);

  if (E->limit <= 0 || DS_MM->magic == CODE_messages_messages) {
    if (q->callback) {
      ((void (*)(std::shared_ptr<void>, int, std::vector<tgl_message *>))q->callback) (q->callback_extra, 1, E->ML);
    }
  } else {
    E->max_id = E->ML[E->ML.size()-1]->permanent_id.id;
    E->offset = 0;
    _tgl_do_msg_search (E, (void (*)(std::shared_ptr<void>, bool, std::vector<tgl_message*>))q->callback, q->callback_extra);
  }
  return 0;
}

static int msg_search_on_error (std::shared_ptr<query> q, int error_code, const std::string &error) {
    TGL_ERROR("RPC_CALL_FAIL " <<  error_code << " " << error);

    std::shared_ptr<msg_search_extra> E = std::static_pointer_cast<msg_search_extra>(q->extra);
    if (q->callback) {
        ((void (*)(std::shared_ptr<void>, int, std::vector<tgl_message*>))q->callback) (q->callback_extra, 0, std::vector<tgl_message*>());
    }
    return 0;
}

static struct query_methods msg_search_methods = {
  .on_answer = msg_search_on_answer,
  .on_error = msg_search_on_error,
  .on_timeout = NULL,
  .type = TYPE_TO_PARAM(messages_messages),
  .name = "messages search",
  .timeout = 0,
};

static void _tgl_do_msg_search(std::shared_ptr<msg_search_extra> E, void (*callback)(std::shared_ptr<void>, bool success, std::vector<tgl_message*> list), std::shared_ptr<void> callback_extra) {
  clear_packet ();
  if (tgl_get_peer_type (E->id) == TGL_PEER_UNKNOWN) {
    out_int (CODE_messages_search_global);
    out_string (E->query.c_str());
    out_int (0);
    out_int (CODE_input_peer_empty);
    out_int (E->offset);
    out_int (E->limit);
  } else {
    out_int (CODE_messages_search);
    out_int (0);
    out_peer_id (E->id);

    out_string (E->query.c_str());
    out_int (CODE_input_messages_filter_empty);
    out_int (E->from);
    out_int (E->to);
    out_int (E->offset); // offset
    out_int (E->max_id); // max_id
    out_int (E->limit);
  }
  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &msg_search_methods, E, (void*)callback, callback_extra);
}

//untested
void tgl_do_msg_search (tgl_peer_id_t id, int from, int to, int limit, int offset, const std::string &query, void (*callback)(std::shared_ptr<void>, bool success, std::vector<tgl_message*> list), std::shared_ptr<void> callback_extra) {
    if (tgl_get_peer_type (id) == TGL_PEER_ENCR_CHAT) {
        TGL_ERROR("can not search in secret chats");
        if (callback) {
            callback (callback_extra, 0, std::vector<tgl_message*>());
        }
        return;
    }
    std::shared_ptr<msg_search_extra> E = std::make_shared<msg_search_extra>(id, from, to, limit, offset, query);

    _tgl_do_msg_search (E, callback, callback_extra);
}
/* }}} */

/* {{{ Get difference */

static int get_state_on_answer (std::shared_ptr<query> q, void *D) {
    struct tl_ds_updates_state *DS_US = (struct tl_ds_updates_state *)D;

    assert (tgl_state::instance()->locks & TGL_LOCK_DIFF);
    tgl_state::instance()->locks ^= TGL_LOCK_DIFF;

    tgl_state::instance()->set_pts (DS_LVAL (DS_US->pts));
    tgl_state::instance()->set_qts (DS_LVAL (DS_US->qts));
    tgl_state::instance()->set_date (DS_LVAL (DS_US->date));
    tgl_state::instance()->set_seq (DS_LVAL (DS_US->seq));

    if (q->callback) {
        ((void (*)(std::shared_ptr<void>, int))q->callback) (q->callback_extra, 1);
    }
    return 0;
}

static int lookup_state_on_answer (std::shared_ptr<query> q, void *D) {
    TGL_UNUSED(q);
    struct tl_ds_updates_state *DS_US = (struct tl_ds_updates_state *)D;
    int pts = DS_LVAL (DS_US->pts);
    int qts = DS_LVAL (DS_US->qts);
    int seq = DS_LVAL (DS_US->seq);

    if (pts > tgl_state::instance()->pts() || qts > tgl_state::instance()->qts() || seq > tgl_state::instance()->seq()) {
        tgl_do_get_difference (0, 0, 0);
    }
    return 0;
}


//int get_difference_active;
static int get_difference_on_answer (std::shared_ptr<query> q, void *D) {
  struct tl_ds_updates_difference *DS_UD = (struct tl_ds_updates_difference *)D;

  TGL_DEBUG2("get difference answer");
  assert (tgl_state::instance()->locks & TGL_LOCK_DIFF);
  tgl_state::instance()->locks ^= TGL_LOCK_DIFF;

  if (DS_UD->magic == CODE_updates_difference_empty) {
    tgl_state::instance()->set_date (DS_LVAL (DS_UD->date));
    tgl_state::instance()->set_seq (DS_LVAL (DS_UD->seq));

    TGL_DEBUG("Empty difference. Seq = " << tgl_state::instance()->seq());
    if (q->callback) {
      ((void (*)(std::shared_ptr<void>, int))q->callback) (q->callback_extra, 1);
    }
  } else {
    int i;

    for (i = 0; i < DS_LVAL (DS_UD->users->cnt); i++) {
      tglf_fetch_alloc_user (DS_UD->users->data[i]);
    }
    for (i = 0; i < DS_LVAL (DS_UD->chats->cnt); i++) {
      tglf_fetch_alloc_chat (DS_UD->chats->data[i]);
    }

    int ml_pos = DS_LVAL (DS_UD->new_messages->cnt);
    std::vector<tgl_message*> ML;
    for (i = 0; i < ml_pos; i++) {
      ML.push_back(tglf_fetch_alloc_message (DS_UD->new_messages->data[i], NULL));
    }

    int el_pos = DS_LVAL (DS_UD->new_encrypted_messages->cnt);
    std::vector<tgl_message*> EL;
    for (i = 0; i < el_pos; i++) {
#ifdef ENABLE_SECRET_CHAT
      EL.push_back(tglf_fetch_alloc_encrypted_message (DS_UD->new_encrypted_messages->data[i]));
#endif
    }

    //for (i = 0; i < DS_LVAL (DS_UD->other_updates->cnt); i++) {
      //tglu_work_update (1, DS_UD->other_updates->data[i]);
    //}

    for (i = 0; i < DS_LVAL (DS_UD->other_updates->cnt); i++) {
      tglu_work_update (-1, DS_UD->other_updates->data[i]);
    }

    for (i = 0; i < ml_pos; i++) {
      //bl_do_msg_update (&ML[i]->permanent_id);
      //tgl_state::instance()->callback()->new_message(ML[i]);
      if (ML[i]) {
        tgls_free_message(ML[i]);
      }
    }
    for (i = 0; i < el_pos; i++) {
      // messages to secret chats that no longer exist are not initialized and NULL
      if (EL[i]) {
        //bl_do_msg_update (&EL[i]->permanent_id);
        tgl_state::instance()->callback()->new_message(EL[i]);
        tgls_free_message(EL[i]);
      }
    }

    if (DS_UD->state) {
      tgl_state::instance()->set_pts (DS_LVAL (DS_UD->state->pts));
      tgl_state::instance()->set_qts (DS_LVAL (DS_UD->state->qts));
      tgl_state::instance()->set_date (DS_LVAL (DS_UD->state->date));
      tgl_state::instance()->set_seq (DS_LVAL (DS_UD->state->seq));

      if (q->callback) {
        ((void (*)(std::shared_ptr<void>, int))q->callback) (q->callback_extra, 1);
      }
    } else {
      tgl_state::instance()->set_pts (DS_LVAL (DS_UD->intermediate_state->pts));
      tgl_state::instance()->set_qts (DS_LVAL (DS_UD->intermediate_state->qts));
      tgl_state::instance()->set_date (DS_LVAL (DS_UD->intermediate_state->date));

      tgl_do_get_difference (0, (void (*)(std::shared_ptr<void>, bool))q->callback, q->callback_extra);
    }
  }
  return 0;
}

static struct query_methods lookup_state_methods = {
  .on_answer = lookup_state_on_answer,
  .on_error = q_void_on_error,
  .on_timeout = NULL,
  .type = TYPE_TO_PARAM(updates_state),
  .name = "lookup state",
  .timeout = 0,
};

static struct query_methods get_state_methods = {
  .on_answer = get_state_on_answer,
  .on_error = q_void_on_error,
  .on_timeout = NULL,
  .type = TYPE_TO_PARAM(updates_state),
  .name = "get state",
  .timeout = 0,
};

static struct query_methods get_difference_methods = {
  .on_answer = get_difference_on_answer,
  .on_error = q_void_on_error,
  .on_timeout = NULL,
  .type = TYPE_TO_PARAM(updates_difference),
  .name = "get difference",
  .timeout = 0,
};

void tgl_do_lookup_state () {
    if (tgl_state::instance()->locks & TGL_LOCK_DIFF) {
        return;
    }
    clear_packet ();
    tgl_do_insert_header ();
    out_int (CODE_updates_get_state);
    tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &lookup_state_methods, 0, 0, 0);
}

void tgl_do_get_difference (int sync_from_start, void (*callback)(std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra) {
  //get_difference_active = 1;
  //difference_got = 0;
  if (tgl_state::instance()->locks & TGL_LOCK_DIFF) {
    if (callback) {
      callback (callback_extra, 0);
    }
    return;
  }
  tgl_state::instance()->locks |= TGL_LOCK_DIFF;
  clear_packet ();
  tgl_do_insert_header ();
  if (tgl_state::instance()->pts() > 0 || sync_from_start) {
    if (tgl_state::instance()->pts() == 0) { tgl_state::instance()->set_pts(1, true); }
    //if (tgl_state::instance()->qts() == 0) { tgl_state::instance()->set_qts(1, true); }
    if (tgl_state::instance()->date() == 0) { tgl_state::instance()->set_date(1, true); }
    out_int (CODE_updates_get_difference);
    out_int (tgl_state::instance()->pts());
    out_int (tgl_state::instance()->date());
    out_int (tgl_state::instance()->qts());
	tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &get_difference_methods, 0, (void*)callback, callback_extra);
  } else {
	out_int (CODE_updates_get_state);
	tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &get_state_methods, 0, (void*)callback, callback_extra);
  }
}
/* }}} */

/* {{{ Get channel difference */
void tgl_do_get_channel_difference (int id, void (*callback)(std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra);

static int get_channel_difference_on_answer (std::shared_ptr<struct query> q, void *D) {
  struct tl_ds_updates_channel_difference *DS_UD = (struct tl_ds_updates_channel_difference *)D;

  std::shared_ptr<tgl_peer_t> E = std::static_pointer_cast<tgl_peer_t>(q->extra);

  assert (E->flags & TGLCHF_DIFF);
  E->flags ^= TGLCHF_DIFF;

  if (DS_UD->magic == CODE_updates_channel_difference_empty) {
    //bl_do_set_channel_pts (tgl_get_peer_id (E->id), DS_LVAL (DS_UD->channel_pts));

    TGL_DEBUG("Empty difference. Seq = " << tgl_state::instance()->seq());
    if (q->callback) {
      ((void (*)(std::shared_ptr<void>, bool))q->callback) (q->callback_extra, 1);
    }
  } else {
    int i;

    for (i = 0; i < DS_LVAL (DS_UD->users->cnt); i++) {
      tglf_fetch_alloc_user (DS_UD->users->data[i]);
    }
    for (i = 0; i < DS_LVAL (DS_UD->chats->cnt); i++) {
      tglf_fetch_alloc_chat (DS_UD->chats->data[i]);
    }

    int ml_pos = DS_LVAL (DS_UD->new_messages->cnt);
    struct tgl_message **ML = (struct tgl_message **)talloc (ml_pos * sizeof (void *));
    for (i = 0; i < ml_pos; i++) {
      ML[i] = tglf_fetch_alloc_message (DS_UD->new_messages->data[i], NULL);
    }

    for (i = 0; i < DS_LVAL (DS_UD->other_updates->cnt); i++) {
      tglu_work_update (1, DS_UD->other_updates->data[i]);
    }

    for (i = 0; i < DS_LVAL (DS_UD->other_updates->cnt); i++) {
      tglu_work_update (-1, DS_UD->other_updates->data[i]);
    }

    for (i = 0; i < ml_pos; i++) {
      //bl_do_msg_update (&ML[i]->permanent_id);
    }

    tfree (ML, ml_pos * sizeof (void *));

    //bl_do_set_channel_pts (tgl_get_peer_id (E->id), DS_LVAL (DS_UD->channel_pts));
    if (DS_UD->magic != CODE_updates_channel_difference_too_long) {
      if (q->callback) {
        ((void (*)(std::shared_ptr<void>, int))q->callback) (q->callback_extra, 1);
      }
    } else {
      tgl_do_get_channel_difference (tgl_get_peer_id (E->id), (void(*)(std::shared_ptr<void>, bool))q->callback, q->callback_extra);
    }
  }
  return 0;
}

struct paramed_type update_channel_diff_type = TYPE_TO_PARAM(updates_channel_difference);
static struct query_methods get_channel_difference_methods = {
  .on_answer = get_channel_difference_on_answer,
  .on_error = q_void_on_error,
  .on_timeout = nullptr,
  .type = TYPE_TO_PARAM(updates_channel_difference),
  .name = "get channel difference",
  .timeout = 0,
};

void tgl_do_get_channel_difference (int id, void (*callback)(std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra) {
  tgl_peer_id_t channel_id = TGL_MK_CHANNEL (id);
  //tgl_peer_t *E = tgl_peer_get (TGL_MK_CHANNEL (id));

#if 0
  if (!E || !(E->flags & TGLPF_CREATED) || !E->channel.pts) { 
    if (callback) {
      callback (callback_extra, 0);
    }
    return;
  }
  //get_difference_active = 1;
  //difference_got = 0;
  if (E->flags & TGLCHF_DIFF) {
    if (callback) {
      callback (callback_extra, 0);
    }
    return;
  }
  E->flags |= TGLCHF_DIFF;
#endif
  clear_packet ();
  tgl_do_insert_header ();

  out_int (CODE_updates_get_channel_difference);
  out_int (CODE_input_channel);
  out_int (tgl_get_peer_id (channel_id));
  out_long (channel_id.access_hash);

  out_int (CODE_channel_messages_filter_empty);
  out_int (0); //out_int (E->channel.pts);
  out_int (100);

  //std::shared_ptr<struct tgl_channel> C = std::make_shared<struct tgl_channel>(E->channel);
  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &get_channel_difference_methods, /*C*/0, (void*)callback, callback_extra);
}
/* }}} */

/* {{{ Visualize key */

//int tgl_do_visualize_key (tgl_peer_id_t id, unsigned char buf[16]) {
//    assert (tgl_get_peer_type (id) == TGL_PEER_ENCR_CHAT);
//    assert (P);
//    if (P->encr_chat.state != sc_ok) {
//        TGL_WARNING("Chat is not initialized yet");
//        return -1;
//    }
//    memcpy (buf, P->encr_chat.first_key_sha, 16);
//    return 0;
//}
/* }}} */

/* {{{ Add user to chat */

void tgl_do_add_user_to_chat (tgl_peer_id_t chat_id, tgl_peer_id_t id, int limit, void (*callback)(std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra) {
  clear_packet ();
  out_int (CODE_messages_add_chat_user);
  out_int (tgl_get_peer_id (chat_id));

  assert (tgl_get_peer_type (id) == TGL_PEER_USER);
  out_int (CODE_input_user);
  out_int (tgl_get_peer_id (id));
  out_long (id.access_hash);
  out_int (limit);

  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_msgs_methods, 0, (void*)callback, callback_extra);
}

void tgl_do_del_user_from_chat (tgl_peer_id_t chat_id, tgl_peer_id_t id, void (*callback)(std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra) {
  clear_packet ();
  out_int (CODE_messages_delete_chat_user);
  out_int (tgl_get_peer_id (chat_id));

  assert (tgl_get_peer_type (id) == TGL_PEER_USER);
  out_int (CODE_input_user);
  out_int (tgl_get_peer_id (id));
  out_long (id.access_hash);
  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_msgs_methods, 0, (void*)callback, callback_extra);
}

/* }}} */

/* {{{ Add user to channel */

void tgl_do_channel_invite_user (tgl_peer_id_t channel_id, tgl_peer_id_t id, void (*callback)(std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra) {
  clear_packet ();
  out_int (CODE_channels_invite_to_channel);
  out_int (CODE_input_channel);
  out_int (channel_id.peer_id);
  out_long (channel_id.access_hash);

  out_int (CODE_vector);
  out_int (1);
  out_int (CODE_input_user);
  out_int (tgl_get_peer_id (id));
  out_long (id.access_hash);

  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_msgs_methods, 0, (void*)callback, callback_extra);
}

void tgl_do_channel_kick_user (tgl_peer_id_t channel_id, tgl_peer_id_t id, void (*callback)(std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra) {
  clear_packet ();
  out_int (CODE_channels_kick_from_channel);
  out_int (CODE_input_channel);
  out_int (channel_id.peer_id);
  out_long (channel_id.access_hash);

  out_int (CODE_input_user);
  out_int (tgl_get_peer_id (id));
  out_long (id.access_hash);

  out_int (CODE_bool_true);
  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_msgs_methods, 0, (void*)callback, callback_extra);
}

/* }}} */

/* {{{ Create secret chat */

#ifdef ENABLE_SECRET_CHAT
int tgl_do_create_secret_chat(const tgl_peer_id_t& user_id, void (*callback)(std::shared_ptr<void>, bool success, const std::shared_ptr<tgl_secret_chat>& E), std::shared_ptr<void> callback_extra) {
    return tgl_do_create_encr_chat_request (user_id, callback, callback_extra);
}
#endif
/* }}} */

/* {{{ Create group chat */

void tgl_do_create_group_chat (std::vector<tgl_peer_id_t> user_ids, const std::string &chat_topic, void (*callback)(std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra) {
  clear_packet ();
  out_int (CODE_messages_create_chat);
  out_int (CODE_vector);
  out_int (user_ids.size()); // Number of users, currently we support only 1 user.
  for (tgl_peer_id_t id : user_ids) {
    if (tgl_get_peer_type (id) != TGL_PEER_USER) {
      tgl_set_query_error (EINVAL, "Can not create chat with unknown user");
      if (callback) {
        callback (callback_extra, 0);
      }
      return;
    }
    out_int (CODE_input_user);
    out_int (tgl_get_peer_id (id));
    out_long (id.access_hash);
  }
  TGL_NOTICE("sending out chat creat request users number:%d" << user_ids.size());
  out_cstring (chat_topic.c_str(), chat_topic.length());
  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_msgs_methods, 0, (void*)callback, callback_extra);
}
/* }}} */

/* {{{ Create channel */

void tgl_do_create_channel (int users_num, tgl_peer_id_t ids[], const char *chat_topic, int chat_topic_len, const char *about, int about_len, unsigned long long flags, void (*callback)(std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra) {
  clear_packet ();
  out_int (CODE_channels_create_channel);
  out_int (flags); // looks like 2 is disable non-admin messages
  out_cstring (chat_topic, chat_topic_len);
  out_cstring (about, about_len);
  //out_int (CODE_vector);
  //out_int (users_num); 
  int i;
  for (i = 0; i < users_num; i++) {
    tgl_peer_id_t id = ids[i];
    if (tgl_get_peer_type (id) != TGL_PEER_USER) {
      tgl_set_query_error (EINVAL, "Can not create chat with unknown user");
      if (callback) {
        callback (callback_extra, 0);
      }
      return;
    }
    out_int (CODE_input_user);
    out_int (tgl_get_peer_id (id));
    out_long (id.access_hash);
  }
  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_msgs_methods, 0, (void*)callback, callback_extra);
}
/* }}} */

/* {{{ Delete msg */

static int delete_msg_on_answer (std::shared_ptr<query> q, void *D) {
  struct tl_ds_messages_affected_messages *DS_MAM = (struct tl_ds_messages_affected_messages *)D;

  std::shared_ptr<tgl_message_id_t> id = std::static_pointer_cast<tgl_message_id_t>(q->extra);
  q->extra = NULL;

#if 0
  struct tgl_message *M = tgl_message_get (id.get());
  if (M) {
    //bl_do_message_delete (&M->permanent_id);
    //TODO
    //tgl_state::instance()->callback.msg_deleted(M->&permanent_id);
  }
#endif
  tgl_state::instance()->callback()->message_deleted(id->id);

  int r = tgl_check_pts_diff (DS_LVAL (DS_MAM->pts), DS_LVAL (DS_MAM->pts_count));

  if (r > 0) {
    //bl_do_set_pts (TLS, DS_LVAL (DS_MAM->pts));
    tgl_state::instance()->set_pts (DS_LVAL (DS_MAM->pts));
  }

  if (q->callback) {
    ((void (*)(std::shared_ptr<void>, int))q->callback) (q->callback_extra, 1);
  }
  return 0;
}

static int delete_msg_on_error (std::shared_ptr<struct query> q, int error_code, const std::string &error) {
  TGL_ERROR("RPC_CALL_FAIL " <<  error_code << " " << error);
  if (q->callback) {
    ((void (*)(std::shared_ptr<void>, bool))(q->callback))(q->callback_extra, 0);
  }
  std::shared_ptr<tgl_message_id_t> id = std::static_pointer_cast<tgl_message_id_t>(q->extra);
  q->extra = NULL;
  return 0;
}


static struct query_methods delete_msg_methods = {
  .on_answer = delete_msg_on_answer,
  .on_error = delete_msg_on_error,
  .on_timeout = NULL,
  .type = TYPE_TO_PARAM(messages_affected_messages),
  .name = "delete message",
  .timeout = 0,
};

void tgl_do_delete_msg (tgl_message_id_t *_msg_id, void (*callback)(std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra) {
  tgl_message_id_t msg_id = *_msg_id;
  if (msg_id.peer_type == TGL_PEER_TEMP_ID) {
    msg_id = tgl_convert_temp_msg_id (msg_id);
  }
  if (msg_id.peer_type == TGL_PEER_TEMP_ID) {
    tgl_set_query_error (EINVAL, "unknown message");
    if (callback) {
      callback (callback_extra, 0);
    }
    return;
  }
  clear_packet ();
  if (msg_id.peer_type == TGL_PEER_CHANNEL) {
    out_int (CODE_channels_delete_messages);
    out_int (CODE_input_channel);
    out_int (msg_id.peer_id);
    out_long (msg_id.access_hash);

    out_int (CODE_vector);
    out_int (1);
    out_int (msg_id.id);
  } else {
    out_int (CODE_messages_delete_messages);
    out_int (CODE_vector);
    out_int (1);
    out_int (msg_id.id);
  }

  std::shared_ptr<tgl_message_id_t> id = std::make_shared<tgl_message_id_t>();
  *id = msg_id;
  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &delete_msg_methods, id, (void*)callback, callback_extra);
}
/* }}} */

/* {{{ Export card */

static int export_card_on_answer (std::shared_ptr<query> q, void *D) {
    struct tl_ds_vector *DS_V = (struct tl_ds_vector *)D;

    int n = DS_LVAL (DS_V->f1);

    int *r = (int*)malloc (4 * n);
    int i;
    for (i = 0; i < n; i++) {
        r[i] = *(int *)DS_V->f2[i];
    }

    if (q->callback) {
        ((void (*)(std::shared_ptr<void>, int, int, int *))q->callback) (q->callback_extra, 1, n, r);
    }
    free (r);
    return 0;
}

struct paramed_type bare_int_type = TYPE_TO_PARAM (bare_int);
struct paramed_type *bare_int_array_type[1] = {&bare_int_type};
struct paramed_type vector_type = (struct paramed_type) {.type = &tl_type_vector, .params=bare_int_array_type};

static struct query_methods export_card_methods = {
  .on_answer = export_card_on_answer,
  .on_error = q_list_on_error,
  .on_timeout = NULL,
  .type = vector_type,
  .name = "export card",
  .timeout = 0,
};

void tgl_do_export_card (void (*callback)(std::shared_ptr<void>, bool success, int size, int *card), std::shared_ptr<void> callback_extra) {
    clear_packet ();
    out_int (CODE_contacts_export_card);
    tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &export_card_methods, 0, (void*)callback, callback_extra);
}
/* }}} */

/* {{{ Import card */

static int import_card_on_answer (std::shared_ptr<query> q, void *D) {
  std::shared_ptr<tgl_user> user = tglf_fetch_alloc_user((struct tl_ds_user *)D);

  if (q->callback) {
    ((void (*)(std::shared_ptr<void>, bool, const std::shared_ptr<tgl_user>&))q->callback) (q->callback_extra, true, user);
  }
  return 0;
}

static struct query_methods import_card_methods = {
  .on_answer = import_card_on_answer,
  .on_error = q_ptr_on_error,
  .on_timeout = NULL,
  .type = TYPE_TO_PARAM(user),
  .name = "import card",
  .timeout = 0,
};

void tgl_do_import_card (int size, int *card, void (*callback)(std::shared_ptr<void>, bool success, const std::shared_ptr<tgl_user>& user), std::shared_ptr<void> callback_extra) {
    clear_packet ();
    out_int (CODE_contacts_import_card);
    out_int (CODE_vector);
    out_int (size);
    out_ints (card, size);
    tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &import_card_methods, 0, (void*)callback, callback_extra);
}
/* }}} */

void tgl_do_start_bot (tgl_peer_id_t bot, tgl_peer_id_t chat, const char *str, int str_len, void (*callback)(std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra) {
  clear_packet ();
  out_int (CODE_messages_start_bot);
  out_int (CODE_input_user);
  out_int (tgl_get_peer_id (bot));
  out_long (bot.access_hash);
  out_int (tgl_get_peer_id (chat));
  long long m;
  tglt_secure_random ((unsigned char*)&m, 8);
  out_long (m);
  out_cstring (str, str_len);
  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_msgs_methods, 0, (void*)callback, callback_extra);
}

/* {{{ Send typing */
static int send_typing_on_answer (std::shared_ptr<query> q, void *D) {
    TGL_UNUSED(D);
    if (q->callback) {
        ((void (*)(std::shared_ptr<void>, int))q->callback)(q->callback_extra, 1);
    }
    return 0;
}

static struct query_methods send_typing_methods = {
  .on_answer = send_typing_on_answer,
  .on_error = q_void_on_error,
  .on_timeout = NULL,
  .type = bool_type,
  .name = "send typing",
  .timeout = 0,
};

void tgl_do_send_typing (tgl_peer_id_t id, enum tgl_typing_status status, void (*callback)(std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra) {
    if (tgl_get_peer_type (id) != TGL_PEER_ENCR_CHAT) {
        clear_packet ();
        out_int (CODE_messages_set_typing);
        out_peer_id(id);
        switch (status) {
        case tgl_typing_none:
        case tgl_typing_typing:
            out_int (CODE_send_message_typing_action);
            break;
        case tgl_typing_cancel:
            out_int (CODE_send_message_cancel_action);
            break;
        case tgl_typing_record_video:
            out_int (CODE_send_message_record_video_action);
            break;
        case tgl_typing_upload_video:
            out_int (CODE_send_message_upload_video_action);
            break;
        case tgl_typing_record_audio:
            out_int (CODE_send_message_record_audio_action);
            break;
        case tgl_typing_upload_audio:
            out_int (CODE_send_message_upload_audio_action);
            break;
        case tgl_typing_upload_photo:
            out_int (CODE_send_message_upload_photo_action);
            break;
        case tgl_typing_upload_document:
            out_int (CODE_send_message_upload_document_action);
            break;
        case tgl_typing_geo:
            out_int (CODE_send_message_geo_location_action);
            break;
        case tgl_typing_choose_contact:
            out_int (CODE_send_message_choose_contact_action);
            break;
        }
        tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_typing_methods, 0, (void*)callback, callback_extra);
    } else {
        if (callback) {
            callback (callback_extra, 0);
        }
    }
}
/* }}} */

/* {{{ Extd query */
#ifndef DISABLE_EXTF
char *tglf_extf_print_ds (void *DS, struct paramed_type *T);

static int ext_query_on_answer (std::shared_ptr<query> q, void *D) {
  if (q->callback) {
    char *buf = tglf_extf_print_ds (D, &q->type);
    ((void (*)(std::shared_ptr<void>, bool, char *))q->callback) (q->callback_extra, 1, buf);
  }
  tgl_paramed_type_free (q->type);
  return 0;
}

static struct query_methods ext_query_methods = {
  .on_answer = ext_query_on_answer,
  .on_error = q_list_on_error,
  .on_timeout = NULL,
  .type = NULL,
  .name = "ext query",
  .timeout = 0,
};

void tgl_do_send_extf (const char *data, int data_len, void (*callback)(std::shared_ptr<void>, bool success, const char *buf), std::shared_ptr<void> callback_extra) {
  clear_packet ();

  ext_query_methods.type = tglf_extf_store (data, data_len);

  if (ext_query_methods.type) {
    tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &ext_query_methods, 0, (void*)callback, callback_extra);
  }
}
#else
void tgl_do_send_extf (const char *data, int data_len, void (*callback)(std::shared_ptr<void>, bool success, const char *buf), std::shared_ptr<void> callback_extra) {
  assert (0);
}
#endif
/* }}} */

/* {{{ get messages */

static int get_messages_on_answer (std::shared_ptr<query> q, void *D) {
  struct tl_ds_messages_messages *DS_MM = (struct tl_ds_messages_messages *)D;

  int i;
  for (i = 0; i < DS_LVAL (DS_MM->users->cnt); i++) {
    tglf_fetch_alloc_user (DS_MM->users->data[i]);
  }
  for (i = 0; i < DS_LVAL (DS_MM->chats->cnt); i++) {
    tglf_fetch_alloc_chat (DS_MM->chats->data[i]);
  }

  struct tgl_message **ML;
  if (q->extra) {
    ML = (struct tgl_message **)calloc (1,sizeof (void *) * DS_LVAL (DS_MM->messages->cnt));
  } else {
    static struct tgl_message *M;
    M = NULL;
    ML = &M;
    assert (DS_LVAL (DS_MM->messages->cnt) <= 1);
  }
  for (i = 0; i < DS_LVAL (DS_MM->messages->cnt); i++) {
    ML[i] = tglf_fetch_alloc_message (DS_MM->messages->data[i], NULL);
  }
  if (q->callback) {
    if (q->extra) {
      ((void (*)(std::shared_ptr<void>, int, int, struct tgl_message **))q->callback)(q->callback_extra, 1, DS_LVAL (DS_MM->messages->cnt), ML);
    } else {
      if (DS_LVAL (DS_MM->messages->cnt) > 0) {
        ((void (*)(std::shared_ptr<void>, int, struct tgl_message *))q->callback)(q->callback_extra, 1, *ML);
      } else {
        tgl_set_query_error (ENOENT, "no such message");
        ((void (*)(std::shared_ptr<void>, int, struct tgl_message *))q->callback)(q->callback_extra, 0, NULL);
      }
    }
  }
  if (q->extra) {
    free (ML);
  }
  return 0;
}

static struct query_methods get_messages_methods = {
  .on_answer = get_messages_on_answer,
  .on_error = q_ptr_on_error,
  .on_timeout = NULL,
  .type = TYPE_TO_PARAM(messages_messages),
  .name = "get messages",
  .timeout = 0,
};

void tgl_do_get_message (tgl_message_id_t *_msg_id, void (*callback)(std::shared_ptr<void>, bool success, struct tgl_message *M), std::shared_ptr<void> callback_extra) {
  tgl_message_id_t msg_id = *_msg_id;
  if (msg_id.peer_type == TGL_PEER_TEMP_ID) {
    msg_id = tgl_convert_temp_msg_id (msg_id);
  }
  if (msg_id.peer_type == TGL_PEER_TEMP_ID) {
    tgl_set_query_error (EINVAL, "unknown message");
    if (callback) {
      callback (callback_extra, 0, NULL);
    }
    return;
  }

#if 0
  struct tgl_message *M = tgl_message_get (&msg_id);
  if (M) {
    if (callback) {
      callback (callback_extra, 1, M);
    }
    return;
  }
#endif

  clear_packet ();

  TGL_ERROR("id=" << msg_id.id);
  out_int (CODE_messages_get_messages);
  out_int (CODE_vector);
  out_int (1);
  out_int (msg_id.id);


  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &get_messages_methods, 0, (void*)callback, callback_extra);
}
/* }}} */

/* {{{ Export/import chat link */
static int export_chat_link_on_answer (std::shared_ptr<query> q, void *D) {
    struct tl_ds_exported_chat_invite *DS_ECI = (struct tl_ds_exported_chat_invite *)D;

    char *s = (char*)DS_STR_DUP (DS_ECI->link);

    if (q->callback) {
        ((void (*)(std::shared_ptr<void>, int, const char *))q->callback)(q->callback_extra, s ? 1 : 0, s);
    }
    free (s);
    return 0;
}

static struct query_methods export_chat_link_methods = {
  .on_answer = export_chat_link_on_answer,
  .on_error = q_ptr_on_error,
  .on_timeout = NULL,
  .type = TYPE_TO_PARAM(exported_chat_invite),
  .name = "export chat link",
  .timeout = 0,
};

void tgl_do_export_chat_link (tgl_peer_id_t id, void (*callback)(std::shared_ptr<void>, bool success, const char *link), std::shared_ptr<void> callback_extra) {
    if (tgl_get_peer_type (id) != TGL_PEER_CHAT) {
        TGL_ERROR("Can only export chat link for chat");
        if (callback) {
            callback (callback_extra, 0, NULL);
        }
        return;
    }

    clear_packet ();
    out_int (CODE_messages_export_chat_invite);
    out_int (tgl_get_peer_id (id));

    tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &export_chat_link_methods, 0, (void*)callback, callback_extra);
}

void tgl_do_import_chat_link (const char *link, int len, void (*callback)(std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra) {
    const char *l = link + len - 1;
    while (l >= link && *l != '/') {
        l --;
    }
    l ++;

    clear_packet ();
    out_int (CODE_messages_import_chat_invite);
    out_cstring (l, len - (l - link));

    tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_msgs_methods, 0, (void*)callback, callback_extra);
}

/* }}} */

/* {{{ Export/import channel link */

void tgl_do_export_channel_link (tgl_peer_id_t id, void (*callback)(std::shared_ptr<void>, bool success, const char *link), std::shared_ptr<void> callback_extra) {
  if (tgl_get_peer_type (id) != TGL_PEER_CHANNEL) {
    tgl_set_query_error (EINVAL, "Can only export chat link for chat");
    if (callback) {
      callback (callback_extra, 0, NULL);
    }
    return;
  }

  clear_packet ();
  out_int (CODE_channels_export_invite);
  out_int (CODE_input_channel);
  out_int (tgl_get_peer_id (id));
  out_long (id.access_hash);

  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &export_chat_link_methods, 0, (void*)callback, callback_extra);
}

/* }}} */

/* {{{ set password */
static int set_password_on_answer (std::shared_ptr<query> q, void *D) {
    TGL_UNUSED(D);
    if (q->callback) {
        ((void (*)(std::shared_ptr<void>, int))q->callback)(q->callback_extra, 1);
    }
    return 0;
}

static int set_password_on_error (std::shared_ptr<query> q, int error_code, const std::string &error) {
    if (error_code == 400) {
        if (error == "PASSWORD_HASH_INVALID") {
            TGL_WARNING("Bad old password");
            if (q->callback) {
                ((void (*)(std::shared_ptr<void>, int))q->callback)(q->callback_extra, 0);
            }
            return 0;
        }
        if (error == "NEW_PASSWORD_BAD") {
            TGL_WARNING("Bad new password (unchanged or equals hint)");
            if (q->callback) {
                ((void (*)(std::shared_ptr<void>, int))q->callback)(q->callback_extra, 0);
            }
            return 0;
        }
        if (error == "NEW_SALT_INVALID") {
            TGL_WARNING("Bad new salt");
            if (q->callback) {
                ((void (*)(std::shared_ptr<void>, int))q->callback)(q->callback_extra, 0);
            }
            return 0;
        }
    }
    TGL_ERROR("RPC_CALL_FAIL " <<  error_code << " " << error);
    if (q->callback) {
        ((void (*)(std::shared_ptr<void>, int))q->callback)(q->callback_extra, 0);
    }
    return 0;
}

static struct query_methods set_password_methods = {
  .on_answer = set_password_on_answer,
  .on_error = set_password_on_error,
  .on_timeout = NULL,
  .type = bool_type,
  .name = "set password",
  .timeout = 0,
};

static void tgl_do_act_set_password(const char *current_password, int current_password_len, const char *new_password, int new_password_len, const char *current_salt, int current_salt_len, const char *new_salt, int new_salt_len, const std::string &hint, void (*callback)(std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra) {
    clear_packet ();
    static char s[512];
    static unsigned char shab[32];

    assert (current_salt_len <= 128);
    assert (current_password_len <= 128);
    assert (new_salt_len <= 128);
    assert (new_password_len <= 128);

    out_int (CODE_account_update_password_settings);

    if (current_password_len && current_salt_len) {
        memcpy (s, current_salt, current_salt_len);
        memcpy (s + current_salt_len, current_password, current_password_len);
        memcpy (s + current_salt_len + current_password_len, current_salt, current_salt_len);

    TGLC_sha256 ((const unsigned char *)s, 2 * current_salt_len + current_password_len, shab);
    out_cstring ((const char *)shab, 32);
  } else {
    out_string ("");
  }

    out_int (CODE_account_password_input_settings);
    if (new_password_len) {
        out_int (1);

        static char d[256];
        memcpy (d, new_salt, new_salt_len);

        int l = new_salt_len;
        tglt_secure_random ((unsigned char*)d + l, 16);
        l += 16;
        memcpy (s, d, l);

        memcpy (s + l, new_password, new_password_len);
        memcpy (s + l + new_password_len, d, l);

    TGLC_sha256 ((const unsigned char *)s, 2 * l + new_password_len, shab);

        out_cstring (d, l);
        out_cstring ((const char *)shab, 32);
        out_cstring (hint.c_str(), hint.size());
    } else {
        out_int (0);
    }


    tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &set_password_methods, 0, (void*)callback, callback_extra);
}

struct change_password_extra {
    char *current_password = NULL;
    char *new_password = NULL;
    char *current_salt = NULL;
    char *new_salt = NULL;
    std::string hint;
    int current_password_len = 0;
    int new_password_len = 0;
    int current_salt_len = 0;
    int new_salt_len = 0;
    void (*callback)(std::shared_ptr<void>, bool) = NULL;
    std::shared_ptr<void> callback_extra;
};

void tgl_on_new_pwd (const void *pwd, std::shared_ptr<void> _T);
void tgl_on_new2_pwd (const void *pwd, std::shared_ptr<void> _T) {
    std::shared_ptr<change_password_extra> E = std::static_pointer_cast<change_password_extra>(_T);
    if (strlen ((char*)pwd) != (size_t)E->new_password_len || memcmp (E->new_password, pwd, E->new_password_len)) {
        free (E->new_password);
        E->new_password = NULL;
        E->new_password_len = 0;
        TGL_ERROR("passwords do not match");
        tgl_state::instance()->callback()->get_values(tgl_new_password, "new password: ", 2, tgl_on_new_pwd, E);
        return;
    }
    tgl_do_act_set_password (E->current_password, E->current_password_len,
                             E->new_password, E->new_password_len,
                             E->current_salt, E->current_salt_len,
                             E->new_salt, E->new_salt_len,
                             E->hint,
                             E->callback, E->callback_extra);

    free (E->current_password);
    free (E->new_password);
    free (E->current_salt);
    free (E->new_salt);
}

void tgl_on_new_pwd (const void *pwd, std::shared_ptr<void> _T) {
    std::shared_ptr<change_password_extra> E = std::static_pointer_cast<change_password_extra>(_T);
    E->new_password_len = strlen ((const char*)pwd);
    E->new_password = (char*)tmemdup (pwd, E->new_password_len);
    tgl_on_new2_pwd(pwd, E);
}

void tgl_on_old_pwd (const void *pwd, std::shared_ptr<void> _T) {
    std::shared_ptr<change_password_extra> E = std::static_pointer_cast<change_password_extra>(_T);
    const char **answer = (const char **)pwd;
    E->current_password_len = strlen (answer[0]);
    E->current_password = (char*)tmemdup (answer[0], E->current_password_len);
    tgl_on_new_pwd(*(answer + 1), E);
}

static int set_get_password_on_answer (std::shared_ptr<query> q, void *D) {
    tl_ds_account_password *DS_AP = (tl_ds_account_password*)(D);

    std::shared_ptr<std::string> new_hint = std::static_pointer_cast<std::string>(q->extra);

    std::shared_ptr<change_password_extra> E = std::make_shared<change_password_extra>();

    if (DS_AP->current_salt) {
        E->current_salt_len = DS_AP->current_salt->len;
        E->current_salt = (char*)tmemdup (DS_AP->current_salt->data, E->current_salt_len);
    }
    if (DS_AP->new_salt) {
        E->new_salt_len = DS_AP->new_salt->len;
        E->new_salt = (char*)tmemdup (DS_AP->new_salt->data, E->new_salt_len);
    }

    if (new_hint) {
        E->hint = *new_hint;
    }

    E->callback = (void (*)(std::shared_ptr<void>, bool))q->callback;
    E->callback_extra = q->callback_extra;

    if (DS_AP->magic == CODE_account_no_password) {
        tgl_state::instance()->callback()->get_values(tgl_new_password, "new password: ", 2, tgl_on_new_pwd, E);
    } else {
        static char s[512];
        snprintf (s, 511, "old password (hint %.*s): ", DS_RSTR (DS_AP->hint));
        tgl_state::instance()->callback()->get_values(tgl_cur_and_new_password, s, 3, tgl_on_old_pwd, E);
    }
    return 0;
}

static struct query_methods set_get_password_methods = {
  .on_answer = set_get_password_on_answer,
  .on_error = q_void_on_error,
  .on_timeout = NULL,
  .type = TYPE_TO_PARAM(account_password),
  .name = "get password",
  .timeout = 0,
};

void tgl_do_set_password (const char *hint, int hint_len, void (*callback)(void *extra, bool success), std::shared_ptr<void> callback_extra) {
    clear_packet ();
    out_int (CODE_account_get_password);
    std::shared_ptr<std::string> extra = hint ? std::make_shared<std::string>(hint, hint_len) : nullptr;
    tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &set_get_password_methods, extra, (void*)callback, callback_extra);
}

/* }}} */

/* {{{ check password */
static int check_password_on_error (std::shared_ptr<query> q, int error_code, const std::string &error) {
    if (error_code == 400) {
        TGL_ERROR("bad password");
        tgl_do_check_password((void (*)(std::shared_ptr<void>, bool ))q->callback, q->callback_extra);
        return 0;
    }
    tgl_state::instance()->locks ^= TGL_LOCK_PASSWORD;
    TGL_ERROR("RPC_CALL_FAIL " <<  error_code << " " << error);
    if (q->callback) {
        ((void (*)(std::shared_ptr<void>, int))q->callback)(q->callback_extra, 0);
    }
    return 0;
}

static int check_password_on_answer (std::shared_ptr<query> q, void *D) {
    TGL_UNUSED(D);
    tgl_state::instance()->locks ^= TGL_LOCK_PASSWORD;
    if (q->callback) {
        ((void (*)(std::shared_ptr<void>, int))q->callback)(q->callback_extra, 1);
    }
    return 0;
}

static struct query_methods check_password_methods = {
  .on_answer = check_password_on_answer,
  .on_error = check_password_on_error,
  .on_timeout = NULL,
  .type = TYPE_TO_PARAM(auth_authorization),
  .name = "check password",
  .timeout = 0,
};


struct check_password_extra {
    char *current_salt = NULL;
    int current_salt_len = 0;
    void (*callback)(std::shared_ptr<void>, int) = NULL;
    std::shared_ptr<void> callback_extra;
};

static void tgl_pwd_got (const void *pwd, std::shared_ptr<void> _T) {
    std::shared_ptr<check_password_extra> E = std::static_pointer_cast<check_password_extra>(_T);

    clear_packet ();
    static char s[512];
    static unsigned char shab[32];

    assert (E->current_salt_len <= 128);
    assert (strlen ((const char*)pwd) <= 128);

    out_int (CODE_auth_check_password);

    if (pwd && E->current_salt_len) {
        int l = E->current_salt_len;
        memcpy (s, E->current_salt, l);

        int r = strlen ((const char*)pwd);
        strcpy (s + l, (const char*)pwd);

        memcpy (s + l + r, E->current_salt, l);

    TGLC_sha256 ((const unsigned char *)s, 2 * l + r, shab);
    out_cstring ((const char *)shab, 32);
  } else {
    out_string ("");
  }

    tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &check_password_methods, 0, (void*)E->callback, E->callback_extra);

    free (E->current_salt);
}

static int check_get_password_on_error (std::shared_ptr<query> q, int error_code, const std::string &error) {
    tgl_state::instance()->locks ^= TGL_LOCK_PASSWORD;
    TGL_ERROR("RPC_CALL_FAIL " <<  error_code << " " << error);
    if (q->callback) {
        ((void (*)(std::shared_ptr<void>, int))q->callback) (q->callback_extra, 0);
    }
    return 0;
}

static int check_get_password_on_answer (std::shared_ptr<query> q, void *D) {
    tl_ds_account_password *DS_AP = (tl_ds_account_password*)(D);

    if (DS_AP->magic == CODE_account_no_password) {
        tgl_state::instance()->locks ^= TGL_LOCK_PASSWORD;
        return 0;
    }

  static char s[512];
  snprintf (s, 511, "type password (hint %.*s): ", DS_RSTR (DS_AP->hint));

    std::shared_ptr<check_password_extra> E = std::make_shared<check_password_extra>();

    if (DS_AP->current_salt) {
        E->current_salt_len = DS_AP->current_salt->len;
        E->current_salt = (char*)tmemdup (DS_AP->current_salt->data, E->current_salt_len);
    }

    E->callback = (void (*)(std::shared_ptr<void>, int))q->callback;
    E->callback_extra = q->callback_extra;

    tgl_state::instance()->callback()->get_values(tgl_cur_password, s, 1, tgl_pwd_got, E);
    return 0;
}

static struct query_methods check_get_password_methods = {
  .on_answer = check_get_password_on_answer,
  .on_error = check_get_password_on_error,
  .on_timeout = NULL,
  .type = TYPE_TO_PARAM(account_password),
  .name = "get password",
  .timeout = 0,
};

void tgl_do_check_password (void (*callback)(std::shared_ptr<void> extra, bool success), std::shared_ptr<void> callback_extra) {
    clear_packet ();
    out_int (CODE_account_get_password);
    tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &check_get_password_methods, NULL, (void*)callback, callback_extra);
}

/* }}} */

/* {{{ send broadcast */
void tgl_do_send_broadcast (int num, tgl_peer_id_t peer_id[], const char *text, int text_len, unsigned long long flags, void (*callback)(std::shared_ptr<void> extra, bool success, int num, struct tgl_message *ML[]), std::shared_ptr<void> callback_extra) {

  assert (num <= 1000);

  std::shared_ptr<messages_send_extra> E = std::make_shared<messages_send_extra>();
  E->multi = 1;
  E->count = num;
  E->list = (tgl_message_id_t *)talloc (sizeof (tgl_message_id_t) * num);

  int i;
  for (i = 0; i < num; i++) {
    assert (tgl_get_peer_type (peer_id[i]) == TGL_PEER_USER);

    int disable_preview = flags & TGL_SEND_MSG_FLAG_DISABLE_PREVIEW;
    //if (!(flags & TGL_SEND_MSG_FLAG_ENABLE_PREVIEW) && tgl_state::instance()->disable_link_preview) {
      //disable_preview = 1;
    //}
    if (disable_preview) {
      disable_preview = TGLMF_DISABLE_PREVIEW;
    }

    struct tgl_message_id id = tgl_peer_id_to_random_msg_id (peer_id[i]);
    E->list[i] = id;

    tgl_peer_id_t from_id = tgl_state::instance()->our_id();
    //bl_do_edit_message (&id, &from_id, &peer_id[i], NULL, NULL, &date, text, text_len, &TDSM, NULL, NULL, NULL, NULL, TGLMF_UNREAD | TGLMF_OUT | TGLMF_PENDING | TGLMF_CREATE | TGLMF_CREATED);

    int date = time (0);
    struct tl_ds_message_media TDSM;
    TDSM.magic = CODE_message_media_empty;

    struct tgl_message* M = tglm_message_create (&id, &from_id, &peer_id[i], NULL, NULL, &date, text, &TDSM, NULL, NULL, NULL, TGLMF_UNREAD | TGLMF_OUT | TGLMF_PENDING | TGLMF_CREATE | TGLMF_CREATED);
    tgls_free_message(M);
  }

  clear_packet ();
  out_int (CODE_messages_send_broadcast);
  out_int (CODE_vector);
  out_int (num);
  for (i = 0; i < num; i++) {
    assert (tgl_get_peer_type (peer_id[i]) == TGL_PEER_USER);

    out_int (CODE_input_user);
    out_int (tgl_get_peer_id (peer_id[i]));
    out_long (peer_id[i].access_hash);
  }

  out_int (CODE_vector);
  out_int (num);
  for (i = 0; i < num; i++) {
    out_long (E->list[i].id);
  }
  out_cstring (text, text_len);

  out_int (CODE_message_media_empty);

  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_msgs_methods, E, (void*)callback, callback_extra);
}
/* }}} */

/* {{{ block user */
static int block_user_on_answer (std::shared_ptr<query> q, void *D) {
    TGL_UNUSED(D);
    if (q->callback) {
        ((void (*)(std::shared_ptr<void>, int))q->callback)(q->callback_extra, 1);
    }
    return 0;
}

static struct query_methods block_user_methods = {
  .on_answer = block_user_on_answer,
  .on_error = q_void_on_error,
  .on_timeout = NULL,
  .type = bool_type,
  .name = "block user",
  .timeout = 0,
};

void tgl_do_block_user (tgl_peer_id_t id, void (*callback)(std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra) {
  if (tgl_get_peer_type (id) != TGL_PEER_USER) {
    tgl_set_query_error (EINVAL, "id should be user id");
    if (callback) {
      callback (callback_extra, 0);
    }
    return;
  }
  clear_packet ();

  out_int (CODE_contacts_block);
  out_int (CODE_input_user);
  out_int (tgl_get_peer_id (id));
  out_long (id.access_hash);
  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &block_user_methods, 0, (void*)callback, callback_extra);
}


void tgl_do_unblock_user (tgl_peer_id_t id, void (*callback)(std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra) {
  if (tgl_get_peer_type (id) != TGL_PEER_USER) {
    tgl_set_query_error (EINVAL, "id should be user id");
    if (callback) {
      callback (callback_extra, 0);
    }
    return;
  }

  clear_packet ();

  out_int (CODE_contacts_unblock);
  
  out_int (CODE_input_user);
  out_int (tgl_get_peer_id (id));
  out_long (id.access_hash);
  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &block_user_methods, 0, (void*)callback, callback_extra);
}
/* }}} */

/* {{{ get terms of service */
static int get_tos_on_answer (std::shared_ptr<struct query> q, void *D) {
  struct tl_ds_help_terms_of_service *DS_T = (struct tl_ds_help_terms_of_service *)D;
  int l = DS_T->text->len;
  char *s = (char *)talloc (l + 1);
  char *str = DS_T->text->data;
  int p = 0;
  int pp = 0;
  while (p < l) {
    if (*str == '\\' && p < l - 1) {
      str ++;
      p ++;
      switch (*str) {
      case 'n':
        s[pp ++] = '\n';
        break;
      case 't':
        s[pp ++] = '\t';
        break;
      case 'r':
        s[pp ++] = '\r';
        break;
      default:
        s[pp ++] = *str;
      }
      str ++;
      p ++;
    } else {
      s[pp ++] = *str;
      str ++;
      p ++;
    }
  }
  s[pp] = 0;

  if (q->callback) {
    ((void (*)(std::shared_ptr<void>, int, char *))q->callback)(q->callback_extra, 1, s);
  }
  tfree (s, l + 1);
  return 0;
}

struct paramed_type help_tos_type = TYPE_TO_PARAM(help_terms_of_service);
static struct query_methods get_tos_methods = {
  .on_answer = get_tos_on_answer,
  .on_error = q_ptr_on_error,
  .on_timeout = nullptr,
  .type = TYPE_TO_PARAM(help_terms_of_service),
  .name = "get tos",
  .timeout = 0,
};

void tgl_do_get_terms_of_service (void (*callback)(std::shared_ptr<void>, bool success, const char *ans), std::shared_ptr<void> callback_extra) {
  clear_packet ();

  out_int (CODE_help_get_terms_of_service);
  out_string ("");
  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &get_tos_methods, 0, (void*)callback, callback_extra);
}
/* }}} */

void tgl_do_upgrade_group (tgl_peer_id_t id, void (*callback)(std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra) {
  clear_packet ();

  out_int (CODE_messages_migrate_chat);
  out_int (tgl_get_peer_id (id));
  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_msgs_methods, 0, (void*)callback, callback_extra);
}


static void set_dc_configured (std::shared_ptr<void> _D, bool success) {
  std::shared_ptr<tgl_dc> D = std::static_pointer_cast<tgl_dc>(_D);
  assert (success);
  D->flags |= TGLDCF_CONFIGURED;

  TGL_DEBUG("DC " << D->id << " is now configured");

  //D->ev->start(tgl_state::instance()->temp_key_expire_time * 0.9);
  if (D == tgl_state::instance()->DC_working || tgl_signed_dc(D)) {
    D->send_pending_queries();
  } else if (!tgl_signed_dc(D)) {
    if (D->auth_transfer_in_process) {
      D->send_pending_queries();
    } else {
      tgl_do_transfer_auth(D->id, tgl_transfer_auth_callback, D);
    }
  }
}

static int send_bind_temp_on_answer(std::shared_ptr<query> q, void *D) {
    TGL_UNUSED(D);
    std::shared_ptr<tgl_dc> DC = std::static_pointer_cast<tgl_dc>(q->extra);
    DC->flags |= TGLDCF_BOUND;
    TGL_DEBUG("Bind successful in DC " << DC->id);
    tgl_do_help_get_config_dc (DC);
    return 0;
}

static int send_bind_on_error (std::shared_ptr<query> q, int error_code, const std::string &error) {
    TGL_UNUSED(q);
    TGL_WARNING("bind: error " << error_code << " " << error);
    if (error_code == 400) {
        return -11;
    }
    return 0;
}

static struct query_methods send_bind_temp_methods = {
  .on_answer = send_bind_temp_on_answer,
  .on_error = send_bind_on_error,
  .on_timeout = NULL,
  .type = bool_type,
  .name = "bind temp auth key",
  .timeout = 0,
};

void tgl_do_send_bind_temp_key (std::shared_ptr<tgl_dc> D, long long nonce, int expires_at, void *data, int len, long long msg_id) {
    clear_packet ();
    out_int (CODE_auth_bind_temp_auth_key);
    out_long (D->auth_key_id);
    out_long (nonce);
    out_int (expires_at);
    out_cstring ((char*)data, len);
    std::shared_ptr<query> q = tglq_send_query_ex (D, packet_ptr - packet_buffer, packet_buffer, &send_bind_temp_methods, D, 0, 0, QUERY_FORCE_SEND);
    assert (q->msg_id == msg_id);
}

static int update_status_on_answer (std::shared_ptr<query> q, void *D) {
    TGL_UNUSED(D);
    if (q->callback) {
        ((void (*)(std::shared_ptr<void>, int))q->callback) (q->callback_extra, 1);
    }
    return 0;
}

static struct query_methods update_status_methods = {
  .on_answer = update_status_on_answer,
  .on_error = q_void_on_error,
  .on_timeout = NULL,
  .type = bool_type,
  .name = "update status",
  .timeout = 0,
};

void tgl_do_update_status (int online, void (*callback)(std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra) {
    clear_packet ();
    out_int (CODE_account_update_status);
    out_int (online ? CODE_bool_false : CODE_bool_true);
    tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &update_status_methods, 0, (void*)callback, callback_extra);
}

#ifdef ENABLE_SECRET_CHAT
void tgl_do_request_exchange (struct tgl_secret_chat *E) {
  assert (0);
  exit (2);
}

void tgl_do_accept_exchange (struct tgl_secret_chat *E, long long exchange_id, unsigned char ga[]) {
  assert (0);
  exit (2);
}

void tgl_do_confirm_exchange (struct tgl_secret_chat *E, int sen_nop) {
  assert (0);
  exit (2);
}

void tgl_do_commit_exchange (struct tgl_secret_chat *E, unsigned char gb[]) {
  assert (0);
  exit (2);
}

void tgl_do_abort_exchange (struct tgl_secret_chat *E) {
  assert (0);
  exit (2);
}
#endif

void tgl_started_cb(std::shared_ptr<void> arg, bool success) {
  TGL_UNUSED(arg);
  if (!success) {
    TGL_ERROR("login problem");
    tgl_state::instance()->callback()->on_failed_login();
    return;
  }
  if (!tgl_state::instance()->started) {
    tgl_state::instance()->started = 1;
    tgl_state::instance()->callback()->started();
  }
}

void tgl_transfer_auth_callback (std::shared_ptr<void> arg, bool success) {
  std::shared_ptr<tgl_dc> DC = std::static_pointer_cast<tgl_dc>(arg);
  assert(DC);
  DC->auth_transfer_in_process = false;
  if (!success) {
    TGL_ERROR("auth transfer problem to DC " << DC->id);
    return;
  }
  TGL_NOTICE("auth transferred from DC " << tgl_state::instance()->DC_working->id << " to DC " << DC->id);
  DC->send_pending_queries();
}

void tgl_export_all_auth () {
  for (size_t i = 0; i < tgl_state::instance()->DC_list.size(); i++) {
    if (tgl_state::instance()->DC_list[i] && !tgl_signed_dc(tgl_state::instance()->DC_list[i])) {
      tgl_do_transfer_auth (i, tgl_transfer_auth_callback, tgl_state::instance()->DC_list[i]);
    }
  }
}

void tgl_signed_in() {
  tgl_state::instance()->callback()->logged_in();

  TGL_DEBUG("signed in, sending unsent messages and retrieving current server state");

  tglm_send_all_unsent();
  tgl_do_get_difference (0, tgl_started_cb, 0);
}

struct sign_up_extra {
    char *phone = NULL;
    char *hash = NULL;
    char *first_name = NULL;
    char *last_name = NULL;
    int phone_len = 0;
    int hash_len = 0;
    int first_name_len = 0;
    int last_name_len = 0;
};

void tgl_sign_in_code (const void *code, std::shared_ptr<void> _T);
void tgl_sign_in_result (std::shared_ptr<void> _T, bool success, struct tgl_user *U) {
    TGL_ERROR(".....tgl_sign_in_result");
    std::shared_ptr<sign_up_extra> E = std::static_pointer_cast<sign_up_extra>(_T);
    if (success) {
        free (E->phone);
        free (E->hash);
    } else {
        TGL_ERROR("incorrect code");
        tgl_state::instance()->callback()->get_values(tgl_code, "code ('call' for phone call):", 1, tgl_sign_in_code, E);
        return;
    }
    tgl_signed_in();
}

void tgl_sign_in_code (const void *code, std::shared_ptr<void> _T) {
    std::shared_ptr<sign_up_extra> E = std::static_pointer_cast<sign_up_extra>(_T);
    if (!strcmp ((const char *)code, "call")) {
        tgl_do_phone_call (E->phone, E->phone_len, E->hash, E->hash_len, 0, 0);
        tgl_state::instance()->callback()->get_values(tgl_code, "code ('call' for phone call):", 1, tgl_sign_in_code, E);
        return;
    }

    tgl_do_send_code_result(E->phone, E->phone_len, E->hash, E->hash_len, (const char *)code, strlen ((const char *)code), tgl_sign_in_result, E);
}

void tgl_sign_up_code (const void *code, std::shared_ptr<void> _T);
void tgl_sign_up_result (std::shared_ptr<void> _T, bool success, struct tgl_user *U) {
    TGL_UNUSED(U);
    std::shared_ptr<sign_up_extra> E = std::static_pointer_cast<sign_up_extra>(_T);
    if (success) {
        free (E->phone);
        free (E->hash);
        free (E->first_name);
        free (E->last_name);
    } else {
        TGL_ERROR("incorrect code");
        tgl_state::instance()->callback()->get_values(tgl_code, "code ('call' for phone call):", 1, tgl_sign_up_code, E);
        return;
    }
    tgl_signed_in();
}

void tgl_sign_up_code (const void *code, std::shared_ptr<void> _T) {
    std::shared_ptr<sign_up_extra> E = std::static_pointer_cast<sign_up_extra>(_T);
    if (!strcmp ((const char*)code, "call")) {
        tgl_do_phone_call (E->phone, E->phone_len, E->hash, E->hash_len, 0, 0);
        tgl_state::instance()->callback()->get_values(tgl_code, "code ('call' for phone call):", 1, tgl_sign_up_code, E);
        return;
    }

    tgl_do_send_code_result_auth (E->phone, E->phone_len, E->hash, E->hash_len, (const char*)code, strlen ((const char*)code), E->first_name, E->first_name_len, E->last_name, E->last_name_len, tgl_sign_up_result, E);
}


void tgl_set_last_name (const char *last_name, std::shared_ptr<sign_up_extra> E) {
    E->last_name_len = strlen (last_name);
    E->last_name = (char*)tmemdup (last_name, E->last_name_len);
}

int tgl_set_first_name (const char *first_name, std::shared_ptr<sign_up_extra> E) {
    if (strlen (first_name) < 1) {
        return -1;
    }

    E->first_name_len = strlen (first_name);
    E->first_name = (char*)tmemdup (first_name, E->first_name_len);
    return 0;
}

void tgl_register_cb (const void *rinfo, std::shared_ptr<void> _T) {
    std::shared_ptr<sign_up_extra> E = std::static_pointer_cast<sign_up_extra>(_T);
    const char **yn = (const char**)rinfo;
    if (yn[0]) {
        if (!tgl_set_first_name(yn[1], E)) {
            tgl_set_last_name(yn[2], E);
            tgl_state::instance()->callback()->get_values(tgl_code, "code ('call' for phone call):", 1, tgl_sign_up_code, E);
        }
        else {
            tgl_state::instance()->callback()->get_values(tgl_register_info, "registration info:", 3, tgl_register_cb, E);
        }
    } else {
        TGL_ERROR("stopping registration");
        free (E->phone);
        free (E->hash);
        tgl_state::instance()->login ();
    }
}

void tgl_sign_in_phone (const void *phone, std::shared_ptr<void> arg);
void tgl_sign_in_phone_cb (std::shared_ptr<void> extra, bool success, int registered, const char *mhash) {
    tgl_state::instance()->locks ^= TGL_LOCK_PHONE;
    std::shared_ptr<sign_up_extra> E = std::static_pointer_cast<sign_up_extra>(extra);
    if (!success) {
        TGL_ERROR("Incorrect phone number");

        free (E->phone);
        tgl_state::instance()->callback()->get_values(tgl_phone_number, "phone number:", 1, tgl_sign_in_phone, NULL);
        return;
    }

    E->hash_len = strlen (mhash);
    E->hash = (char*)tmemdup (mhash, E->hash_len);

    if (registered) {
        TGL_NOTICE("Already registered. Need code");
        tgl_state::instance()->callback()->get_values(tgl_code, "code ('call' for phone call):", 1, tgl_sign_in_code, E);
    } else {
        TGL_NOTICE("Not registered");
        tgl_state::instance()->callback()->get_values(tgl_register_info, "registration info:", 3, tgl_register_cb, E);
    }
}

void tgl_sign_in_phone (const void *phone, std::shared_ptr<void> arg) {
    TGL_UNUSED(arg);
    std::shared_ptr<sign_up_extra> E = std::make_shared<sign_up_extra>();
    E->phone_len = strlen((const char *)phone);
    E->phone = (char*)tmemdup (phone, E->phone_len);

    tgl_state::instance()->locks |= TGL_LOCK_PHONE;

    tgl_do_send_code (E->phone, E->phone_len, tgl_sign_in_phone_cb, E);
}

void tgl_bot_hash_cb (const void *code, std::shared_ptr<void> arg);

void tgl_sign_in_bot_cb (std::shared_ptr<void> _T, bool success, struct tgl_user *U) {
    TGL_UNUSED(_T);
    TGL_UNUSED(U);
    if (!success) {
        TGL_ERROR("incorrect bot hash");
        tgl_state::instance()->callback()->get_values(tgl_bot_hash, "bot hash:", 1, tgl_bot_hash_cb, nullptr);
        return;
    }
    tgl_signed_in();
}

void tgl_bot_hash_cb (const void *code, std::shared_ptr<void> arg) {
    TGL_UNUSED(arg);
    tgl_do_send_bot_auth ((const char*)code, strlen ((const char*)code), tgl_sign_in_bot_cb, NULL);
}

void tgl_sign_in () {
  if (!tgl_signed_dc(tgl_state::instance()->DC_working)) {
    if (!(tgl_state::instance()->locks & TGL_LOCK_PHONE)) {
      tgl_state::instance()->callback()->get_values(tgl_phone_number, "phone number:", 1, tgl_sign_in_phone, NULL);
    }
  } else {
    tgl_signed_in();
  }
}

static void check_authorized (std::shared_ptr<void> arg) {
  std::shared_ptr<tgl_dc> DC = tgl_state::instance()->DC_working;
  if (!DC) {
    TGL_ERROR("no working DC, can't check authorization");
    return;
  }

  if (DC && (tgl_signed_dc(DC) || tgl_authorized_dc(DC))) {
    tgl_state::instance()->ev_login = nullptr;
    tgl_sign_in();
  } else {
    tgl_dc_authorize(DC);
    tgl_state::instance()->ev_login->start(0.1);
  }
}

void tgl_state::login () {
  if (DC_working && tgl_signed_dc(DC_working) && tgl_authorized_dc(DC_working)) {
    tgl_sign_in();
  } else {
    tgl_state::instance()->ev_login = tgl_state::instance()->timer_factory()->create_timer(std::bind(&check_authorized, nullptr));
    tgl_state::instance()->ev_login->start(0.1);
  }
}


static int callback (std::shared_ptr<struct query> q, void *D) {
   if (q->callback) {
     ((void (*)(std::shared_ptr<void>))(q->callback)) (q->callback_extra);
  }
  return 0;
}

static int send_change_code_on_answer (std::shared_ptr<struct query> q, void *D) {

  struct tl_ds_account_sent_change_phone_code *DS_ASCPC = (struct tl_ds_account_sent_change_phone_code *)D;

  char *phone_code_hash = DS_STR_DUP (DS_ASCPC->phone_code_hash);

  if (q->callback) {
    ((void (*)(std::shared_ptr<void>, int, const char *))(q->callback)) (q->callback_extra, 1, phone_code_hash);
  }
  tfree_str (phone_code_hash);
  return 0;
}

struct change_phone_extra {
  char *phone;
  char *hash;
  char *first_name;
  char *last_name;
  int phone_len;
  int hash_len;
  int first_name_len;
  int last_name_len;
  void (*callback)(std::shared_ptr<void> extra, bool success);
  std::shared_ptr<void> callback_extra;
};

static struct query_methods set_phone_methods  = {
  .on_answer = callback,
  .on_error = sign_in_on_error,
  .on_timeout = nullptr,
  .type = TYPE_TO_PARAM(user),
  .name = "set phone",
  .timeout = 0,
};

static struct query_methods send_change_code_methods  = {
  .on_answer = send_change_code_on_answer,
  .on_error = q_list_on_error,
  .on_timeout = nullptr,
  .type = TYPE_TO_PARAM(account_sent_change_phone_code),
  .name = "send change phone code",
  .timeout = 0,
};

void tgl_set_number_code (const void *code, std::shared_ptr<void> _T);
void tgl_set_number_result (std::shared_ptr<void> _T, bool success, struct tgl_user *U) {
  std::shared_ptr<struct change_phone_extra> E = std::static_pointer_cast<change_phone_extra>(_T);
  if (success) {
    if (E->callback) {
      E->callback (E->callback_extra, 1);
    }
    tfree (E->phone, E->phone_len);
    tfree (E->hash, E->hash_len);
  } else {
    TGL_ERROR("incorrect code");
    tgl_state::instance()->callback()->get_values (tgl_code, "code:", 1, tgl_set_number_code, E);
  }
}

void tgl_set_number_code (const void *code, std::shared_ptr<void> _T) {
  std::shared_ptr<struct change_phone_extra> E = std::static_pointer_cast<change_phone_extra>(_T);

  const char **code_strings = (const char **)code;

  clear_packet ();
  out_int (CODE_account_change_phone);
  out_cstring (E->phone, E->phone_len);
  out_cstring (E->hash, E->hash_len);
  out_cstring (code_strings[0], strlen (code_strings[0]));
  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &set_phone_methods, 0, (void*)tgl_set_number_result, E);
}


void tgl_set_phone_number_cb (std::shared_ptr<void> extra, bool success, const char *mhash) {
  std::shared_ptr<struct change_phone_extra> E = std::static_pointer_cast<change_phone_extra>(extra);
  if (!success) {
    TGL_ERROR("Incorrect phone number");
    if (E->callback) {
      E->callback (E->callback_extra, 0);
    }
    tfree (E->phone, E->phone_len);
    return;
  }

  E->hash_len = strlen (mhash);
  E->hash = (char *)tmemdup (mhash, E->hash_len);

  tgl_state::instance()->callback()->get_values (tgl_code, "code:", 1, tgl_set_number_code, E);
}

void tgl_do_set_phone_number (const char *phonenumber, int phonenumber_len, void (*callback)(std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra) {
  std::shared_ptr<struct change_phone_extra> E = std::make_shared<change_phone_extra>();
  E->phone_len = phonenumber_len;
  E->phone = (char *)tmemdup (phonenumber, E->phone_len);

  clear_packet ();
  tgl_do_insert_header ();
  out_int (CODE_account_send_change_phone_code);
  out_cstring (E->phone, E->phone_len);
  E->callback = callback;
  E->callback_extra = callback_extra;

  tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &send_change_code_methods, NULL, (void*)tgl_set_phone_number_cb, E);
}
