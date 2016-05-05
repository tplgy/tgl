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
#include "queries-encrypted.h"
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

static int mystreq1 (const char *a, const char *b, int l) {
    if ((int)strlen (a) != l) { return 1; }
    return memcmp (a, b, l);
}

/* {{{ COMMON */

std::shared_ptr<query> tglq_query_get(long long id)
{
    for (auto it = tgl_state::instance()->queries_tree.begin(); it != tgl_state::instance()->queries_tree.end(); it++) {
        if (id == (*it)->msg_id()) {
            return *it;
        }
    }
    return NULL;
}

static void tglq_query_remove(const std::shared_ptr<query>& q)
{
    for (auto it = tgl_state::instance()->queries_tree.begin(); it != tgl_state::instance()->queries_tree.end(); it++) {
        if (q == (*it)) {
            tgl_state::instance()->queries_tree.erase(it);
            return;
        }
    }
}

void query::cancel_timer()
{
    if (m_timer) {
        m_timer->cancel();
    }
}

void query::clear_timer()
{
    cancel_timer();
    m_timer = nullptr;
}

void query::alarm()
{
    TGL_DEBUG("Alarm query " << m_msg_id << " (type '" << m_name << "')");

    assert(m_timer);
    double timeout = timeout_interval();
    m_timer->start(timeout ? timeout : DEFAULT_QUERY_TIMEOUT);

    if (m_session && m_session_id && m_dc && m_dc->sessions[0] == m_session && m_session->session_id == m_session_id) {
        clear_packet ();
        out_int (CODE_msg_container);
        out_int (1);
        out_long (m_msg_id);
        out_int (m_seq_no);
        out_int (m_data.size());
        out_ints ((int*)m_data.data(), m_data.size() / 4);
        tglmp_encrypt_send_message (m_session->c, packet_buffer, packet_ptr - packet_buffer, m_flags & QUERY_FORCE_SEND);
    } else if (m_dc->sessions[0]) {
        m_flags &= ~QUERY_ACK_RECEIVED;
        tglq_query_remove(shared_from_this());
        m_session = m_dc->sessions[0];
        long long old_id = m_msg_id;
        m_msg_id = tglmp_encrypt_send_message(m_session->c, (int*)m_data.data(), m_data.size() / 4, (m_flags & QUERY_FORCE_SEND) | 1);
        TGL_NOTICE("Resent query #" << old_id << " as #" << m_msg_id << " of size " << m_data.size() << " to DC " << m_dc->id);
        tgl_state::instance()->queries_tree.push_back(shared_from_this());
        m_session_id = m_session->session_id;
        auto dc = m_session->dc.lock();
        if (dc && !(dc->flags & TGLDCF_CONFIGURED) && !(m_flags & QUERY_FORCE_SEND)) {
            m_session_id = 0;
        }
    } else {
        // we don't have a valid session with the DC, so defer query until we do
        m_timer->cancel();
        m_dc->add_pending_query(shared_from_this());
    }
}

void tglq_regen_query (long long id) {
  std::shared_ptr<query> q = tglq_query_get (id);
  if (!q) { return; }
  TGL_NOTICE("regen query " << id);
  q->regen();
}

void query::regen()
{
  m_flags &= ~QUERY_ACK_RECEIVED;

  if (!(m_session && m_session_id && m_dc && m_dc->sessions[0] == m_session && m_session->session_id == m_session_id)) {
    m_session_id = 0;
  } else {
    auto dc = m_session->dc.lock();
    if (dc && !(dc->flags & TGLDCF_CONFIGURED) && !(m_flags & QUERY_FORCE_SEND)) {
      m_session_id = 0;
    }
  }
  m_timer->start(0.001);
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
        q->cancel_timer();
        q->alarm();
    }
}

static void alarm_query_gateway(std::shared_ptr<query> q) {
    assert(q);
    if (q->on_timeout()) {
        tglq_query_remove(q);
    } else {
        q->alarm();
    }
}

void tgl_transfer_auth_callback (std::shared_ptr<tgl_dc> arg, bool success);
void tgl_do_transfer_auth (int num, std::function<void(bool success)> callback);

void query::execute(const std::shared_ptr<tgl_dc>& dc, int flags)
{
    m_dc = dc;
    assert(m_dc);
    bool pending = false;
    if (!m_dc->sessions[0]) {
        tglmp_dc_create_session(m_dc);
        pending = true;
    }

    if (!(m_dc->flags & TGLDCF_CONFIGURED) && !(flags & QUERY_FORCE_SEND)) {
        pending = true;
    }

    if (!tgl_signed_dc(m_dc) && !(flags & QUERY_LOGIN) && !(flags & QUERY_FORCE_SEND)) {
        pending = true;
        if (m_dc != tgl_state::instance()->DC_working) {
            tgl_do_transfer_auth(m_dc->id, std::bind(tgl_transfer_auth_callback, m_dc, std::placeholders::_1));
        }
    }

    TGL_DEBUG("Sending query \"" << m_name << "\" of size " << m_data.size() << " to DC " << m_dc->id << (pending ? " (pending)" : ""));

    if (pending) {
        m_msg_id = 0;
        m_session = 0;
        m_session_id = 0;
        m_seq_no = 0;
    } else {
        m_msg_id = tglmp_encrypt_send_message (m_dc->sessions[0]->c, (int*)m_data.data(), m_data.size() / 4, 1 | (flags & QUERY_FORCE_SEND));
        m_session = m_dc->sessions[0];
        m_session_id = m_session->session_id;
        m_seq_no = m_session->seq_no - 1;
        TGL_DEBUG("Sent query \"" << m_name << "\" of size " << m_data.size() << " to DC " << m_dc->id << ": #" << m_msg_id);
    }

    m_flags = flags & ~QUERY_ACK_RECEIVED;
    tgl_state::instance()->queries_tree.push_back(shared_from_this());

    m_timer = tgl_state::instance()->timer_factory()->create_timer(std::bind(&alarm_query_gateway, shared_from_this()));
    if (!pending) {
        double timeout = timeout_interval();
        m_timer->start(timeout ? timeout : DEFAULT_QUERY_TIMEOUT);
    }

    tgl_state::instance()->active_queries ++;
    m_dc->add_query(shared_from_this());

    if (pending) {
        m_dc->add_pending_query(shared_from_this());
    }
}

bool query::execute_after_pending()
{
    assert(m_dc);
    double timeout = timeout_interval();

    if (!m_dc->sessions[0]) {
        tglmp_dc_create_session(m_dc);
    }

    if (!m_dc->auth_key_id) {
        TGL_DEBUG("not ready to send pending query " << this << " (" << m_name << "), re-queuing");
        m_dc->add_pending_query(shared_from_this());
        return false;
    }
    if (!tgl_signed_dc(m_dc) && !(m_flags & QUERY_LOGIN)) {
        TGL_DEBUG("not ready to send pending non-login query " << this << " (" << m_name << "), re-queuing");
        m_dc->add_pending_query(shared_from_this());
        return false;
    }

    m_flags &= ~QUERY_ACK_RECEIVED;
    tglq_query_remove(shared_from_this());
    m_session = m_dc->sessions[0];
    m_msg_id = tglmp_encrypt_send_message(m_session->c, (int*)m_data.data(), m_data.size() / 4, (m_flags & QUERY_FORCE_SEND) | 1);
    tgl_state::instance()->queries_tree.push_back(shared_from_this());
    m_session_id = m_session->session_id;
    auto dc = m_session->dc.lock();
    if (dc && !(dc->flags & TGLDCF_CONFIGURED) && !(m_flags & QUERY_FORCE_SEND)) {
        m_session_id = 0;
    }

    TGL_DEBUG("Sending pending query \"" << m_name << "\" (" << m_msg_id << ") of size " << m_data.size() << " to DC " << m_dc->id);

    m_timer->start(timeout ? timeout : DEFAULT_QUERY_TIMEOUT);

    return true;
}

void tglq_query_ack(long long id) {
    std::shared_ptr<query> q = tglq_query_get(id);
    if (q) {
        q->ack();
    }
}

void query::ack()
{
    if (!(m_flags & QUERY_ACK_RECEIVED)) {
        m_flags |= QUERY_ACK_RECEIVED;
        cancel_timer();
    }
}

void tglq_query_delete(long long id) {
    std::shared_ptr<query> q = tglq_query_get (id);
    if (!q) {
        return;
    }

    q->clear_timer();
    tglq_query_remove(q);
    tgl_state::instance()->active_queries --;
    q->dc()->remove_query(q);
}

static void resend_query_cb(const std::shared_ptr<query>& q, bool success);

void tglq_free_query (std::shared_ptr<query> q) {
    q->clear_timer();
}

void tglq_query_free_all () {
    for (auto it = tgl_state::instance()->queries_tree.begin(); it != tgl_state::instance()->queries_tree.end(); it++) {
        tglq_free_query(*it);
    }
    tgl_state::instance()->queries_tree.clear();
}

int tglq_query_error(long long id)
{
    int result = fetch_int ();
    TGL_ASSERT_UNUSED(result, result == CODE_rpc_error);
    int error_code = fetch_int ();
    int error_len = prefetch_strlen ();
    std::string error_string = std::string(fetch_str (error_len), error_len);
    std::shared_ptr<query> q = tglq_query_get(id);
    if (!q) {
        TGL_WARNING("error for unknown query #" << id << " #" << error_code << ": " << error_string);
    } else {
        TGL_WARNING("error for query '" << q->name() << "' #" << id << " #" << error_code << ": " << error_string);
        return q->handle_error(error_code, error_string);
    }

    tgl_state::instance()->active_queries--;

    return 0;
}

int query::handle_error(int error_code, const std::string& error_string)
{
    if (!(m_flags & QUERY_ACK_RECEIVED)) {
        cancel_timer();
    }

    tglq_query_remove(shared_from_this());
    int res = 0;

    int error_handled = 0;

    switch (error_code) {
      case 303:
        // migrate
        {
          int offset = -1;
          if (error_string.size() >= 15 && !memcmp (error_string.data(), "PHONE_MIGRATE_", 14)) {
            offset = 14;
            //} else if (error_len >= 14 && !memcmp (error_string, "FILE_MIGRATE_", 13)) {
            //    offset = 13;
        }
        if (error_string.size() >= 17 && !memcmp (error_string.data(), "NETWORK_MIGRATE_", 16)) {
          offset = 16;
        }
        if (error_string.size() >= 14 && !memcmp (error_string.data(), "USER_MIGRATE_", 13)) {
          offset = 13;
        }
        if (offset >= 0) {
          int i = 0;
          while (offset < static_cast<int>(error_string.size()) && error_string.data()[offset] >= '0' && error_string.data()[offset] <= '9') {
            i = i * 10 + error_string[offset] - '0';
            offset ++;
          }
          TGL_WARNING("Trying to handle error...");
          if (i > 0 && i < TGL_MAX_DC_NUM) {
            tgl_state::instance()->set_working_dc(i);
            tgl_state::instance()->login();
            m_flags &= ~QUERY_ACK_RECEIVED;
            //m_session_id = 0;
            //struct tgl_dc *DC = q->DC;
            //if (!(DC->flags & 4) && !(q->flags & QUERY_FORCE_SEND)) {
            m_session_id = 0;
            //}
            m_dc = tgl_state::instance()->DC_working;
            m_timer->start(0);
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
        if (!mystreq1 ("SESSION_PASSWORD_NEEDED", error_string.data(), error_string.size())) {
          if (!(tgl_state::instance()->locks & TGL_LOCK_PASSWORD)) {
            tgl_state::instance()->locks |= TGL_LOCK_PASSWORD;
            tgl_do_check_password(std::bind(resend_query_cb, shared_from_this(), std::placeholders::_1)); // TODO make that a shared_ptr
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
          if (strncmp (error_string.data(), "FLOOD_WAIT_", 11)) {
            if (error_code == 420) {
              TGL_ERROR("error = " << error_string);
            }
            wait = 10;
          } else {
            wait = atoll (error_string.data() + 11);
          }
          m_flags &= ~QUERY_ACK_RECEIVED;
          m_timer->start(wait);
          std::shared_ptr<tgl_dc> DC = m_dc;
          if (!(DC->flags & 4) && !(m_flags & QUERY_FORCE_SEND)) {
            m_session_id = 0;
          }
          error_handled = 1;
        }
        break;
    }

    if (error_handled) {
      TGL_NOTICE("error for query #" << m_msg_id << " error:" << error_code << " " << error_string << " (HANDLED)");
    } else {
      TGL_WARNING("error for query #"<< m_msg_id << " error:" << error_code << " " << error_string);
      res = on_error(error_code, error_string);
    }

    m_dc->remove_query(shared_from_this());

    if (res <= 0) {
      clear_timer();
    }

    if (res == -11) {
      tgl_state::instance()->active_queries --;
      return -1;

    }

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
    if (!(q->flags() & QUERY_ACK_RECEIVED)) {
      q->cancel_timer();
    }

    int *save = in_ptr;
    TGL_DEBUG("in_ptr = " << in_ptr << ", end_ptr = " << in_end);
    if (skip_type_any (q->type()) < 0) {
      TGL_ERROR("Skipped " << (long)(in_ptr - save) << " int out of " << (long)(in_end - save) << " (type " << q->type()->type->id << ") (query type " << q->name() << ")");
      TGL_ERROR("0x" << std::hex << *(save - 1) << " 0x" << *(save) << " 0x" << *(save + 1) << " 0x" << *(save + 2));
      assert (0);
    }

    assert (in_ptr == in_end);
    in_ptr = save;

    void *DS = fetch_ds_type_any (q->type());
    assert (DS);

    q->on_answer(DS);
    free_ds_type_any (DS, q->type());

    assert (in_ptr == in_end);

    q->clear_timer();
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

class query_help_get_config: public query
{
public:
    explicit query_help_get_config(const std::function<void(bool)>& callback)
        : query("get config", TYPE_TO_PARAM(config))
        , m_callback(callback)
    { }

    virtual void on_answer(void* DS) override
    {
        tl_ds_config* DS_C = static_cast<tl_ds_config*>(DS);

        int count = DS_LVAL(DS_C->dc_options->cnt);
        for (int i = 0; i < count; ++i) {
            fetch_dc_option(DS_C->dc_options->data[i]);
        }

        int max_chat_size = DS_LVAL(DS_C->chat_size_max);
        int max_bcast_size = 0; //DS_LVAL (DS_C->broadcast_size_max);
        TGL_DEBUG("chat_size = " << max_chat_size << ", bcast_size = " << max_bcast_size);

        if (m_callback) {
            m_callback(true);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false);
        }
        return 0;
    }

    virtual double timeout_interval() const override { return 1; }

private:
    std::function<void(bool)> m_callback;
};

void tgl_do_help_get_config(std::function<void(bool)> callback) {
    clear_packet ();
    tgl_do_insert_header ();
    out_int (CODE_help_get_config);

    auto q = std::make_shared<query_help_get_config>(callback);
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    q->execute(tgl_state::instance()->DC_working);
}

static void set_dc_configured (std::shared_ptr<void> _D, bool success);
void tgl_do_help_get_config_dc (std::shared_ptr<tgl_dc> D) {
    clear_packet ();
    tgl_do_insert_header();
    out_int (CODE_help_get_config);

    auto q = std::make_shared<query_help_get_config>(std::bind(set_dc_configured, D, std::placeholders::_1));
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    q->execute(tgl_state::instance()->DC_working, QUERY_FORCE_SEND);
}
/* }}} */

/* {{{ Send code */
class query_send_code: public query
{
public:
    explicit query_send_code(const std::function<void(bool, int, const char*)>& callback)
        : query("send code", TYPE_TO_PARAM(auth_sent_code))
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        tl_ds_auth_sent_code* DS_ASC = static_cast<tl_ds_auth_sent_code*>(D);

        std::string phone_code_hash;
        if (DS_ASC->phone_code_hash && DS_ASC->phone_code_hash->data) {
            phone_code_hash = std::string(DS_ASC->phone_code_hash->data, DS_ASC->phone_code_hash->len);
        }

        int registered = DS_BVAL(DS_ASC->phone_registered);;

        if (m_callback) {
            m_callback(true, registered, phone_code_hash.c_str());
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false, 0, nullptr);
        }
        return 0;
    }

private:
    std::function<void(bool, int, const char*)> m_callback;
};

void tgl_do_send_code (const char *phone, int phone_len, std::function<void(bool, int, const char *)> callback) {
    TGL_NOTICE("requesting confirmation code from dc " << tgl_state::instance()->DC_working->id);

    clear_packet ();
    tgl_do_insert_header ();
    out_int (CODE_auth_send_code);
    out_cstring (phone, phone_len);
    out_int (0);
    out_int (tgl_state::instance()->app_id());
    out_string (tgl_state::instance()->app_hash().c_str());
    out_string ("en");

    auto q = std::make_shared<query_send_code>(callback);
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    q->execute(tgl_state::instance()->DC_working, QUERY_LOGIN);
}

class query_phone_call: public query
{
public:
    explicit query_phone_call(const std::function<void(bool)>& callback)
        : query("phone call", TYPE_TO_PARAM(bool))
        , m_callback(callback)
    { }

    virtual void on_answer(void*) override
    {
        if (m_callback) {
            m_callback(true);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false);
        }
        return 0;
    }

private:
    std::function<void(bool)> m_callback;
};

void tgl_do_phone_call (const char *phone, int phone_len, const char *hash, int hash_len, std::function<void(bool)> callback) {
    TGL_DEBUG("calling user");

    clear_packet ();
    tgl_do_insert_header ();
    out_int (CODE_auth_send_call);
    out_cstring (phone, phone_len);
    out_cstring (hash, hash_len);

    auto q = std::make_shared<query_phone_call>(callback);
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    q->execute(tgl_state::instance()->DC_working);
}
/* }}} */

/* {{{ Sign in / Sign up */
class query_sign_in: public query
{
public:
    explicit query_sign_in(const std::function<void(bool, const std::shared_ptr<struct tgl_user>&)>& callback)
        : query("sign in", TYPE_TO_PARAM(auth_authorization))
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        TGL_DEBUG2("sign_in_on_answer");
        tl_ds_auth_authorization* DS_AA = static_cast<tl_ds_auth_authorization*>(D);
        std::shared_ptr<struct tgl_user> user = tglf_fetch_alloc_user(DS_AA->user);
        tgl_state::instance()->set_dc_signed (tgl_state::instance()->DC_working->id);
        if (m_callback) {
            m_callback(!!user, user);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false, nullptr);
        }
        return 0;
    }

private:
    std::function<void(bool, const std::shared_ptr<struct tgl_user>&)> m_callback;
};

int tgl_do_send_code_result (const char *phone, int phone_len, const char *hash, int hash_len, const char *code, int code_len, std::function<void(bool success, const std::shared_ptr<tgl_user>& U)> callback) {
    clear_packet ();
    out_int (CODE_auth_sign_in);
    out_cstring (phone, phone_len);
    out_cstring (hash, hash_len);
    out_cstring (code, code_len);

    auto q = std::make_shared<query_sign_in>(callback);
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    q->execute(tgl_state::instance()->DC_working, QUERY_LOGIN);
    return 0;
}

int tgl_do_send_code_result_auth (const char *phone, int phone_len, const char *hash, int hash_len, const char *code, int code_len, const char *first_name, int first_name_len,
        const char *last_name, int last_name_len, std::function<void(bool, const std::shared_ptr<tgl_user>&)> callback) {
    clear_packet ();
    out_int (CODE_auth_sign_up);
    out_cstring (phone, phone_len);
    out_cstring (hash, hash_len);
    out_cstring (code, code_len);
    out_cstring (first_name, first_name_len);
    out_cstring (last_name, last_name_len);

    auto q = std::make_shared<query_sign_in>(callback);
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    q->execute(tgl_state::instance()->DC_working, QUERY_LOGIN);
    return 0;
}

int tgl_do_send_bot_auth (const char *code, int code_len, std::function<void(bool, const std::shared_ptr<tgl_user>&)> callback) {
    clear_packet ();
    out_int (CODE_auth_import_bot_authorization);
    out_int (0);
    out_int (tgl_state::instance()->app_id());
    out_string (tgl_state::instance()->app_hash().c_str());
    out_cstring (code, code_len);

    auto q = std::make_shared<query_sign_in>(callback);
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    q->execute(tgl_state::instance()->DC_working, QUERY_LOGIN);
    return 0;
}
/* }}} */

/* {{{ Get contacts */
class query_get_contacts: public query
{
public:
    explicit query_get_contacts(
            const std::function<void(bool, const std::vector<std::shared_ptr<tgl_user>>&)>& callback)
        : query("get contacts", TYPE_TO_PARAM(contacts_contacts))
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        tl_ds_contacts_contacts* DS_CC = static_cast<tl_ds_contacts_contacts*>(D);
        int n = DS_CC->users ? DS_LVAL (DS_CC->users->cnt) : 0;
        std::vector<std::shared_ptr<tgl_user>> users(n);
        for (int i = 0; i < n; i++) {
            users[i] = tglf_fetch_alloc_user(DS_CC->users->data[i]);
        }
        if (m_callback) {
            m_callback(true, users);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false, std::vector<std::shared_ptr<tgl_user>>());
        }
        return 0;
    }

private:
    std::function<void(bool, const std::vector<std::shared_ptr<tgl_user>>&)> m_callback;
};

void tgl_do_update_contact_list () {
    clear_packet ();
    out_int (CODE_contacts_get_contacts);
    out_string ("");

    auto q = std::make_shared<query_get_contacts>(nullptr);
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    q->execute(tgl_state::instance()->DC_working);
}
/* }}} */

/* {{{ Send msg (plain text) */
class query_msg_send: public query
{
public:
    query_msg_send(const std::shared_ptr<tgl_message>& message,
            const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback)
        : query("send message", TYPE_TO_PARAM(updates))
        , m_message(message)
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        tl_ds_updates* DS_U = static_cast<tl_ds_updates*>(D);
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
        if (m_callback) {
            m_callback(true, m_message);
        }
        tgl_state::instance()->callback()->message_sent(m_message, DS_LVAL(DS_U->id), -1);
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " <<  error_code << " " << error_string);
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
        if (m_callback) {
            m_callback(false, m_message);
        }

        // FIXME: is this correct? Maybe when we implement message deletion disabled above.
        tgl_state::instance()->callback()->message_deleted(m_message->permanent_id.id);
        return 0;
    }
private:
    std::shared_ptr<tgl_message> m_message;
    std::function<void(bool, const std::shared_ptr<tgl_message>&)> m_callback;
};

void tgl_do_send_msg(const std::shared_ptr<tgl_message>& M, std::function<void(bool, const std::shared_ptr<tgl_message>& M)> callback) {
#ifdef ENABLE_SECRET_CHAT
    if (tgl_get_peer_type (M->to_id) == TGL_PEER_ENCR_CHAT) {
        tgl_do_send_encr_msg(M, callback);
        return;
    }
#endif
  clear_packet ();
  out_int (CODE_messages_send_message);

  unsigned f = ((M->flags & TGLMF_DISABLE_PREVIEW) ? 2 : 0) | (M->reply_id ? 1 : 0) | (M->reply_markup ? 4 : 0) | (M->entities.size() > 0 ? 8 : 0);
  if (tgl_get_peer_type (M->from_id) == TGL_PEER_CHANNEL) {
    f |= 16;
  }
  out_int (f);
  out_peer_id (M->to_id);
  if (M->reply_id) {
    out_int (M->reply_id);
  }
  out_cstring (M->message.c_str(), M->message.size());
  out_long (M->permanent_id.id);

  //TODO
  //long long *x = (long long *)malloc (12);
  //*x = M->id;
  //*(int*)(x+1) = M->to_id.id;

  if (M->reply_markup) {
    if (!M->reply_markup->button_matrix.empty()) {
      out_int (CODE_reply_keyboard_markup);
      out_int (M->reply_markup->flags);
      out_int (CODE_vector);
      out_int (M->reply_markup->button_matrix.size());
      for (size_t i = 0; i < M->reply_markup->button_matrix.size(); ++i) {
        out_int (CODE_keyboard_button_row);
        out_int (CODE_vector);
        out_int (M->reply_markup->button_matrix[i].size());
        for (size_t j = 0; j < M->reply_markup->button_matrix[i].size(); ++j) {
          out_int (CODE_keyboard_button);
          out_string (M->reply_markup->button_matrix[i][j].c_str());
        }
      }
    } else {
      out_int (CODE_reply_keyboard_hide);
    }
  }

  if (M->entities.size() > 0) {
    out_int (CODE_vector);
    out_int (M->entities.size());
    for (size_t i = 0; i < M->entities.size(); i++) {
      auto entity = M->entities[i];
      switch (entity->type) {
      case tgl_message_entity_bold:
        out_int (CODE_message_entity_bold);
        out_int (entity->start);
        out_int (entity->length);
        break;
      case tgl_message_entity_italic:
        out_int (CODE_message_entity_italic);
        out_int (entity->start);
        out_int (entity->length);
        break;
      case tgl_message_entity_code:
        out_int (CODE_message_entity_code);
        out_int (entity->start);
        out_int (entity->length);
        break;
      case tgl_message_entity_text_url:
        out_int (CODE_message_entity_text_url);
        out_int (entity->start);
        out_int (entity->length);
        out_string (entity->text_url.c_str());
        break;
      default:
        assert (0);
      }
    }
  }

  auto q = std::make_shared<query_msg_send>(M, callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}

void tgl_do_send_message (tgl_peer_id_t peer_id, const char *text, int text_len, unsigned long long flags, struct tl_ds_reply_markup *reply_markup, std::function<void(bool success, const std::shared_ptr<tgl_message>& M)> callback)
{
  if (tgl_get_peer_type (peer_id) == TGL_PEER_ENCR_CHAT) {
#ifdef ENABLE_SECRET_CHAT
    std::shared_ptr<tgl_secret_chat> secret_chat = tgl_state::instance()->secret_chat_for_id(peer_id);
    if (!secret_chat) {
      tgl_set_query_error (EINVAL, "unknown secret chat");
      if (callback) {
        callback(0, 0);
      }
      return;
    }
    if (secret_chat->state != sc_ok) {
      tgl_set_query_error (EINVAL, "secret chat not in ok state");
      if (callback) {
        callback(0, 0);
      }
      return;
    }
#endif
  }

  int date = time (0);

  struct tgl_message_id id = tgl_peer_id_to_random_msg_id (peer_id);

  std::shared_ptr<tgl_message> M;

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
          callback(0, 0);
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

  tgl_do_send_msg(M, callback);
}

void tgl_do_reply_message (tgl_message_id_t *_reply_id, const char *text, int text_len, unsigned long long flags, std::function<void(bool success, const std::shared_ptr<tgl_message>& M)> callback)
{
  tgl_message_id_t reply_id = *_reply_id;
  if (reply_id.peer_type == TGL_PEER_TEMP_ID) {
    reply_id = tgl_convert_temp_msg_id (reply_id);
  }
  if (reply_id.peer_type == TGL_PEER_TEMP_ID) {
    tgl_set_query_error (EINVAL, "unknown message");
    if (callback) {
      callback(0, 0);
    }
    return;
  }
  if (reply_id.peer_type == TGL_PEER_ENCR_CHAT) {
    tgl_set_query_error (EINVAL, "can not reply on message from secret chat");
    if (callback) {
      callback(0, 0);
    }

    tgl_peer_id_t peer_id = tgl_msg_id_to_peer_id (reply_id);

    tgl_do_send_message (peer_id, text, text_len, flags | TGL_SEND_MSG_FLAG_REPLY (reply_id.id), NULL, callback);
  }
}
/* }}} */

/* {{{ Send text file */
void tgl_do_send_text (tgl_peer_id_t id, const char *file_name, unsigned long long flags, std::function<void(bool success, const std::shared_ptr<tgl_message>& M)> callback)
{
  int fd = open (file_name, O_RDONLY | O_BINARY);
  if (fd < 0) {
    tgl_set_query_error (EBADF, "Can not open file: %s", strerror(errno));
    if (callback) {
      callback(0, NULL);
    }
    return;
  }
  static char buf[(1 << 20) + 1];
  int x = read (fd, buf, (1 << 20) + 1);
  if (x < 0) {
    tgl_set_query_error (EBADF, "Can not read from file: %s", strerror(errno));
    close (fd);
    if (callback) {
      callback(0, NULL);
    }

    assert (x >= 0);
    close (fd);
    if (x == (1 << 20) + 1) {
        tgl_set_query_error (E2BIG, "text file is too big");
        if (callback) {
            callback(0, NULL);
        }
    } else {
        tgl_do_send_message (id, buf, x, flags, NULL, callback);
    }
  }
}

void tgl_do_reply_text (tgl_message_id_t *_reply_id, const char *file_name, unsigned long long flags, std::function<void(bool success, const std::shared_ptr<tgl_message>& M)> callback)
{
  tgl_message_id_t reply_id = *_reply_id;
  if (reply_id.peer_type == TGL_PEER_TEMP_ID) {
    reply_id = tgl_convert_temp_msg_id (reply_id);
  }
  if (reply_id.peer_type == TGL_PEER_TEMP_ID) {
    tgl_set_query_error (EINVAL, "unknown message");
    if (callback) {
      callback(0, 0);
    }
    return;
  }
  if (reply_id.peer_type == TGL_PEER_ENCR_CHAT) {
    tgl_set_query_error (EINVAL, "can not reply on message from secret chat");
    if (callback) {
      callback(0, 0);
    }

    tgl_peer_id_t peer_id = tgl_msg_id_to_peer_id (reply_id);

    tgl_do_send_text (peer_id, file_name, flags | TGL_SEND_MSG_FLAG_REPLY (reply_id.id), callback);
  }
}
/* }}} */

/* {{{ Mark read */
class query_mark_read: public query
{
public:
    query_mark_read(const tgl_peer_id_t& id, int max_id,
            const std::function<void(bool)>& callback)
        : query("mark read", TYPE_TO_PARAM(messages_affected_history))
        , m_id(id)
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        tl_ds_messages_affected_messages* DS_MAM = static_cast<tl_ds_messages_affected_messages*>(D);

        int r = tgl_check_pts_diff(DS_LVAL(DS_MAM->pts), DS_LVAL(DS_MAM->pts_count));

        if (r > 0) {
            tgl_state::instance()->set_pts(DS_LVAL(DS_MAM->pts));
        }

#if 0
        if (tgl_get_peer_type (E->id) == TGL_PEER_USER) {
          bl_do_user (TLS, tgl_get_peer_id (E->id), NULL, NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, &E->max_id, NULL, NULL, TGL_FLAGS_UNCHANGED);
        } else {
          assert (tgl_get_peer_type (E->id) == TGL_PEER_CHAT);
          bl_do_chat (TLS, tgl_get_peer_id (E->id), NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &E->max_id, NULL, TGL_FLAGS_UNCHANGED);
        }
#endif
        if (m_callback) {
            m_callback(true);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false);
        }
        return 0;
    }

private:
    tgl_peer_id_t m_id;
    std::function<void(bool)> m_callback;
};

void tgl_do_messages_mark_read(const tgl_peer_id_t& id, int max_id, int offset, const std::function<void(bool)>& callback) {
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

    auto q = std::make_shared<query_mark_read>(id, max_id, callback);
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    q->execute(tgl_state::instance()->DC_working);
  } else {
    out_int (CODE_channels_read_history);

    out_int (CODE_input_channel);
    out_int (tgl_get_peer_id (id));
    out_long (id.access_hash);

    out_int (max_id);

    auto q = std::make_shared<query_mark_read>(id, max_id, callback);
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    q->execute(tgl_state::instance()->DC_working);
  }
}

void tgl_do_mark_read (tgl_peer_id_t id, std::function<void(bool success)> callback) {
  if (tgl_get_peer_type (id) == TGL_PEER_USER || tgl_get_peer_type (id) == TGL_PEER_CHAT || tgl_get_peer_type (id) == TGL_PEER_CHANNEL) {
    tgl_do_messages_mark_read (id, 0, 0, callback);
    return;
  }
#ifdef ENABLE_SECRET_CHAT
  assert (tgl_get_peer_type (id) == TGL_PEER_ENCR_CHAT);
  std::shared_ptr<tgl_secret_chat> secret_chat = tgl_state::instance()->secret_chat_for_id(id);
  if (!secret_chat) {
    tgl_set_query_error (EINVAL, "unknown secret chat");
    if (callback) {
      callback(false);
    }
    return;
  }
  tgl_do_messages_mark_read_encr(secret_chat, callback);
#endif
}
/* }}} */

/* {{{ Get history */
static void _tgl_do_get_history(const tgl_peer_id_t& id, int limit, int offset, int max_id,
        const std::function<void(bool success, const std::vector<std::shared_ptr<tgl_message>>& list)>& callback);

class query_get_history: public query
{
public:
    query_get_history(const tgl_peer_id_t& id, int limit, int offset, int max_id,
            const std::function<void(bool, const std::vector<std::shared_ptr<tgl_message>>&)>& callback)
        : query("get history", TYPE_TO_PARAM(messages_messages))
        , m_id(id)
        , m_limit(limit)
        , m_offset(offset)
        , m_max_id(max_id)
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        tl_ds_messages_messages* DS_MM = static_cast<tl_ds_messages_messages*>(D);
        for (int i = 0; i < DS_LVAL(DS_MM->chats->cnt); i++) {
            tglf_fetch_alloc_chat(DS_MM->chats->data[i]);
        }

        for (int i = 0; i < DS_LVAL(DS_MM->users->cnt); i++) {
            tglf_fetch_alloc_user(DS_MM->users->data[i]);
        }

        int n = DS_LVAL(DS_MM->messages->cnt);
        for (int i = 0; i < n; i++) {
            m_messages.push_back(tglf_fetch_alloc_message(DS_MM->messages->data[i], NULL));
        }
        m_offset += n;
        m_limit -= n;

        int count = DS_LVAL(DS_MM->count);
        if (count >= 0 && m_limit + m_offset >= count) {
            m_limit = count - m_offset;
            if (m_limit < 0) {
                m_limit = 0;
            }
        }
        assert (m_limit >= 0);

        if (m_limit <= 0 || DS_MM->magic == CODE_messages_messages || DS_MM->magic == CODE_messages_channel_messages) {
            if (m_callback) {
                m_callback(true, m_messages);
            }
            /*if (m_messages.size() > 0) {
              tgl_do_messages_mark_read (m_id, m_messages[0]->id, 0, 0, 0);
            }*/
        } else {
            m_offset = 0;
            m_max_id = m_messages[m_messages.size()-1]->permanent_id.id;
            _tgl_do_get_history (m_id, m_limit, m_offset, m_max_id,
                    m_callback);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false, std::vector<std::shared_ptr<tgl_message>>());
        }
        return 0;
    }
private:
    std::vector<std::shared_ptr<tgl_message>> m_messages;
    tgl_peer_id_t m_id;
    int m_limit;
    int m_offset;
    int m_max_id;
    std::function<void(bool, const std::vector<std::shared_ptr<tgl_message>>&)> m_callback;
};

static void _tgl_do_get_history(const tgl_peer_id_t& id, int limit, int offset, int max_id,
        const std::function<void(bool, const std::vector<std::shared_ptr<tgl_message>>& list)>& callback) {
  clear_packet ();
  //tgl_peer_t *C = tgl_peer_get (id);
  if (tgl_get_peer_type (id) != TGL_PEER_CHANNEL) {// || (C && (C->flags & TGLCHF_MEGAGROUP))) {
    out_int (CODE_messages_get_history);
    out_peer_id (id);
  } else {
    out_int (CODE_channels_get_important_history);

    out_int (CODE_input_channel);
    out_int (tgl_get_peer_id (id));
    out_long (id.access_hash);
  }
  out_int (max_id);
  out_int (offset);
  out_int (limit);
  out_int (0);
  out_int (0);

  auto q = std::make_shared<query_get_history>(id, limit, offset, max_id, callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}

void tgl_do_get_history (tgl_peer_id_t id, int offset, int limit, int offline_mode,
    std::function<void(bool success, const std::vector<std::shared_ptr<tgl_message>>& list)> callback) {
  if (tgl_get_peer_type (id) == TGL_PEER_ENCR_CHAT || offline_mode) {
#ifdef ENABLE_SECRET_CHAT
    // FIXME
    //tgl_do_get_local_history (id, offset, limit, callback, callback_extra);
    //tgl_do_mark_read (id, 0, 0);
#endif
    return;
  }
  _tgl_do_get_history(id, limit, offset, -1, callback);
}
/* }}} */

/* {{{ Get dialogs */
struct get_dialogs_state {
    std::vector<tgl_peer_id_t> peers;
    std::vector<tgl_message_id_t> last_message_ids;
    std::vector<int> unread_count;
    std::vector<int> read_box_max_id;
    tgl_peer_id_t offset_peer;
    int limit = 0;
    int offset = 0;
    int offset_date;
    int max_id = 0;
    int channels = 0;
};

static void _tgl_do_get_dialog_list(const std::shared_ptr<get_dialogs_state>& state,
        const std::function<void(bool, const std::vector<tgl_peer_id_t>&, const std::vector<tgl_message_id_t>&, const std::vector<int>&)>& callback);

class query_get_dialogs: public query
{
public:
    query_get_dialogs(const std::shared_ptr<get_dialogs_state>& state,
            const std::function<void(bool, const std::vector<tgl_peer_id_t>&, const std::vector<tgl_message_id_t>&, const std::vector<int>&)>& callback)
        : query("get dialogs", TYPE_TO_PARAM(messages_dialogs))
        , m_state(state)
        , m_callback(callback)
    { }

    virtual void on_answer(void *D) override
    {
        tl_ds_messages_dialogs* DS_MD = static_cast<tl_ds_messages_dialogs*>(D);
        int dl_size = DS_LVAL (DS_MD->dialogs->cnt);

        for (int i = 0; i < DS_LVAL (DS_MD->chats->cnt); i++) {
            tglf_fetch_alloc_chat (DS_MD->chats->data[i]);
        }

        for (int i = 0; i < DS_LVAL (DS_MD->users->cnt); i++) {
            tglf_fetch_alloc_user (DS_MD->users->data[i]);
        }

        for (int i = 0; i < dl_size; i++) {
            struct tl_ds_dialog *DS_D = DS_MD->dialogs->data[i];
            tgl_peer_id_t peer_id = tglf_fetch_peer_id(DS_D->peer);
            m_state->peers.push_back(peer_id);
            m_state->last_message_ids.push_back(tgl_peer_id_to_msg_id(peer_id, DS_LVAL(DS_D->top_message)));
            m_state->unread_count.push_back(DS_LVAL(DS_D->unread_count));
            m_state->read_box_max_id.push_back(DS_LVAL(DS_D->read_inbox_max_id));
        }

        for (int i = 0; i < DS_LVAL (DS_MD->messages->cnt); i++) {
            tglf_fetch_alloc_message (DS_MD->messages->data[i], NULL);
        }

        TGL_DEBUG("dl_size = " << dl_size << ", total = " << m_state->peers.size());

        if (dl_size && static_cast<int>(m_state->peers.size()) < m_state->limit
                && DS_MD->magic == CODE_messages_dialogs_slice
                && static_cast<int>(m_state->peers.size()) < DS_LVAL(DS_MD->count)) {
            if (m_state->peers.size() > 0) {
                m_state->offset_peer = m_state->peers[m_state->peers.size() - 1];
#if 0
                int p = static_cast<int>(m_state->size()) - 1;
                while (p >= 0) {
                    struct tgl_message *M = tgl_message_get (m_state->last_message_ids[p]);
                    if (M) {
                        m_state->offset_date = M->date;
                        break;
                    }
                    p --;
                }
#endif
            }
            _tgl_do_get_dialog_list(m_state, m_callback);
        } else {
            if (m_callback) {
                m_callback(true, m_state->peers, m_state->last_message_ids, m_state->unread_count);
            }
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_code);
        if (m_callback) {
            m_callback(0, std::vector<tgl_peer_id_t>(), std::vector<tgl_message_id_t>(), std::vector<int>());
        }
        return 0;
    }

private:
    std::shared_ptr<get_dialogs_state> m_state;
    std::function<void(bool, const std::vector<tgl_peer_id_t>&,
            const std::vector<tgl_message_id_t>&, const std::vector<int>&)> m_callback;
};

static void _tgl_do_get_dialog_list(const std::shared_ptr<get_dialogs_state>& state,
        const std::function<void(bool, const std::vector<tgl_peer_id_t>&, const std::vector<tgl_message_id_t>&, const std::vector<int>&)>& callback) {
  clear_packet ();
  if (state->channels) {
    out_int (CODE_channels_get_dialogs);
    out_int (state->offset);
    out_int (state->limit - state->peers.size());
  } else {
    out_int (CODE_messages_get_dialogs);
    out_int (state->offset_date);
    out_int (state->offset);
    //out_int (0);
    if (state->offset_peer.peer_type) {
      out_peer_id (state->offset_peer);
    } else {
      out_int (CODE_input_peer_empty);
    }
    out_int (state->limit - state->peers.size());
  }

  auto q = std::make_shared<query_get_dialogs>(state, callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}

void tgl_do_get_dialog_list(int limit, int offset,
        const std::function<void(bool success,
                const std::vector<tgl_peer_id_t>& peers,
                const std::vector<tgl_message_id_t>& last_msg_ids,
                const std::vector<int>& unread_count)>& callback) {
  std::shared_ptr<get_dialogs_state> state = std::make_shared<get_dialogs_state>();
  state->limit = limit;
  state->offset = offset;
  state->channels = 0;
  _tgl_do_get_dialog_list(state, callback);
}

void tgl_do_get_channels_dialog_list(int limit, int offset,
        const std::function<void(bool success,
                const std::vector<tgl_peer_id_t>& peers,
                const std::vector<tgl_message_id_t>& last_msg_ids,
                const std::vector<int>& unread_count)>& callback) {
  std::shared_ptr<get_dialogs_state> state = std::make_shared<get_dialogs_state>();
  state->limit = limit;
  state->offset = offset;
  state->channels = 1;
  state->offset_date = 0;
  state->offset_peer.peer_type = 0;
  _tgl_do_get_dialog_list(state, callback);
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
class query_set_profile_name: public query
{
public:
    explicit query_set_profile_name(const std::function<void(bool)>& callback)
        : query("set profile name", TYPE_TO_PARAM(user))
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        tglf_fetch_alloc_user(static_cast<tl_ds_user*>(D));
        if (m_callback) {
            m_callback(true);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_code);
        if (m_callback) {
            m_callback(false);
        }
        return 0;
    }

private:
    std::function<void(bool)> m_callback;
};

void tgl_do_set_profile_name (const std::string& first_name, const std::string& last_name, std::function<void(bool)> callback) {
    clear_packet ();
    out_int (CODE_account_update_profile);
    out_cstring (first_name.c_str(), last_name.length());
    out_cstring (last_name.c_str(), last_name.length());

    auto q = std::make_shared<query_set_profile_name>(callback);
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    q->execute(tgl_state::instance()->DC_working);
}

void tgl_do_set_username (const std::string& username, std::function<void(bool success)> callback) {
    clear_packet ();
    out_int (CODE_account_update_username);
    out_cstring (username.c_str(), username.length());

    auto q = std::make_shared<query_set_profile_name>(callback);
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    q->execute(tgl_state::instance()->DC_working);
}
/* }}} */

/* {{{ Contacts search */
class query_contact_search: public query
{
public:
    explicit query_contact_search(const std::function<void(bool)>& callback)
        : query("contact search", TYPE_TO_PARAM(contacts_resolved_peer))
        , m_callback(callback)
    { }

    virtual void on_answer(void *D) override
    {
        tl_ds_contacts_resolved_peer* DS_CRU = static_cast<tl_ds_contacts_resolved_peer*>(D);
        //tgl_peer_id_t peer_id = tglf_fetch_peer_id (DS_CRU->peer);
        for (int i = 0; i < DS_LVAL(DS_CRU->users->cnt); i++) {
            tglf_fetch_alloc_user (DS_CRU->users->data[i]);
        }
        for (int i = 0; i < DS_LVAL(DS_CRU->chats->cnt); i++) {
            tglf_fetch_alloc_chat (DS_CRU->chats->data[i]);
        }
        //tgl_peer_t *P = tgl_peer_get (peer_id);
        if (m_callback) {
            m_callback(true);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_code);
        if (m_callback) {
            m_callback(false);
        }
        return 0;
    }

private:
    std::function<void(bool)> m_callback;
};

void tgl_do_contact_search (const char *name, int name_len, std::function<void(bool success)> callback) {
  clear_packet ();
  out_int (CODE_contacts_resolve_username);
  out_cstring (name, name_len);

  auto q = std::make_shared<query_contact_search>(callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}
/* }}} */

/* {{{ Forward */
query_send_msgs::query_send_msgs(const std::shared_ptr<messages_send_extra>& extra,
        const std::function<void(bool, const std::shared_ptr<tgl_message>&)> single_callback)
    : query("send messages (single)", TYPE_TO_PARAM(updates))
    , m_extra(extra)
    , m_single_callback(single_callback)
    , m_multi_callback(nullptr)
    , m_bool_callback(nullptr)
{
    assert(m_extra);
    assert(!m_extra->multi);
}

query_send_msgs::query_send_msgs(const std::shared_ptr<messages_send_extra>& extra,
        const std::function<void(bool success, const std::vector<std::shared_ptr<tgl_message>>& messages)>& multi_callback)
    : query("send messages (multi)", TYPE_TO_PARAM(updates))
    , m_extra(extra)
    , m_single_callback(nullptr)
    , m_multi_callback(multi_callback)
    , m_bool_callback(nullptr)
{
    assert(m_extra);
    assert(m_extra->multi);
}

query_send_msgs::query_send_msgs(const std::function<void(bool)>& bool_callback)
    : query("send messages (bool callback)", TYPE_TO_PARAM(updates))
    , m_extra(nullptr)
    , m_single_callback(nullptr)
    , m_multi_callback(nullptr)
    , m_bool_callback(bool_callback)
{ }

void query_send_msgs::on_answer(void *D)
{
    tglu_work_any_updates(1, static_cast<tl_ds_updates*>(D), NULL);
    tglu_work_any_updates(0, static_cast<tl_ds_updates*>(D), NULL);

    if (!m_extra) {
        if (m_bool_callback) {
            m_bool_callback(true);
        }
    } else if (m_extra->multi) {
        std::vector<std::shared_ptr<tgl_message>> messages;
#if 0 // FIXME
        int count = E->count;
        int i;
        for (i = 0; i < count; i++) {
            int y = tgls_get_local_by_random (E->message_ids[i]);
            ML[i] = tgl_message_get (y);
        }
#endif
        if (m_multi_callback) {
            m_multi_callback(true, messages);
        }
    } else {
#if 0 // FIXME
        int y = tgls_get_local_by_random (E->id);
        struct tgl_message *M = tgl_message_get (y);
#endif
        std::shared_ptr<tgl_message> M;
        if (m_single_callback) {
            m_single_callback(true, M);
        }
    }
}

int query_send_msgs::on_error(int error_code, const std::string& error_string)
{
    TGL_ERROR("RPC_CALL_FAIL " <<  error_code << " " << error_string);

    if (!m_extra) {
        if (m_bool_callback) {
            m_bool_callback(false);
        }
    } else if (m_extra->multi) {
        if (m_multi_callback) {
            m_multi_callback(false, std::vector<std::shared_ptr<tgl_message>>());
        }
    } else {
        if (m_single_callback) {
            m_single_callback(false, nullptr);
        }
    }
    return 0;
}

void tgl_do_forward_messages(const tgl_peer_id_t& id, const std::vector<tgl_message_id_t>& ids_in, unsigned long long flags,
        const std::function<void(bool success, const std::vector<std::shared_ptr<tgl_message>>& messages)>& callback)
{
  if (tgl_get_peer_type (id) == TGL_PEER_ENCR_CHAT) {
    TGL_ERROR("can not forward messages to secret chats");
    if (callback) {
      callback(false, std::vector<std::shared_ptr<tgl_message>>());
    }
    return;
  }
  tgl_peer_id_t from_id = TGL_MK_USER (0);
  std::vector<tgl_message_id_t> ids;
  for (size_t i = 0; i < ids_in.size(); ++i) {
    tgl_message_id_t msg_id = ids_in[i];
    if (msg_id.peer_type == TGL_PEER_TEMP_ID) {
      msg_id = tgl_convert_temp_msg_id (msg_id);
    }
    if (msg_id.peer_type == TGL_PEER_TEMP_ID) {
      tgl_set_query_error (EINVAL, "unknown message");
      if (callback) {
        callback(false, std::vector<std::shared_ptr<tgl_message>>());
      }
      return;
    }

    if (msg_id.peer_type == TGL_PEER_ENCR_CHAT) {
      tgl_set_query_error (EINVAL, "can not forward message from secret chat");
      if (callback) {
        callback(false, std::vector<std::shared_ptr<tgl_message>>());
      }
      return;
    }

    ids.push_back(msg_id);

    if (i == 0) {
      from_id = tgl_msg_id_to_peer_id (msg_id);
    } else {
      if (tgl_cmp_peer_id (from_id, tgl_msg_id_to_peer_id (msg_id))) {
        tgl_set_query_error (EINVAL, "can not forward messages from different dialogs");
        if (callback) {
          callback(false, std::vector<std::shared_ptr<tgl_message>>());
        }
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
  out_int (ids_in.size());
  for (size_t i = 0; i < ids.size(); i++) {
    out_int (ids[i].id);
  }

  std::shared_ptr<messages_send_extra> E = std::make_shared<messages_send_extra>();
  E->multi = true;
  E->count = ids.size();
  out_int (CODE_vector);
  out_int (ids.size());
  for (size_t i = 0; i < ids.size(); i++) {
    E->message_ids.push_back(tgl_peer_id_to_random_msg_id(id));
    assert(E->message_ids[i].id);
    out_long (E->message_ids[i].id);
  }

  out_peer_id (id);

  auto q = std::make_shared<query_send_msgs>(E, callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}

void tgl_do_forward_message (tgl_peer_id_t peer_id, tgl_message_id_t *_msg_id, unsigned long long flags, std::function<void(bool success, const std::shared_ptr<tgl_message>& M)> callback)
{
  tgl_message_id_t msg_id = *_msg_id;
  if (msg_id.peer_type == TGL_PEER_TEMP_ID) {
    msg_id = tgl_convert_temp_msg_id (msg_id);
  }
  if (msg_id.peer_type == TGL_PEER_TEMP_ID) {
    tgl_set_query_error (EINVAL, "unknown message");
    if (callback) {
      callback(0, 0);
    }
    return;
  }
  if (msg_id.peer_type == TGL_PEER_ENCR_CHAT) {
    tgl_set_query_error (EINVAL, "can not forward messages from secret chat");
    if (callback) {
      callback(0, 0);
    }
    return;
  }
  if (peer_id.peer_type == TGL_PEER_ENCR_CHAT) {
    TGL_ERROR("can not forward messages to secret chats");
    if (callback) {
      callback(0, 0);
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

  auto q = std::make_shared<query_send_msgs>(E, callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}

void tgl_do_send_contact (tgl_peer_id_t id, const char *phone, int phone_len,
    const char *first_name, int first_name_len, const char *last_name, int last_name_len,
    unsigned long long flags, std::function<void(bool success, const std::shared_ptr<tgl_message>& M)> callback)
{
  if (tgl_get_peer_type (id) == TGL_PEER_ENCR_CHAT) {
    TGL_ERROR("can not send contact to secret chat");
    if (callback) {
      callback(0, 0);
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

  auto q = std::make_shared<query_send_msgs>(E, callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}

void tgl_do_reply_contact (tgl_message_id_t *_reply_id, const char *phone, int phone_len, const char *first_name, int first_name_len, const char *last_name,
        int last_name_len, unsigned long long flags, std::function<void(bool success, const std::shared_ptr<tgl_message>& M)> callback)
{
  tgl_message_id_t reply_id = *_reply_id;
  if (reply_id.peer_type == TGL_PEER_TEMP_ID) {
    reply_id = tgl_convert_temp_msg_id (reply_id);
  }
  if (reply_id.peer_type == TGL_PEER_TEMP_ID) {
    tgl_set_query_error (EINVAL, "unknown message");
    if (callback) {
      callback(0, 0);
    }
    return;
  }
  if (reply_id.peer_type == TGL_PEER_ENCR_CHAT) {
    tgl_set_query_error (EINVAL, "can not reply on message from secret chat");
    if (callback) {
      callback(0, 0);
    }

    tgl_peer_id_t peer_id = tgl_msg_id_to_peer_id (reply_id);

    tgl_do_send_contact (peer_id, phone, phone_len, first_name, first_name_len, last_name, last_name_len, flags | TGL_SEND_MSG_FLAG_REPLY (reply_id.id), callback);
  }
}

void tgl_do_forward_media (tgl_peer_id_t peer_id, tgl_message_id_t *_msg_id, unsigned long long flags, std::function<void(bool success, const std::shared_ptr<tgl_message>& M)> callback)
{
  if (tgl_get_peer_type (peer_id) == TGL_PEER_ENCR_CHAT) {
    tgl_set_query_error (EINVAL, "can not forward messages to secret chats");
    if (callback) {
      callback(0, 0);
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
      callback(0, 0);
    }
    return;
  }
  if (msg_id.peer_type == TGL_PEER_ENCR_CHAT) {
    tgl_set_query_error (EINVAL, "can not forward message from secret chat");
    if (callback) {
      callback(0, 0);
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
      callback(0, 0);
    }
    return;
  }
  if (M->media.type != tgl_message_media_photo && M->media.type != tgl_message_media_document && M->media.type != tgl_message_media_audio && M->media.type != tgl_message_media_video) {
    tgl_set_query_error (EINVAL, "can only forward photo/document");
    if (callback) {
      callback(0, 0);
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

  auto q = std::make_shared<query_send_msgs>(E, callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}
/* }}} */

/* {{{ Send location */

void tgl_do_send_location (tgl_peer_id_t peer_id, double latitude, double longitude, unsigned long long flags, std::function<void(bool success, const std::shared_ptr<tgl_message>& M)> callback)
{
  if (tgl_get_peer_type (peer_id) == TGL_PEER_ENCR_CHAT) {
#ifdef ENABLE_SECRET_CHAT
    tgl_do_send_location_encr (peer_id, latitude, longitude, flags, callback);
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

    auto q = std::make_shared<query_send_msgs>(E, callback);
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    q->execute(tgl_state::instance()->DC_working);
  }
}

#if 0
void tgl_do_reply_location (tgl_message_id_t *_reply_id, double latitude, double longitude, unsigned long long flags, std::function<void(bool success, struct tgl_message *M)> callback) {
  tgl_message_id_t reply_id = *_reply_id;
  if (reply_id.peer_type == TGL_PEER_TEMP_ID) {
    reply_id = tgl_convert_temp_msg_id (reply_id);
  }
  if (reply_id.peer_type == TGL_PEER_TEMP_ID) {
    tgl_set_query_error (EINVAL, "unknown message");
    if (callback) {
      callback(0, 0);
    }
    return;
  }
  if (reply_id.peer_type == TGL_PEER_ENCR_CHAT) {
    tgl_set_query_error (EINVAL, "can not reply on message from secret chat");
    if (callback) {
      callback(0, 0);
    }

  tgl_peer_id_t peer_id = tgl_msg_id_to_peer_id (reply_id);

  tgl_do_send_location (peer_id, latitude, longitude, flags | TGL_SEND_MSG_FLAG_REPLY (reply_id.id), callback, callback_extra);
}
#endif
/* }}} */

/* {{{ Rename chat */

void tgl_do_rename_chat (tgl_peer_id_t id, const char *name, int name_len, std::function<void(bool success)> callback) {
    clear_packet ();
    out_int (CODE_messages_edit_chat_title);
    assert (tgl_get_peer_type (id) == TGL_PEER_CHAT);
    out_int (tgl_get_peer_id (id));
    out_cstring (name, name_len);

    auto q = std::make_shared<query_send_msgs>(callback);
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    q->execute(tgl_state::instance()->DC_working);
}
/* }}} */

 /* {{{ Rename channel */

void tgl_do_rename_channel (tgl_peer_id_t id, const char *name, int name_len, std::function<void(bool success)> callback) {
  clear_packet ();
  out_int (CODE_channels_edit_title);
  assert (tgl_get_peer_type (id) == TGL_PEER_CHANNEL);
  out_int (CODE_input_channel);
  out_int (tgl_get_peer_id (id));
  out_long (id.access_hash);
  out_cstring (name, name_len);

  auto q = std::make_shared<query_send_msgs>(callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}
/* }}} */

 /* {{{ Join channel */

void tgl_do_join_channel (tgl_peer_id_t id, std::function<void(bool success)> callback) {
  clear_packet ();
  out_int (CODE_channels_join_channel);
  assert (tgl_get_peer_type (id) == TGL_PEER_CHANNEL);
  out_int (CODE_input_channel);
  out_int (tgl_get_peer_id (id));
  out_long (id.access_hash);

  auto q = std::make_shared<query_send_msgs>(callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}
/* }}} */

/* {{{ Leave channel */

void tgl_do_leave_channel (tgl_peer_id_t id, std::function<void(bool success)> callback) {
  clear_packet ();
  out_int (CODE_channels_leave_channel);
  assert (tgl_get_peer_type (id) == TGL_PEER_CHANNEL);
  out_int (CODE_input_channel);
  out_int (tgl_get_peer_id (id));
  out_long (id.access_hash);

  auto q = std::make_shared<query_send_msgs>(callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}
/* }}} */

/* {{{ channel change about */
class query_channels_set_about: public query
{
public:
    explicit query_channels_set_about(const std::function<void(bool)>& callback)
        : query("channels set about", TYPE_TO_PARAM(bool))
        , m_callback(callback)
    { }

    virtual void on_answer(void*) override
    {
        if (m_callback) {
            m_callback(true);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false);
        }
        return 0;
    }

private:
    std::function<void(bool)> m_callback;
};

void tgl_do_channel_set_about (tgl_peer_id_t id, const char *about, int about_len, std::function<void(bool success)> callback) {
  clear_packet ();
  out_int (CODE_channels_edit_about);
  assert (tgl_get_peer_type (id) == TGL_PEER_CHANNEL);
  out_int (CODE_input_channel);
  out_int (tgl_get_peer_id (id));
  out_long (id.access_hash);
  out_cstring (about, about_len);

  auto q = std::make_shared<query_channels_set_about>(callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}
/* }}} */

/* {{{ Channel set username */
void tgl_do_channel_set_username (tgl_peer_id_t id, const char *username, int username_len, std::function<void(bool success)> callback) {
  clear_packet ();
  out_int (CODE_channels_update_username);
  assert (tgl_get_peer_type (id) == TGL_PEER_CHANNEL);
  out_int (CODE_input_channel);
  out_int (tgl_get_peer_id (id));
  out_long (id.access_hash);
  out_cstring (username, username_len);

  auto q = std::make_shared<query_channels_set_about>(callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}
/* }}} */

/* {{{ Channel set admin */
void tgl_do_channel_set_admin (tgl_peer_id_t channel_id, tgl_peer_id_t user_id, int type, std::function<void(bool success)> callback) {
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

  auto q = std::make_shared<query_send_msgs>(callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}
/* }}} */

/* {{{ Channel members */
struct channel_get_members_state {
  tgl_peer_id_t channel_id;
  std::vector<tgl_peer_id_t> peers;
  int type = 0;
  int offset = 0;
  int limit = -1;
};

static void _tgl_do_channel_get_members(const std::shared_ptr<struct channel_get_members_state>& state,
        const std::function<void(bool, const std::vector<tgl_peer_id_t>&)>& callback);

class query_channels_get_members: public query
{
public:
    query_channels_get_members(const std::shared_ptr<channel_get_members_state>& state,
            const std::function<void(bool, const std::vector<tgl_peer_id_t>&)>& callback)
        : query("channels get members", TYPE_TO_PARAM(channels_channel_participants))
        , m_state(state)
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        tl_ds_channels_channel_participants* DS_CP = static_cast<tl_ds_channels_channel_participants*>(D);
        int count = DS_LVAL(DS_CP->participants->cnt);
        for (int i = 0; i < DS_LVAL(DS_CP->users->cnt); i++) {
            tglf_fetch_alloc_user(DS_CP->users->data[i]);
        }

        for (int i = 0; i < count; i++) {
            m_state->peers.push_back(TGL_MK_USER(DS_LVAL(DS_CP->participants->data[i]->user_id)));
        }
        m_state->offset += count;

        if (!count || static_cast<int>(m_state->peers.size()) == m_state->limit) {
            m_callback(true, m_state->peers);
        } else {
            _tgl_do_channel_get_members(m_state, m_callback);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false, std::vector<tgl_peer_id_t>());
        }
        return 0;
    }

private:
    std::shared_ptr<channel_get_members_state> m_state;
    std::function<void(bool, const std::vector<tgl_peer_id_t>&)> m_callback;
};

static void _tgl_do_channel_get_members(const std::shared_ptr<struct channel_get_members_state>& state,
        const std::function<void(bool, const std::vector<tgl_peer_id_t>&)>& callback) {
  clear_packet ();
  out_int (CODE_channels_get_participants);
  assert (tgl_get_peer_type (state->channel_id) == TGL_PEER_CHANNEL);
  out_int (CODE_input_channel);
  out_int (state->channel_id.peer_id);
  out_long (state->channel_id.access_hash);

  switch (state->type) {
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
  out_int (state->offset);
  out_int (state->limit);

  auto q = std::make_shared<query_channels_get_members>(state, callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}

void tgl_do_channel_get_members(const tgl_peer_id_t& channel_id, int limit, int offset, int type, const std::function<void(bool success, const std::vector<tgl_peer_id_t>& peers)>& callback) {
  std::shared_ptr<channel_get_members_state> state = std::make_shared<channel_get_members_state>();
  state->type = type;
  state->channel_id = channel_id;
  state->limit = limit;
  state->offset = offset;
  _tgl_do_channel_get_members(state, callback);
}
/* }}} */

/* {{{ Chat info */
class query_chat_info: public query
{
public:
    explicit query_chat_info(const std::function<void(bool, const std::shared_ptr<tgl_chat>&)>& callback)
        : query("chat info", TYPE_TO_PARAM(messages_chat_full))
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        std::shared_ptr<tgl_chat> chat = tglf_fetch_alloc_chat_full(static_cast<tl_ds_messages_chat_full*>(D));
        if (m_callback) {
            m_callback(true, chat);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false, nullptr);
        }
        return 0;
    }

private:
    std::function<void(bool, const std::shared_ptr<tgl_chat>&)> m_callback;
};

void tgl_do_get_chat_info (int id, int offline_mode, std::function<void(bool success, const std::shared_ptr<tgl_chat>& C)> callback) {
  if (offline_mode) {
#if 0
    tgl_peer_t *C = tgl_peer_get (id);
    if (!C) {
      tgl_set_query_error (EINVAL, "unknown chat id");
      if (callback) {
        callback(0, 0);
      }
    } else {
      if (callback) {
        callback(1, &C->chat);
      }
    }
#endif
    return;
  }
  clear_packet ();
  out_int (CODE_messages_get_full_chat);
  out_int (id);

  auto q = std::make_shared<query_chat_info>(callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}
/* }}} */

/* {{{ Channel info */
class query_channel_info: public query
{
public:
    explicit query_channel_info(const std::function<void(bool, const std::shared_ptr<tgl_channel>&)>& callback)
        : query("channel info", TYPE_TO_PARAM(messages_chat_full))
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        std::shared_ptr<tgl_channel> channel = tglf_fetch_alloc_channel_full(static_cast<tl_ds_messages_chat_full*>(D));
        if (m_callback) {
            m_callback(true, channel);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false, nullptr);
        }
        return 0;
    }

private:
    std::function<void(bool, const std::shared_ptr<tgl_channel>&)> m_callback;
};

void tgl_do_get_channel_info (tgl_peer_id_t id, int offline_mode, std::function<void(bool success, const std::shared_ptr<tgl_channel>& C)> callback) {
  if (offline_mode) {
#if 0
    tgl_peer_t *C = tgl_peer_get (id);
    if (!C) {
      tgl_set_query_error (EINVAL, "unknown chat id");
      if (callback) {
        callback(0, 0);
      }
    } else {
      if (callback) {
        callback(1, &C->channel);
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

  auto q = std::make_shared<query_channel_info>(callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}
/* }}} */

/* {{{ User info */
class query_user_info: public query
{
public:
    explicit query_user_info(const std::function<void(bool, const std::shared_ptr<tgl_user>&)>& callback)
        : query("user info", TYPE_TO_PARAM(user_full))
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        std::shared_ptr<tgl_user> user = tglf_fetch_alloc_user_full(static_cast<tl_ds_user_full*>(D));
        if (m_callback) {
            m_callback(true, user);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false, nullptr);
        }
        return 0;
    }

private:
    std::function<void(bool, const std::shared_ptr<tgl_user>&)> m_callback;
};

void tgl_do_get_user_info(const tgl_peer_id_t& id, int offline_mode, const std::function<void(bool success, const std::shared_ptr<tgl_user>& user)>& callback) {
  if (tgl_get_peer_type (id) != TGL_PEER_USER) {
    tgl_set_query_error (EINVAL, "id should be user id");
    if (callback) {
      callback(false, nullptr);
    }
    return;
  }
  if (offline_mode) {
#if 0
    tgl_peer_t *C = tgl_peer_get (id);
    if (!C) {
      tgl_set_query_error (EINVAL, "unknown user id");
      if (callback) {
        callback(0, 0);
      }
    } else {
      if (callback) {
        callback(1, &C->user);
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

  auto q = std::make_shared<query_user_info>(callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}

static void resend_query_cb(const std::shared_ptr<query>& q, bool success) {
    assert (success);

    TGL_DEBUG2("resend_query_cb");
    tgl_state::instance()->set_dc_signed (tgl_state::instance()->DC_working->id);

    clear_packet ();
    out_int (CODE_users_get_full_user);
    out_int (CODE_input_user_self);

    auto user_info_q = std::make_shared<query_user_info>(nullptr);
    user_info_q->load_data(packet_buffer, packet_ptr - packet_buffer);
    user_info_q->execute(tgl_state::instance()->DC_working);

    if (auto dc = q->dc()) {
        dc->add_pending_query(q);
        dc->send_pending_queries();
    }
}
/* }}} */

/* {{{ Export auth */
class query_import_auth: public query
{
public:
    query_import_auth(const std::shared_ptr<tgl_dc>& dc,
            const std::function<void(bool)>& callback)
        : query("import authorization", TYPE_TO_PARAM(auth_authorization))
        , m_dc(dc)
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        tl_ds_auth_authorization* DS_U = static_cast<tl_ds_auth_authorization*>(D);
        tglf_fetch_alloc_user(DS_U->user);

        assert(m_dc);
        TGL_NOTICE("auth imported from DC " << tgl_state::instance()->DC_working->id << " to DC " << m_dc->id);

        tgl_state::instance()->set_dc_signed(m_dc->id);

        if (m_callback) {
            m_callback(true);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false);
        }
        return 0;
    }

private:
    std::shared_ptr<tgl_dc> m_dc;
    std::function<void(bool)> m_callback;
};

class query_export_auth: public query
{
public:
    query_export_auth(const std::shared_ptr<tgl_dc>& dc,
            const std::function<void(bool)>& callback)
        : query("export authorization", TYPE_TO_PARAM(auth_exported_authorization))
        , m_dc(dc)
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        TGL_NOTICE("export_auth_on_answer " << m_dc->id);
        tl_ds_auth_exported_authorization* DS_EA = static_cast<tl_ds_auth_exported_authorization*>(D);
        tgl_state::instance()->set_our_id(DS_LVAL(DS_EA->id));

        clear_packet ();
        tgl_do_insert_header ();
        out_int(CODE_auth_import_authorization);
        out_int(tgl_get_peer_id(tgl_state::instance()->our_id()));
        out_cstring(DS_STR(DS_EA->bytes));
    
        auto q = std::make_shared<query_import_auth>(m_dc, m_callback);
        q->load_data(packet_buffer, packet_ptr - packet_buffer);
        q->execute(m_dc, QUERY_LOGIN);
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false);
        }
        return 0;
    }

private:
    std::shared_ptr<tgl_dc> m_dc;
    std::function<void(bool)> m_callback;
};

// export auth from working DC and import to DC "num"
void tgl_do_transfer_auth (int num, std::function<void(bool success)> callback) {
    std::shared_ptr<tgl_dc> DC = tgl_state::instance()->DC_list[num];
    if (DC->auth_transfer_in_process) {
        return;
    }
    DC->auth_transfer_in_process = true;
    TGL_NOTICE("Transferring auth from DC " << tgl_state::instance()->DC_working->id << " to DC " << num);
    clear_packet ();
    out_int (CODE_auth_export_authorization);
    out_int (num);

    auto q = std::make_shared<query_export_auth>(DC, callback);
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    q->execute(tgl_state::instance()->DC_working);
}
/* }}} */

/* {{{ Add contact */
class query_add_contact: public query
{
public:
    explicit query_add_contact(const std::function<void(bool, const std::vector<int>&)>& callback)
        : query("add contact", TYPE_TO_PARAM(contacts_imported_contacts))
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        tl_ds_contacts_imported_contacts* DS_CIC = static_cast<tl_ds_contacts_imported_contacts*>(D);
        if (DS_LVAL(DS_CIC->imported->cnt) > 0) {
            TGL_DEBUG("Added successfully");
        } else {
            TGL_DEBUG("Not added");
        }
        int n = DS_LVAL(DS_CIC->users->cnt);
        std::vector<int> users(n);
        for (int i = 0; i < n; i++) {
            users[i] = tglf_fetch_alloc_user(DS_CIC->users->data[i])->id.peer_id;
        }
        if (m_callback) {
            m_callback(true, users);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false, std::vector<int>());
        }
        return 0;
    }

private:
    std::function<void(bool, const std::vector<int>&)> m_callback;
};

void tgl_do_add_contact (const std::string& phone, const std::string& first_name, const std::string& last_name, bool replace, std::function<void(bool success, const std::vector<int>& user_ids)> callback) {
    clear_packet ();
    out_int (CODE_contacts_import_contacts);
    out_int (CODE_vector);
    out_int (1); // TODO allow adding multiple contacts
    out_int (CODE_input_phone_contact);
    long long r;
    tglt_secure_random ((unsigned char*)&r, 8);
    out_long (r);
    out_cstring (phone.c_str(), phone.length());
    out_cstring (first_name.c_str(), first_name.length());
    out_cstring (last_name.c_str(), last_name.length());
    out_int (replace ? CODE_bool_true : CODE_bool_false);

    auto q = std::make_shared<query_add_contact>(callback);
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    q->execute(tgl_state::instance()->DC_working);
}
/* }}} */

/* {{{ Del contact */
class query_del_contact: public query
{
public:
    explicit query_del_contact(const std::function<void(bool)>& callback)
        : query("del contact", TYPE_TO_PARAM(contacts_link))
        , m_callback(callback)
    { }

    virtual void on_answer(void*) override
    {
        if (m_callback) {
            m_callback(true);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false);
        }
        return 0;
    }

private:
    std::function<void(bool)> m_callback;
};

void tgl_do_del_contact (tgl_peer_id_t id, std::function<void(bool success)> callback) {
    clear_packet ();
    out_int (CODE_contacts_delete_contact);

  out_int (CODE_input_user);
  out_int (tgl_get_peer_id (id));
  out_long (id.access_hash);

  auto q = std::make_shared<query_del_contact>(callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}
/* }}} */

/* {{{ Msg search */

struct msg_search_state {
    msg_search_state(tgl_peer_id_t id, int from, int to, int limit, int offset, const std::string &query) :
        id(id), from(from), to(to), limit(limit), offset(offset), query(query) {}
    std::vector<std::shared_ptr<tgl_message>> messages;
    tgl_peer_id_t id;
    int from;
    int to;
    int limit;
    int offset;
    int max_id = 0;
    std::string query;
};

static void _tgl_do_msg_search(const std::shared_ptr<msg_search_state>& state,
        const std::function<void(bool, const std::vector<std::shared_ptr<tgl_message>>&)>& callback);

class query_msg_search: public query
{
public:
    query_msg_search(const std::shared_ptr<msg_search_state>& state,
            const std::function<void(bool, const std::vector<std::shared_ptr<tgl_message>>&)>& callback)
        : query("messages search", TYPE_TO_PARAM(messages_messages))
        , m_state(state)
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        tl_ds_messages_messages* DS_MM = static_cast<tl_ds_messages_messages*>(D);
        for (int i = 0; i < DS_LVAL(DS_MM->chats->cnt); i++) {
            tglf_fetch_alloc_chat(DS_MM->chats->data[i]);
        }
        for (int i = 0; i < DS_LVAL(DS_MM->users->cnt); i++) {
            tglf_fetch_alloc_user (DS_MM->users->data[i]);
        }

        int n = DS_LVAL (DS_MM->messages->cnt);
        for (int i = 0; i < n; i++) {
            m_state->messages.push_back(tglf_fetch_alloc_message(DS_MM->messages->data[i], NULL));
        }
        m_state->offset += n;
        m_state->limit -= n;
        if (m_state->limit + m_state->offset >= DS_LVAL(DS_MM->count)) {
            m_state->limit = DS_LVAL(DS_MM->count) - m_state->offset;
            if (m_state->limit < 0) {
                m_state->limit = 0;
            }
        }
        assert (m_state->limit >= 0);

        if (m_state->limit <= 0 || DS_MM->magic == CODE_messages_messages) {
            if (m_callback) {
                m_callback(true, m_state->messages);
            }
        } else {
            m_state->max_id = m_state->messages[m_state->messages.size()-1]->permanent_id.id;
            m_state->offset = 0;
            _tgl_do_msg_search(m_state, m_callback);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " <<  error_code << " " << error_string);
        if (m_callback) {
            m_callback(0, std::vector<std::shared_ptr<tgl_message>>());
        }
        return 0;
    }

private:
    std::shared_ptr<msg_search_state> m_state;
    std::function<void(bool, const std::vector<std::shared_ptr<tgl_message>>&)> m_callback;
};

static void _tgl_do_msg_search(const std::shared_ptr<msg_search_state>& state,
        const std::function<void(bool, const std::vector<std::shared_ptr<tgl_message>>&)>& callback)
{
  clear_packet ();
  if (tgl_get_peer_type (state->id) == TGL_PEER_UNKNOWN) {
    out_int (CODE_messages_search_global);
    out_string (state->query.c_str());
    out_int (0);
    out_int (CODE_input_peer_empty);
    out_int (state->offset);
    out_int (state->limit);
  } else {
    out_int (CODE_messages_search);
    out_int (0);
    out_peer_id (state->id);

    out_string (state->query.c_str());
    out_int (CODE_input_messages_filter_empty);
    out_int (state->from);
    out_int (state->to);
    out_int (state->offset); // offset
    out_int (state->max_id); // max_id
    out_int (state->limit);
  }

  auto q = std::make_shared<query_msg_search>(state, callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}

//untested
void tgl_do_msg_search(const tgl_peer_id_t& id, int from, int to, int limit, int offset, const std::string &query,
        const std::function<void(bool success, const std::vector<std::shared_ptr<tgl_message>>& list)>& callback) {
    if (tgl_get_peer_type (id) == TGL_PEER_ENCR_CHAT) {
        TGL_ERROR("can not search in secret chats");
        if (callback) {
            callback(false, std::vector<std::shared_ptr<tgl_message>>());
        }
        return;
    }
    std::shared_ptr<msg_search_state> state = std::make_shared<msg_search_state>(id, from, to, limit, offset, query);
    _tgl_do_msg_search(state, callback);
}
/* }}} */

/* {{{ Get difference */
class query_get_state: public query
{
public:
    query_get_state(const std::function<void(bool)>& callback)
        : query("get state", TYPE_TO_PARAM(updates_state))
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        tl_ds_updates_state* DS_US = static_cast<tl_ds_updates_state*>(D);
        assert (tgl_state::instance()->locks & TGL_LOCK_DIFF);
        tgl_state::instance()->locks ^= TGL_LOCK_DIFF;
        tgl_state::instance()->set_pts(DS_LVAL (DS_US->pts));
        tgl_state::instance()->set_qts(DS_LVAL (DS_US->qts));
        tgl_state::instance()->set_date(DS_LVAL (DS_US->date));
        tgl_state::instance()->set_seq(DS_LVAL (DS_US->seq));
        if (m_callback) {
            m_callback(true);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false);
        }
        return 0;
    }

private:
    std::function<void(bool)> m_callback;
};

class query_lookup_state: public query
{
public:
    explicit query_lookup_state(const std::function<void(bool)>& callback)
        : query("lookup state", TYPE_TO_PARAM(updates_state))
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        tl_ds_updates_state* DS_US = static_cast<tl_ds_updates_state*>(D);
        int pts = DS_LVAL(DS_US->pts);
        int qts = DS_LVAL(DS_US->qts);
        int seq = DS_LVAL(DS_US->seq);
        if (pts > tgl_state::instance()->pts() || qts > tgl_state::instance()->qts() || seq > tgl_state::instance()->seq()) {
            tgl_do_get_difference (0, 0);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false);
        }
        return 0;
    }

private:
    std::function<void(bool)> m_callback;
};

class query_get_difference: public query
{
public:
    query_get_difference(const std::function<void(bool)>& callback)
        : query("get difference", TYPE_TO_PARAM(updates_difference))
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        TGL_DEBUG2("get difference answer");

        tl_ds_updates_difference* DS_UD = static_cast<tl_ds_updates_difference*>(D);

        assert (tgl_state::instance()->locks & TGL_LOCK_DIFF);
        tgl_state::instance()->locks ^= TGL_LOCK_DIFF;

        if (DS_UD->magic == CODE_updates_difference_empty) {
            tgl_state::instance()->set_date(DS_LVAL(DS_UD->date));
            tgl_state::instance()->set_seq(DS_LVAL(DS_UD->seq));

            TGL_DEBUG("Empty difference. Seq = " << tgl_state::instance()->seq());
            if (m_callback) {
                m_callback(true);
            }
        } else {
            for (int i = 0; i < DS_LVAL(DS_UD->users->cnt); i++) {
                tglf_fetch_alloc_user(DS_UD->users->data[i]);
            }
            for (int i = 0; i < DS_LVAL(DS_UD->chats->cnt); i++) {
                tglf_fetch_alloc_chat (DS_UD->chats->data[i]);
            }

            int message_count = DS_LVAL (DS_UD->new_messages->cnt);
            std::vector<std::shared_ptr<tgl_message>> messages;
            for (int i = 0; i < message_count; i++) {
                messages.push_back(tglf_fetch_alloc_message(DS_UD->new_messages->data[i], NULL));
            }

            int encrypted_message_count = DS_LVAL(DS_UD->new_encrypted_messages->cnt);
            std::vector<std::shared_ptr<tgl_message>> encrypted_messages;
            for (int i = 0; i < encrypted_message_count; i++) {
#ifdef ENABLE_SECRET_CHAT
                encrypted_messages.push_back(tglf_fetch_alloc_encrypted_message(DS_UD->new_encrypted_messages->data[i]));
#endif
            }

#if 0
            for (int i = 0; i < DS_LVAL(DS_UD->other_updates->cnt); i++) {
                tglu_work_update(1, DS_UD->other_updates->data[i]);
            }
#endif

            for (int i = 0; i < DS_LVAL(DS_UD->other_updates->cnt); i++) {
                tglu_work_update(-1, DS_UD->other_updates->data[i]);
            }
#if 0
            for (int i = 0; i < message_count; i++) {
                bl_do_msg_update (&messages[i]->permanent_id);
                tgl_state::instance()->callback()->new_message(messages[i]);
            }
#endif

            for (int i = 0; i < encrypted_message_count; i++) {
                // messages to secret chats that no longer exist are not initialized and NULL
                if (encrypted_messages[i]) {
                    tgl_state::instance()->callback()->new_message(encrypted_messages[i]);
                }
            }

            if (DS_UD->state) {
                tgl_state::instance()->set_pts(DS_LVAL (DS_UD->state->pts));
                tgl_state::instance()->set_qts(DS_LVAL (DS_UD->state->qts));
                tgl_state::instance()->set_date(DS_LVAL (DS_UD->state->date));
                tgl_state::instance()->set_seq(DS_LVAL (DS_UD->state->seq));
                if (m_callback) {
                    m_callback(true);
                }
            } else {
                tgl_state::instance()->set_pts(DS_LVAL (DS_UD->intermediate_state->pts));
                tgl_state::instance()->set_qts(DS_LVAL (DS_UD->intermediate_state->qts));
                tgl_state::instance()->set_date(DS_LVAL (DS_UD->intermediate_state->date));
                tgl_do_get_difference (0, m_callback);
            }
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false);
        }
        return 0;
    }

private:
    std::function<void(bool)> m_callback;
};

void tgl_do_lookup_state () {
    if (tgl_state::instance()->locks & TGL_LOCK_DIFF) {
        return;
    }
    clear_packet ();
    tgl_do_insert_header ();
    out_int (CODE_updates_get_state);

    auto q = std::make_shared<query_lookup_state>(nullptr);
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    q->execute(tgl_state::instance()->DC_working);
}

void tgl_do_get_difference(int sync_from_start, const std::function<void(bool success)>& callback) {
  //get_difference_active = 1;
  //difference_got = 0;
  if (tgl_state::instance()->locks & TGL_LOCK_DIFF) {
    if (callback) {
      callback(0);
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
    auto q = std::make_shared<query_get_difference>(callback);
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    q->execute(tgl_state::instance()->DC_working);
  } else {
    out_int (CODE_updates_get_state);
    auto q = std::make_shared<query_get_state>(callback);
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    q->execute(tgl_state::instance()->DC_working);
  }
}
/* }}} */

/* {{{ Get channel difference */
class query_get_channel_difference: public query
{
public:
    query_get_channel_difference(const std::shared_ptr<tgl_channel>& channel,
            const std::function<void(bool)>& callback)
        : query("get channel difference", TYPE_TO_PARAM(updates_channel_difference))
        , m_channel(channel)
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        tl_ds_updates_channel_difference* DS_UD = static_cast<tl_ds_updates_channel_difference*>(D);

        assert (m_channel->flags & TGLCHF_DIFF);
        m_channel->flags ^= TGLCHF_DIFF;

        if (DS_UD->magic == CODE_updates_channel_difference_empty) {
            //bl_do_set_channel_pts (tgl_get_peer_id (channel->id), DS_LVAL (DS_UD->channel_pts));
            TGL_DEBUG("Empty difference. Seq = " << tgl_state::instance()->seq());
            if (m_callback) {
                m_callback(true);
            }
        } else {
            for (int i = 0; i < DS_LVAL(DS_UD->users->cnt); i++) {
                tglf_fetch_alloc_user (DS_UD->users->data[i]);
            }

            for (int i = 0; i < DS_LVAL(DS_UD->chats->cnt); i++) {
                tglf_fetch_alloc_chat(DS_UD->chats->data[i]);
            }

            int message_count = DS_LVAL(DS_UD->new_messages->cnt);
            std::vector<std::shared_ptr<tgl_message>> messages;
            for (int i = 0; i < message_count; i++) {
                messages.push_back(tglf_fetch_alloc_message(DS_UD->new_messages->data[i], NULL));
            }

            for (int i = 0; i < DS_LVAL(DS_UD->other_updates->cnt); i++) {
                tglu_work_update(1, DS_UD->other_updates->data[i]);
            }

            for (int i = 0; i < DS_LVAL(DS_UD->other_updates->cnt); i++) {
                tglu_work_update(-1, DS_UD->other_updates->data[i]);
            }

#if 0
            for (int i = 0; i < ml_pos; i++) {
                bl_do_msg_update (&messages[i]->permanent_id);
            }
#endif

            //bl_do_set_channel_pts (tgl_get_peer_id(m_channel->id), DS_LVAL (DS_UD->channel_pts));
            if (DS_UD->magic != CODE_updates_channel_difference_too_long) {
                if (m_callback) {
                    m_callback(true);
                }
            } else {
                tgl_do_get_channel_difference(tgl_get_peer_id(m_channel->id), m_callback);
            }
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false);
        }
        return 0;
    }

private:
    std::shared_ptr<tgl_channel> m_channel;
    std::function<void(bool)> m_callback;
};

void tgl_do_get_channel_difference(int id, const std::function<void(bool success)>& callback) {
  //tgl_peer_t *E = tgl_peer_get (TGL_MK_CHANNEL (id));
  std::shared_ptr<struct tgl_channel> channel = std::make_shared<struct tgl_channel>();
  channel->id = TGL_MK_CHANNEL(id);

  if (!channel || !(channel->flags & TGLPF_CREATED) || !channel->pts) {
    if (callback) {
      callback(0);
    }
    return;
  }
  //get_difference_active = 1;
  //difference_got = 0;
  if (channel->flags & TGLCHF_DIFF) {
    if (callback) {
      callback(0);
    }
    return;
  }
  channel->flags |= TGLCHF_DIFF;

  clear_packet ();
  tgl_do_insert_header ();

  out_int (CODE_updates_get_channel_difference);
  out_int (CODE_input_channel);
  out_int (tgl_get_peer_id (channel->id));
  out_long (channel->id.access_hash);

  out_int (CODE_channel_messages_filter_empty);
  out_int (channel->pts);
  out_int (100);

  auto q = std::make_shared<query_get_channel_difference>(channel, callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
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

void tgl_do_add_user_to_chat (tgl_peer_id_t chat_id, tgl_peer_id_t id, int limit, std::function<void(bool success)> callback) {
  clear_packet ();
  out_int (CODE_messages_add_chat_user);
  out_int (tgl_get_peer_id (chat_id));

  assert (tgl_get_peer_type (id) == TGL_PEER_USER);
  out_int (CODE_input_user);
  out_int (tgl_get_peer_id (id));
  out_long (id.access_hash);
  out_int (limit);

  auto q = std::make_shared<query_send_msgs>(callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}

void tgl_do_del_user_from_chat (tgl_peer_id_t chat_id, tgl_peer_id_t id, std::function<void(bool success)> callback) {
  clear_packet ();
  out_int (CODE_messages_delete_chat_user);
  out_int (tgl_get_peer_id (chat_id));

  assert (tgl_get_peer_type (id) == TGL_PEER_USER);
  out_int (CODE_input_user);
  out_int (tgl_get_peer_id (id));
  out_long (id.access_hash);

  auto q = std::make_shared<query_send_msgs>(callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}

/* }}} */

/* {{{ Add user to channel */

void tgl_do_channel_invite_user (tgl_peer_id_t channel_id, tgl_peer_id_t id, std::function<void(bool success)> callback) {
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

  auto q = std::make_shared<query_send_msgs>(callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}

void tgl_do_channel_kick_user (tgl_peer_id_t channel_id, tgl_peer_id_t id, std::function<void(bool success)> callback) {
  clear_packet ();
  out_int (CODE_channels_kick_from_channel);
  out_int (CODE_input_channel);
  out_int (channel_id.peer_id);
  out_long (channel_id.access_hash);

  out_int (CODE_input_user);
  out_int (tgl_get_peer_id (id));
  out_long (id.access_hash);

  out_int (CODE_bool_true);

  auto q = std::make_shared<query_send_msgs>(callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}

/* }}} */

/* {{{ Create secret chat */

#ifdef ENABLE_SECRET_CHAT
int tgl_do_create_secret_chat(const tgl_peer_id_t& user_id, std::function<void(bool success, const std::shared_ptr<tgl_secret_chat>& E)> callback) {
    return tgl_do_create_encr_chat_request (user_id, callback);
}
#endif
/* }}} */

/* {{{ Create group chat */

void tgl_do_create_group_chat (std::vector<tgl_peer_id_t> user_ids, const std::string &chat_topic, std::function<void(bool success)> callback) {
  clear_packet ();
  out_int (CODE_messages_create_chat);
  out_int (CODE_vector);
  out_int (user_ids.size()); // Number of users, currently we support only 1 user.
  for (tgl_peer_id_t id : user_ids) {
    if (tgl_get_peer_type (id) != TGL_PEER_USER) {
      tgl_set_query_error (EINVAL, "Can not create chat with unknown user");
      if (callback) {
        callback(0);
      }
      return;
    }
    out_int (CODE_input_user);
    out_int (tgl_get_peer_id (id));
    out_long (id.access_hash);
  }
  TGL_NOTICE("sending out chat creat request users number:%d" << user_ids.size());
  out_cstring (chat_topic.c_str(), chat_topic.length());

  auto q = std::make_shared<query_send_msgs>(callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}
/* }}} */

/* {{{ Create channel */

void tgl_do_create_channel (int users_num, tgl_peer_id_t ids[], const char *chat_topic, int chat_topic_len, const char *about, int about_len, unsigned long long flags, std::function<void(bool success)> callback) {
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
        callback(0);
      }
      return;
    }
    out_int (CODE_input_user);
    out_int (tgl_get_peer_id (id));
    out_long (id.access_hash);
  }

  auto q = std::make_shared<query_send_msgs>(callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}
/* }}} */

/* {{{ Delete msg */
class query_delete_msg: public query
{
public:
    query_delete_msg(const tgl_message_id_t& message_id,
            const std::function<void(bool)>& callback)
        : query("delete message", TYPE_TO_PARAM(messages_affected_messages))
        , m_message_id(message_id)
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        tl_ds_messages_affected_messages* DS_MAM = static_cast<tl_ds_messages_affected_messages*>(D);
#if 0 // FIXME
        struct tgl_message *M = tgl_message_get (id.get());
        if (M) {
            bl_do_message_delete (&M->permanent_id);
        }
#endif
        tgl_state::instance()->callback()->message_deleted(m_message_id.id);

        int r = tgl_check_pts_diff(DS_LVAL(DS_MAM->pts), DS_LVAL(DS_MAM->pts_count));

        if (r > 0) {
            tgl_state::instance()->set_pts(DS_LVAL(DS_MAM->pts));
        }

        if (m_callback) {
            m_callback(true);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false);
        }
        return 0;
    }

private:
    tgl_message_id_t m_message_id;
    std::function<void(bool)> m_callback;
};

void tgl_do_delete_msg (tgl_message_id_t *_msg_id, std::function<void(bool success)> callback) {
  tgl_message_id_t msg_id = *_msg_id;
  if (msg_id.peer_type == TGL_PEER_TEMP_ID) {
    msg_id = tgl_convert_temp_msg_id (msg_id);
  }
  if (msg_id.peer_type == TGL_PEER_TEMP_ID) {
    tgl_set_query_error (EINVAL, "unknown message");
    if (callback) {
      callback(0);
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

  auto q = std::make_shared<query_delete_msg>(msg_id, callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}
/* }}} */

/* {{{ Export card */
static struct paramed_type bare_int_type = TYPE_TO_PARAM (bare_int);
static struct paramed_type *bare_int_array_type[1] = {&bare_int_type};
static struct paramed_type vector_type = (struct paramed_type) {.type = &tl_type_vector, .params=bare_int_array_type};

class query_export_card: public query
{
public:
    explicit query_export_card(const std::function<void(bool, const std::vector<int>&)>& callback)
        : query("export card", vector_type)
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        tl_ds_vector* DS_V = static_cast<tl_ds_vector*>(D);
        int n = DS_LVAL (DS_V->f1);
        std::vector<int> card;
        for (int i = 0; i < n; i++) {
            card.push_back(*reinterpret_cast<int*>(DS_V->f2[i]));
        }
        if (m_callback) {
            m_callback(true, card);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false, std::vector<int>());
        }
        return 0;
    }

private:
    std::function<void(bool, const std::vector<int>&)> m_callback;
};

void tgl_do_export_card(const std::function<void(bool success, const std::vector<int>& card)>& callback) {
    clear_packet ();
    out_int (CODE_contacts_export_card);

    auto q = std::make_shared<query_export_card>(callback);
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    q->execute(tgl_state::instance()->DC_working);
}
/* }}} */

/* {{{ Import card */
class query_import_card: public query
{
public:
    explicit query_import_card(const std::function<void(bool, const std::shared_ptr<tgl_user>&)>& callback)
        : query("import card", TYPE_TO_PARAM(user))
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        std::shared_ptr<tgl_user> user = tglf_fetch_alloc_user(static_cast<tl_ds_user*>(D));
        if (m_callback) {
            m_callback(true, user);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false, nullptr);
        }
        return 0;
    }

private:
    std::function<void(bool, const std::shared_ptr<tgl_user>&)> m_callback;
};

void tgl_do_import_card (int size, int *card, std::function<void(bool success, const std::shared_ptr<tgl_user>& user)> callback) {
    clear_packet ();
    out_int (CODE_contacts_import_card);
    out_int (CODE_vector);
    out_int (size);
    out_ints (card, size);

    auto q = std::make_shared<query_import_card>(callback);
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    q->execute(tgl_state::instance()->DC_working);
}
/* }}} */

void tgl_do_start_bot (tgl_peer_id_t bot, tgl_peer_id_t chat, const char *str, int str_len, std::function<void(bool success)> callback) {
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

  auto q = std::make_shared<query_send_msgs>(callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}

/* {{{ Send typing */
class query_send_typing: public query
{
public:
    explicit query_send_typing(const std::function<void(bool)>& callback)
        : query("send typing", TYPE_TO_PARAM(bool))
        , m_callback(callback)
    { }

    virtual void on_answer(void*) override
    {
        if (m_callback) {
            m_callback(true);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false);
        }
        return 0;
    }

private:
    std::function<void(bool)> m_callback;
};

void tgl_do_send_typing (tgl_peer_id_t id, enum tgl_typing_status status, std::function<void(bool success)> callback) {
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
        auto q = std::make_shared<query_send_typing>(callback);
        q->load_data(packet_buffer, packet_ptr - packet_buffer);
        q->execute(tgl_state::instance()->DC_working);
    } else {
        if (callback) {
            callback(false);
        }
    }
}
/* }}} */

/* {{{ Extd query */
#ifndef DISABLE_EXTF
#if 0
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
#endif

void tgl_do_send_extf (const char *data, int data_len, std::function<void(bool success, const char *buf)> callback) {
#if 0
  clear_packet ();

  ext_query_methods.type = tglf_extf_store (data, data_len);

  if (ext_query_methods.type) {
    tglq_send_query (tgl_state::instance()->DC_working, packet_ptr - packet_buffer, packet_buffer, &ext_query_methods, 0, callback ? std::make_shared<std::function<void(bool, const char*)>>(callback));
  }
#else
    if (callback) {
        callback(false, nullptr);
    }
#endif
}
#else
void tgl_do_send_extf (const char *data, int data_len, std::function<void(bool success, const char *buf)> callback) {
  assert (0);
}
#endif
/* }}} */

/* {{{ get messages */
class query_get_messages: public query
{
public:
    explicit query_get_messages(const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& single_callback)
        : query("get messages (single)", TYPE_TO_PARAM(messages_messages))
        , m_single_callback(single_callback)
        , m_multi_callback(nullptr)
    { }

    explicit query_get_messages(const std::function<void(bool, const std::vector<std::shared_ptr<tgl_message>>&)>& multi_callback)
        : query("get messages (multi)", TYPE_TO_PARAM(messages_messages))
        , m_single_callback(nullptr)
        , m_multi_callback(multi_callback)
    { }

    virtual void on_answer(void* D) override
    {
        tl_ds_messages_messages* DS_MM = static_cast<tl_ds_messages_messages*>(D);
        for (int i = 0; i < DS_LVAL(DS_MM->users->cnt); i++) {
            tglf_fetch_alloc_user(DS_MM->users->data[i]);
        }
        for (int i = 0; i < DS_LVAL(DS_MM->chats->cnt); i++) {
            tglf_fetch_alloc_chat(DS_MM->chats->data[i]);
        }

        std::vector<std::shared_ptr<tgl_message>> messages;
        for (int i = 0; i < DS_LVAL(DS_MM->messages->cnt); i++) {
            messages.push_back(tglf_fetch_alloc_message(DS_MM->messages->data[i], NULL));
        }
        if (m_multi_callback) {
            assert(!m_single_callback);
            m_multi_callback(true, messages);
        } else if (m_single_callback) {
            assert(!m_multi_callback);
            if (messages.size() > 0) {
                m_single_callback(true, messages[0]);
            } else {
                tgl_set_query_error (ENOENT, "no such message");
                m_single_callback(false, nullptr);
            }
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_multi_callback) {
            assert(!m_single_callback);
            m_multi_callback(false, std::vector<std::shared_ptr<tgl_message>>());
        } else if (m_single_callback) {
            assert(!m_multi_callback);
            m_single_callback(false, nullptr);
        }
        return 0;
    }

private:
    std::function<void(bool, const std::shared_ptr<tgl_message>&)> m_single_callback;
    std::function<void(bool, const std::vector<std::shared_ptr<tgl_message>>&)> m_multi_callback;
};

void tgl_do_get_message (tgl_message_id_t *_msg_id, std::function<void(bool success, const std::shared_ptr<tgl_message>& M)> callback)
{
  tgl_message_id_t msg_id = *_msg_id;
  if (msg_id.peer_type == TGL_PEER_TEMP_ID) {
    msg_id = tgl_convert_temp_msg_id (msg_id);
  }
  if (msg_id.peer_type == TGL_PEER_TEMP_ID) {
    tgl_set_query_error (EINVAL, "unknown message");
    if (callback) {
      callback(0, NULL);
    }
    return;
  }

#if 0
  struct tgl_message *M = tgl_message_get (&msg_id);
  if (M) {
    if (callback) {
      callback(1, M);
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

  auto q = std::make_shared<query_get_messages>(callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}
/* }}} */

/* {{{ Export/import chat link */
class query_export_chat_link: public query
{
public:
    explicit query_export_chat_link(const std::function<void(bool, const std::string&)>& callback)
        : query("export chat link", TYPE_TO_PARAM(exported_chat_invite))
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        tl_ds_exported_chat_invite* DS_ECI = static_cast<tl_ds_exported_chat_invite*>(D);
        if (m_callback) {
            std::string link;
            if (DS_ECI->link && DS_ECI->link->data) {
                link = std::string(DS_ECI->link->data, DS_ECI->link->len);
            }
            m_callback(true, link);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false, std::string());
        }
        return 0;
    }

private:
    std::function<void(bool, const std::string&)> m_callback;
};

void tgl_do_export_chat_link(const tgl_peer_id_t& id, const std::function<void(bool success, const std::string& link)>& callback) {
    if (tgl_get_peer_type (id) != TGL_PEER_CHAT) {
        TGL_ERROR("Can only export chat link for chat");
        if (callback) {
            callback(false, std::string());
        }
        return;
    }

    clear_packet ();
    out_int (CODE_messages_export_chat_invite);
    out_int (tgl_get_peer_id (id));

    auto q = std::make_shared<query_export_chat_link>(callback);
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    q->execute(tgl_state::instance()->DC_working);
}

void tgl_do_import_chat_link (const char *link, int len, std::function<void(bool success)> callback) {
    const char *l = link + len - 1;
    while (l >= link && *l != '/') {
        l --;
    }
    l ++;

    clear_packet ();
    out_int (CODE_messages_import_chat_invite);
    out_cstring (l, len - (l - link));

    auto q = std::make_shared<query_send_msgs>(callback);
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    q->execute(tgl_state::instance()->DC_working);
}

/* }}} */

/* {{{ Export/import channel link */

void tgl_do_export_channel_link(const tgl_peer_id_t& id, const std::function<void(bool success, const std::string& link)>& callback) {
  if (tgl_get_peer_type (id) != TGL_PEER_CHANNEL) {
    tgl_set_query_error (EINVAL, "Can only export chat link for chat");
    if (callback) {
      callback(0, NULL);
    }
    return;
  }

  clear_packet ();
  out_int (CODE_channels_export_invite);
  out_int (CODE_input_channel);
  out_int (tgl_get_peer_id (id));
  out_long (id.access_hash);

  auto q = std::make_shared<query_export_chat_link>(callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}

/* }}} */

/* {{{ set password */
class query_set_password: public query
{
public:
    explicit query_set_password(const std::function<void(bool)>& callback)
        : query("set password", TYPE_TO_PARAM(bool))
        , m_callback(callback)
    { }

    virtual void on_answer(void*) override
    {
        if (m_callback) {
            m_callback(true);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        if (error_code == 400) {
            if (error_string == "PASSWORD_HASH_INVALID") {
                TGL_WARNING("Bad old password");
                if (m_callback) {
                    m_callback(false);
                }
                return 0;
            }
            if (error_string == "NEW_PASSWORD_BAD") {
                TGL_WARNING("Bad new password (unchanged or equals hint)");
                if (m_callback) {
                    m_callback(false);
                }
                return 0;
            }
            if (error_string == "NEW_SALT_INVALID") {
                TGL_WARNING("Bad new salt");
                if (m_callback) {
                    m_callback(false);
                }
                return 0;
            }
        }

        TGL_ERROR("RPC_CALL_FAIL " <<  error_code << " " << error_string);

        if (m_callback) {
            m_callback(false);
        }

        return 0;
    }

private:
    std::function<void(bool)> m_callback;
};

static void tgl_do_act_set_password(const std::string& current_password,
        const std::string& new_password,
        const std::string& current_salt,
        const std::string& new_salt,
        const std::string& hint,
        const std::function<void(bool success)>& callback) {
    clear_packet ();
    char s[512];
    unsigned char shab[32];
    memset(s, 0, sizeof(s));
    memset(shab, 0, sizeof(shab));

    if (current_salt.size() > 128 || current_password.size() > 128 || new_salt.size() > 128 || new_password.size() > 128) {
        if (callback) {
            callback(false);
        }
        return;
    }

    out_int (CODE_account_update_password_settings);

    if (current_password.size() && current_salt.size()) {
        memcpy (s, current_salt.data(), current_salt.size());
        memcpy (s + current_salt.size(), current_password.data(), current_password.size());
        memcpy (s + current_salt.size() + current_password.size(), current_salt.data(), current_salt.size());

        TGLC_sha256 ((const unsigned char *)s, 2 * current_salt.size() + current_password.size(), shab);
        out_cstring ((const char *)shab, 32);
    } else {
        out_string ("");
    }

    out_int (CODE_account_password_input_settings);
    if (new_password.size()) {
        out_int (1);

        char d[256];
        memset(d, 0, sizeof(d));
        memcpy (d, new_salt.data(), new_salt.size());

        int l = new_salt.size();
        tglt_secure_random ((unsigned char*)d + l, 16);
        l += 16;
        memcpy (s, d, l);

        memcpy (s + l, new_password.data(), new_password.size());
        memcpy (s + l + new_password.size(), d, l);

        TGLC_sha256 ((const unsigned char *)s, 2 * l + new_password.size(), shab);

        out_cstring (d, l);
        out_cstring ((const char *)shab, 32);
        out_cstring (hint.c_str(), hint.size());
    } else {
        out_int (0);
    }

    auto q = std::make_shared<query_set_password>(callback);
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    q->execute(tgl_state::instance()->DC_working);
}

struct change_password_state {
    std::string current_password;
    std::string new_password;
    std::string current_salt;
    std::string new_salt;
    std::string hint;
    std::function<void(bool)> callback;
};

void tgl_on_new_pwd(const std::shared_ptr<change_password_state>& state, const void* answer)
{
    const char** pwds = (const char**)answer;
    state->new_password = std::string(pwds[0]);
    std::string new_password_confirm = std::string(pwds[1]);

    if (state->new_password != new_password_confirm) {
        TGL_ERROR("passwords do not match");
        tgl_state::instance()->callback()->get_values(tgl_new_password, "new password: ", 2, std::bind(tgl_on_new_pwd, state, std::placeholders::_1));
        return;
    }

    tgl_do_act_set_password(state->current_password,
            state->new_password,
            state->current_salt,
            state->new_salt,
            state->hint,
            state->callback);
}

void tgl_on_old_pwd(const std::shared_ptr<change_password_state>& state, const void* answer)
{
    const char** pwds = (const char**)answer;
    state->current_password = std::string(pwds[0]);
    tgl_on_new_pwd(state, pwds + 1);
}

class query_get_and_set_password: public query
{
public:
    query_get_and_set_password(const std::string& hint,
            const std::function<void(bool)>& callback)
        : query("get and set password", TYPE_TO_PARAM(account_password))
        , m_hint(hint)
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        tl_ds_account_password* DS_AP = static_cast<tl_ds_account_password*>(D);
        std::shared_ptr<change_password_state> state = std::make_shared<change_password_state>();

        if (DS_AP->current_salt && DS_AP->current_salt->data) {
            state->current_salt = std::string(DS_AP->current_salt->data, DS_AP->current_salt->len);
        }
        if (DS_AP->new_salt && DS_AP->new_salt->data) {
            state->new_salt = std::string(DS_AP->new_salt->data, DS_AP->new_salt->len);
        }

        if (!m_hint.empty()) {
            state->hint = m_hint;
        }

        state->callback = m_callback;

        if (DS_AP->magic == CODE_account_no_password) {
            tgl_state::instance()->callback()->get_values(tgl_new_password, "new password: ", 2, std::bind(tgl_on_new_pwd, state, std::placeholders::_1));
        } else {
            char s[512];
            memset(s, 0, sizeof(s));
            snprintf (s, sizeof(s) - 1, "old password (hint %.*s): ", DS_RSTR(DS_AP->hint));
            tgl_state::instance()->callback()->get_values(tgl_cur_and_new_password, s, 3, std::bind(tgl_on_old_pwd, state, std::placeholders::_1));
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false);
        }
        return 0;
    }

private:
    std::string m_hint;
    std::function<void(bool)> m_callback;
};

void tgl_do_set_password(const std::string& hint, const std::function<void(bool success)>& callback) {
    clear_packet ();
    out_int (CODE_account_get_password);

    auto q = std::make_shared<query_get_and_set_password>(hint, callback);
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    q->execute(tgl_state::instance()->DC_working);
}

/* }}} */

/* {{{ check password */
class query_check_password: public query
{
public:
    explicit query_check_password(const std::function<void(bool)>& callback)
        : query("check password", TYPE_TO_PARAM(auth_authorization))
        , m_callback(callback)
    { }

    virtual void on_answer(void*) override
    {
        tgl_state::instance()->locks ^= TGL_LOCK_PASSWORD;
        if (m_callback) {
            m_callback(true);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        if (error_code == 400) {
            TGL_ERROR("bad password");
            tgl_do_check_password(m_callback);
            return 0;
        }

        tgl_state::instance()->locks ^= TGL_LOCK_PASSWORD;
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);

        if (m_callback) {
            m_callback(false);
        }

        return 0;
    }

private:
    std::function<void(bool)> m_callback;
};

static void tgl_pwd_got(const std::string& current_salt, const std::function<void(bool)>& callback, const void* answer)
{
    clear_packet ();
    char s[512];
    unsigned char shab[32];
    memset(s, 0, sizeof(s));
    memset(shab, 0, sizeof(shab));

    const char* pwd = static_cast<const char*>(answer);
    int pwd_len = pwd ? strlen(pwd) : 0;
    if (current_salt.size() > 128 || pwd_len > 128) {
        if (callback) {
            callback(false);
        }
        return;
    }

    out_int (CODE_auth_check_password);

    if (pwd && current_salt.size()) {
        memcpy(s, current_salt.data(), current_salt.size());
        memcpy(s + current_salt.size(), pwd, pwd_len);
        memcpy(s + current_salt.size() + pwd_len, current_salt.data(), current_salt.size());
        TGLC_sha256 ((const unsigned char *)s, 2 * current_salt.size() + pwd_len, shab);
        out_cstring ((const char *)shab, 32);
    } else {
        out_string ("");
    }

    auto q = std::make_shared<query_check_password>(callback);
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    q->execute(tgl_state::instance()->DC_working);
}

class query_get_and_check_password: public query
{
public:
    explicit query_get_and_check_password(const std::function<void(bool)>& callback)
        : query("get and check password", TYPE_TO_PARAM(account_password))
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        tl_ds_account_password* DS_AP = static_cast<tl_ds_account_password*>(D);

        if (DS_AP->magic == CODE_account_no_password) {
            tgl_state::instance()->locks ^= TGL_LOCK_PASSWORD;
            return;
        }

        char s[512];
        memset(s, 0, sizeof(s));
        snprintf(s, sizeof(s) - 1, "type password (hint %.*s): ", DS_RSTR(DS_AP->hint));

        std::string current_salt;
        if (DS_AP->current_salt && DS_AP->current_salt->data) {
            current_salt = std::string(DS_AP->current_salt->data, DS_AP->current_salt->len);
        }

        tgl_state::instance()->callback()->get_values(tgl_cur_password, s, 1,
                std::bind(tgl_pwd_got, current_salt, m_callback, std::placeholders::_1));
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        tgl_state::instance()->locks ^= TGL_LOCK_PASSWORD;
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false);
        }
        return 0;
    }

private:
    std::function<void(bool)> m_callback;
};

void tgl_do_check_password (std::function<void(bool success)> callback) {
    clear_packet ();
    out_int (CODE_account_get_password);

    auto q = std::make_shared<query_get_and_check_password>(callback);
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    q->execute(tgl_state::instance()->DC_working);
}

/* }}} */

/* {{{ send broadcast */
void tgl_do_send_broadcast (int num, tgl_peer_id_t peer_id[], const char *text, int text_len, unsigned long long flags,
        std::function<void(bool success, const std::vector<std::shared_ptr<tgl_message>>& ML)> callback)
{
  if (num > 1000) {
      if (callback) {
          callback(false, std::vector<std::shared_ptr<tgl_message>>());
      }
      return;
  }

  std::shared_ptr<messages_send_extra> E = std::make_shared<messages_send_extra>();
  E->multi = true;
  E->count = num;

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
    E->message_ids.push_back(id);

    tgl_peer_id_t from_id = tgl_state::instance()->our_id();
    //bl_do_edit_message (&id, &from_id, &peer_id[i], NULL, NULL, &date, text, text_len, &TDSM, NULL, NULL, NULL, NULL, TGLMF_UNREAD | TGLMF_OUT | TGLMF_PENDING | TGLMF_CREATE | TGLMF_CREATED);

    int date = time (0);
    struct tl_ds_message_media TDSM;
    TDSM.magic = CODE_message_media_empty;

    tglm_message_create (&id, &from_id, &peer_id[i], NULL, NULL, &date, text, &TDSM, NULL, NULL, NULL, TGLMF_UNREAD | TGLMF_OUT | TGLMF_PENDING | TGLMF_CREATE | TGLMF_CREATED);
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
    out_long (E->message_ids[i].id);
  }
  out_cstring (text, text_len);

  out_int (CODE_message_media_empty);

  auto q = std::make_shared<query_send_msgs>(E, callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}
/* }}} */

/* {{{ block user */
class query_block_or_unblock_user: public query
{
public:
    explicit query_block_or_unblock_user(const std::function<void(bool)>& callback)
        : query("block or unblock user", TYPE_TO_PARAM(bool))
        , m_callback(callback)
    { }

    virtual void on_answer(void*) override
    {
        if (m_callback) {
            m_callback(true);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false);
        }
        return 0;
    }

private:
    std::function<void(bool)> m_callback;
};

void tgl_do_block_user (tgl_peer_id_t id, std::function<void(bool success)> callback) {
  if (tgl_get_peer_type (id) != TGL_PEER_USER) {
    tgl_set_query_error (EINVAL, "id should be user id");
    if (callback) {
      callback(false);
    }
    return;
  }
  clear_packet ();

  out_int (CODE_contacts_block);
  out_int (CODE_input_user);
  out_int (tgl_get_peer_id (id));
  out_long (id.access_hash);

  auto q = std::make_shared<query_block_or_unblock_user>(callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}

void tgl_do_unblock_user (tgl_peer_id_t id, std::function<void(bool success)> callback) {
  if (tgl_get_peer_type (id) != TGL_PEER_USER) {
    tgl_set_query_error (EINVAL, "id should be user id");
    if (callback) {
      callback(false);
    }
    return;
  }

  clear_packet ();

  out_int (CODE_contacts_unblock);

  out_int (CODE_input_user);
  out_int (tgl_get_peer_id (id));
  out_long (id.access_hash);

  auto q = std::make_shared<query_block_or_unblock_user>(callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}
/* }}} */

/* {{{ get terms of service */
class query_get_tos: public query
{
public:
    explicit query_get_tos(const std::function<void(bool, const std::string&)>& callback)
        : query("get tos", TYPE_TO_PARAM(help_terms_of_service))
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        tl_ds_help_terms_of_service* DS_T = static_cast<tl_ds_help_terms_of_service*>(D);

        if (!DS_T->text || !DS_T->text->data) {
            if (m_callback) {
                m_callback(true, std::string());
            }
            return;
        }

        int l = DS_T->text->len;
        std::vector<char> buffer(l + 1);
        char *s = buffer.data();
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

        if (m_callback) {
            m_callback(true, std::string(s, pp));
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false, std::string());
        }
        return 0;
    }

private:
    std::function<void(bool, const std::string&)> m_callback;
};

void tgl_do_get_terms_of_service(const std::function<void(bool success, const std::string& tos)>& callback) {
  clear_packet ();

  out_int (CODE_help_get_terms_of_service);
  out_string ("");

  auto q = std::make_shared<query_get_tos>(callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}
/* }}} */
class query_register_device: public query
{
public:
    explicit query_register_device(const std::function<void(bool)>& callback)
        : query("regster device", TYPE_TO_PARAM(bool))
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        if (m_callback) {
            m_callback(true);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false);
        }
        return 0;
    }

private:
    std::function<void(bool)> m_callback;
};

void tgl_do_register_device(int token_type, const std::string& token, const std::string& device_model, const std::string& system_version, const std::string& lang_code,
                                std::function<void(bool success)> callback)
{
    clear_packet ();
    out_int (CODE_account_register_device);
    out_int(token_type);
    out_std_string(token);
    out_std_string(device_model);
    out_std_string(system_version);
    out_string("0.1");
    out_int (CODE_bool_true); // app sandbox
    out_std_string(lang_code);

    auto q = std::make_shared<query_register_device>(callback);
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    q->execute(tgl_state::instance()->DC_working);
}

void tgl_do_upgrade_group (tgl_peer_id_t id, std::function<void(bool success)> callback) {
  clear_packet ();

  out_int (CODE_messages_migrate_chat);
  out_int (tgl_get_peer_id (id));

  auto q = std::make_shared<query_send_msgs>(callback);
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
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
      tgl_do_transfer_auth(D->id, std::bind(tgl_transfer_auth_callback, D, std::placeholders::_1));
    }
  }
}

class query_send_bind_temp_auth_key: public query
{
public:
    explicit query_send_bind_temp_auth_key(const std::shared_ptr<tgl_dc>& dc)
        : query("bind temp auth key", TYPE_TO_PARAM(bool))
        , m_dc(dc)
    { }

    virtual void on_answer(void*) override
    {
        m_dc->flags |= TGLDCF_BOUND;
        TGL_DEBUG("Bind successful in DC " << m_dc->id);
        tgl_do_help_get_config_dc(m_dc);
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_WARNING("Bind: error " << error_code << " " << error_string);
        if (error_code == 400) {
            return -11;
        }
        return 0;
    }

    virtual bool on_timeout() override
    {
        TGL_NOTICE("Bind timed out for DC " << m_dc->id);
        m_dc->reset();
        return true;
    }

private:
    std::shared_ptr<tgl_dc> m_dc;
};

void tgl_do_send_bind_temp_key (std::shared_ptr<tgl_dc> D, long long nonce, int expires_at, void *data, int len, long long msg_id) {
    clear_packet ();
    out_int (CODE_auth_bind_temp_auth_key);
    out_long (D->auth_key_id);
    out_long (nonce);
    out_int (expires_at);
    out_cstring ((char*)data, len);

    auto q = std::make_shared<query_send_bind_temp_auth_key>(D);
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    q->execute(D, QUERY_FORCE_SEND);
    assert (q->msg_id() == msg_id);
}

class query_update_status: public query
{
public:
    explicit query_update_status(const std::function<void(bool)>& callback)
        : query("update status", TYPE_TO_PARAM(bool))
        , m_callback(callback)
    { }

    virtual void on_answer(void*) override
    {
        if (m_callback) {
            m_callback(true);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false);
        }
        return 0;
    }

private:
    std::function<void(bool)> m_callback;
};

void tgl_do_update_status (bool online, std::function<void(bool success)> callback) {
    clear_packet ();
    out_int (CODE_account_update_status);
    out_int (online ? CODE_bool_false : CODE_bool_true);

    auto q = std::make_shared<query_update_status>(callback);
    q->load_data(packet_buffer, packet_ptr - packet_buffer);
    q->execute(tgl_state::instance()->DC_working);
}

void tgl_started_cb(bool success) {
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

void tgl_transfer_auth_callback(std::shared_ptr<tgl_dc> DC, bool success)
{
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
      tgl_do_transfer_auth (i, std::bind(tgl_transfer_auth_callback, tgl_state::instance()->DC_list[i], std::placeholders::_1));
    }
  }
}

void tgl_signed_in() {
  tgl_state::instance()->callback()->logged_in();

  TGL_DEBUG("signed in, sending unsent messages and retrieving current server state");

  tgl_export_all_auth();
  tglm_send_all_unsent();
  tgl_do_get_difference (0, tgl_started_cb);
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

    ~sign_up_extra() {
        free(phone);
        free(hash);
        free(first_name);
        free(last_name);
    }
};

void tgl_sign_in_code(std::shared_ptr<sign_up_extra> E, const void *code);
void tgl_sign_in_result(std::shared_ptr<sign_up_extra> E, bool success, const std::shared_ptr<tgl_user>& U) {
    TGL_ERROR(".....tgl_sign_in_result");
    if (!success) {
        TGL_ERROR("incorrect code");
        tgl_state::instance()->callback()->get_values(tgl_code, "code ('call' for phone call):", 1, std::bind(tgl_sign_in_code, E, std::placeholders::_1));
        return;
    }
    tgl_signed_in();
}

void tgl_sign_in_code(std::shared_ptr<sign_up_extra> E, const void *code)
{
    if (!strcmp ((const char *)code, "call")) {
        tgl_do_phone_call (E->phone, E->phone_len, E->hash, E->hash_len, 0);
        tgl_state::instance()->callback()->get_values(tgl_code, "code ('call' for phone call):", 1, std::bind(tgl_sign_in_code, E, std::placeholders::_1));
        return;
    }

    tgl_do_send_code_result(E->phone, E->phone_len, E->hash, E->hash_len, (const char *)code, strlen ((const char *)code),
            std::bind(tgl_sign_in_result, E, std::placeholders::_1, std::placeholders::_2));
}

void tgl_sign_up_code (std::shared_ptr<sign_up_extra> E, const void *code);
void tgl_sign_up_result (std::shared_ptr<sign_up_extra> E, bool success, const std::shared_ptr<tgl_user>& U) {
    TGL_UNUSED(U);
    if (!success) {
        TGL_ERROR("incorrect code");
        tgl_state::instance()->callback()->get_values(tgl_code, "code ('call' for phone call):", 1, std::bind(tgl_sign_up_code, E, std::placeholders::_1));
        return;
    }
    tgl_signed_in();
}

void tgl_sign_up_code (std::shared_ptr<sign_up_extra> E, const void *code) {
    if (!strcmp ((const char*)code, "call")) {
        tgl_do_phone_call (E->phone, E->phone_len, E->hash, E->hash_len, 0);
        tgl_state::instance()->callback()->get_values(tgl_code, "code ('call' for phone call):", 1, std::bind(tgl_sign_up_code, E, std::placeholders::_1));
        return;
    }

    tgl_do_send_code_result_auth (E->phone, E->phone_len, E->hash, E->hash_len, (const char*)code, strlen ((const char*)code), E->first_name, E->first_name_len,
            E->last_name, E->last_name_len, std::bind(tgl_sign_up_result, E, std::placeholders::_1, std::placeholders::_2));
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

void tgl_register_cb (std::shared_ptr<sign_up_extra> E, const void *rinfo)
{
    const char **yn = (const char**)rinfo;
    if (yn[0]) {
        if (!tgl_set_first_name(yn[1], E)) {
            tgl_set_last_name(yn[2], E);
            tgl_state::instance()->callback()->get_values(tgl_code, "code ('call' for phone call):", 1, std::bind(tgl_sign_up_code, E, std::placeholders::_1));
        }
        else {
            tgl_state::instance()->callback()->get_values(tgl_register_info, "registration info:", 3, std::bind(tgl_register_cb, E, std::placeholders::_1));
        }
    } else {
        TGL_ERROR("stopping registration");
        tgl_state::instance()->login ();
    }
}

void tgl_sign_in_phone(const void *phone);
void tgl_sign_in_phone_cb(std::shared_ptr<sign_up_extra> E, bool success, int registered, const char *mhash) {
    tgl_state::instance()->locks ^= TGL_LOCK_PHONE;
    if (!success) {
        TGL_ERROR("Incorrect phone number");

        free (E->phone);
        E->phone = nullptr;
        E->phone_len = 0;
        tgl_state::instance()->callback()->get_values(tgl_phone_number, "phone number:", 1, tgl_sign_in_phone);
        return;
    }

    E->hash_len = strlen (mhash);
    E->hash = (char*)tmemdup (mhash, E->hash_len);

    if (registered) {
        TGL_NOTICE("Already registered. Need code");
        tgl_state::instance()->callback()->get_values(tgl_code, "code ('call' for phone call):", 1, std::bind(tgl_sign_in_code, E, std::placeholders::_1));
    } else {
        TGL_NOTICE("Not registered");
        tgl_state::instance()->callback()->get_values(tgl_register_info, "registration info:", 3, std::bind(tgl_register_cb, E, std::placeholders::_1));
    }
}

void tgl_sign_in_phone(const void *phone)
{
    std::shared_ptr<sign_up_extra> E = std::make_shared<sign_up_extra>();
    E->phone_len = strlen((const char *)phone);
    E->phone = (char*)tmemdup (phone, E->phone_len);

    tgl_state::instance()->locks |= TGL_LOCK_PHONE;

    tgl_do_send_code(E->phone, E->phone_len, std::bind(tgl_sign_in_phone_cb, E, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
}

void tgl_bot_hash_cb (const void *code);

void tgl_sign_in_bot_cb(bool success, const std::shared_ptr<tgl_user>& U) {
    if (!success) {
        TGL_ERROR("incorrect bot hash");
        tgl_state::instance()->callback()->get_values(tgl_bot_hash, "bot hash:", 1, tgl_bot_hash_cb);
        return;
    }
    tgl_signed_in();
}

void tgl_bot_hash_cb (const void *code) {
    tgl_do_send_bot_auth ((const char*)code, strlen ((const char*)code), tgl_sign_in_bot_cb);
}

void tgl_sign_in () {
  if (!tgl_signed_dc(tgl_state::instance()->DC_working)) {
    if (!(tgl_state::instance()->locks & TGL_LOCK_PHONE)) {
      tgl_state::instance()->callback()->get_values(tgl_phone_number, "phone number:", 1, tgl_sign_in_phone);
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

class query_set_phone: public query
{
public:
    explicit query_set_phone(const std::function<void(bool, const std::shared_ptr<tgl_user>&)>& callback)
        : query("set phone", TYPE_TO_PARAM(user))
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        std::shared_ptr<tgl_user> user = tglf_fetch_alloc_user(static_cast<tl_ds_user*>(D));
        if (m_callback) {
            m_callback(true, user);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false, nullptr);
        }
        return 0;
    }

private:
    std::function<void(bool, const std::shared_ptr<tgl_user>&)> m_callback;
};

class query_send_change_code: public query
{
public:
    explicit query_send_change_code(const std::function<void(bool, const std::string&)>& callback)
        : query("send change phone code", TYPE_TO_PARAM(account_sent_change_phone_code))
        , m_callback(callback)
    { }

    virtual void on_answer(void* D) override
    {
        tl_ds_account_sent_change_phone_code* DS_ASCPC = static_cast<tl_ds_account_sent_change_phone_code*>(D);
        std::string phone_code_hash;
        if (DS_ASCPC->phone_code_hash && DS_ASCPC->phone_code_hash->data) {
            phone_code_hash = std::string(DS_ASCPC->phone_code_hash->data, DS_ASCPC->phone_code_hash->len);
        }
        if (m_callback) {
            m_callback(true, phone_code_hash);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false, std::string());
        }
        return 0;
    }

private:
    std::function<void(bool, const std::string&)> m_callback;
};

struct change_phone_state {
    std::string phone;
    std::string hash;
    std::string first_name;
    std::string last_name;
    std::function<void(bool success)> callback;
};

static void tgl_set_number_code(const std::shared_ptr<change_phone_state>& state, const void *code);

static void tgl_set_number_result(const std::shared_ptr<change_phone_state>& state, bool success, const std::shared_ptr<tgl_user>&) {
  if (success) {
    if (state->callback) {
      state->callback(true);
    }
  } else {
    TGL_ERROR("incorrect code");
    tgl_state::instance()->callback()->get_values(tgl_code, "code:", 1, std::bind(tgl_set_number_code, state, std::placeholders::_1));
  }
}

static void tgl_set_number_code(const std::shared_ptr<change_phone_state>& state, const void *code) {
  const char **code_strings = (const char **)code;

  clear_packet ();
  out_int (CODE_account_change_phone);
  out_cstring (state->phone.data(), state->phone.size());
  out_cstring (state->hash.data(), state->hash.size());
  out_cstring (code_strings[0], strlen (code_strings[0]));

  auto q = std::make_shared<query_set_phone>(std::bind(tgl_set_number_result, state, std::placeholders::_1, std::placeholders::_2));
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}


static void tgl_set_phone_number_cb(const std::shared_ptr<change_phone_state>& state, bool success, const std::string& hash) {
  if (!success) {
      TGL_ERROR("Incorrect phone number");
      if (state->callback) {
          state->callback(false);
      }
      return;
  }

  state->hash = hash;
  tgl_state::instance()->callback()->get_values (tgl_code, "code:", 1, std::bind(tgl_set_number_code, state, std::placeholders::_1));
}

void tgl_do_set_phone_number(const std::string& phonenumber, const std::function<void(bool success)>& callback) {
  std::shared_ptr<change_phone_state> state = std::make_shared<change_phone_state>();
  state->phone = phonenumber;

  clear_packet ();
  tgl_do_insert_header ();
  out_int (CODE_account_send_change_phone_code);
  out_cstring (state->phone.data(), state->phone.size());
  state->callback = callback;

  auto q = std::make_shared<query_send_change_code>(std::bind(tgl_set_phone_number_cb, state, std::placeholders::_1, std::placeholders::_2));
  q->load_data(packet_buffer, packet_ptr - packet_buffer);
  q->execute(tgl_state::instance()->DC_working);
}
