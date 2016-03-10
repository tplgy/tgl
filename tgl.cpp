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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "crypto/rsa_pem.h"
#include "tgl.h"
#include "tools.h"
#include "mtproto-client.h"
#include "tgl-structures.h"
#include <openssl/sha.h>

#include <assert.h>

struct tgl_state tgl_state;

void tgl_set_auth_key(struct tgl_state *TLS, int num, const char *buf)
{
    fprintf(stderr, "set auth %d\n", num);
    assert (num > 0 && num <= MAX_DC_ID);
    assert (TLS->DC_list[num]);

    if (buf) {
        memcpy(TLS->DC_list[num]->auth_key, buf, 256);
    }

    static unsigned char sha1_buffer[20];
    SHA1 ((unsigned char *)TLS->DC_list[num]->auth_key, 256, sha1_buffer);
    TLS->DC_list[num]->auth_key_id = *(long long *)(sha1_buffer + 12);

    TLS->DC_list[num]->flags |= TGLDCF_AUTHORIZED;

    TLS->callback.dc_update(TLS->DC_list[num]);
}

void tgl_set_our_id(struct tgl_state *TLS, int id)
{
    if (TLS->our_id == id) {
        return;
    }
    TLS->our_id = id;
    assert (TLS->our_id > 0);
    if (TLS->callback.our_id) {
        TLS->callback.our_id (TLS->our_id);
    }
}

void tgl_set_dc_option (struct tgl_state *TLS, int flags, int id, const char *ip, int l2, int port)
{
    struct tgl_dc *DC = TLS->DC_list[id];

    if (DC) {
        struct tgl_dc_option *O = DC->options[flags & 3];
        while (O) {
            if (!strncmp (O->ip, ip, l2)) {
                return;
            }
            O = O->next;
        }
    }

    // make sure ip is 0 terminated
    int ip_cpy_length = l2 + (ip[l2-1] == '\0' ? 0 : 1);
    char *ip_cpy = (char*)malloc(ip_cpy_length);
    memcpy(ip_cpy, ip, l2);
    ip_cpy[ip_cpy_length-1] = '\0';

    tglmp_alloc_dc (TLS, flags, id, ip_cpy, port);
}

void tgl_set_dc_signed(struct tgl_state *TLS, int num)
{
    fprintf(stderr, "set signed %d\n", num);
    assert (num > 0 && num <= MAX_DC_ID);
    assert (TLS->DC_list[num]);
    TLS->DC_list[num]->flags |= TGLDCF_LOGGED_IN;
}

void tgl_set_working_dc(struct tgl_state *TLS, int num)
{
    fprintf(stderr, "set working %d\n", num);
    assert (num > 0 && num <= MAX_DC_ID);
    TLS->DC_working = TLS->DC_list[num];
    TLS->dc_working_num = num;
    TLS->callback.change_active_dc(num);
}

void tgl_set_qts(struct tgl_state *TLS, int qts)
{
    if (TLS->locks & TGL_LOCK_DIFF) { return; }
    if (qts <= TLS->qts) { return; }
    TLS->qts = qts;
}

void tgl_set_pts(struct tgl_state *TLS, int pts)
{
    if (TLS->locks & TGL_LOCK_DIFF) { return; }
    if (pts <= TLS->pts) { return; }
    TLS->pts = pts;
}

void tgl_set_date(struct tgl_state *TLS, int date)
{
    if (TLS->locks & TGL_LOCK_DIFF) { return; }
    if (date <= TLS->date) { return; }
    TLS->date = date;
}

void tgl_set_seq(struct tgl_state *TLS, int seq)
{
    if (TLS->locks & TGL_LOCK_DIFF) { return; }
    if (seq <= TLS->seq) { return; }
    TLS->seq = seq;
}
void tgl_set_download_directory (struct tgl_state *TLS, const char *path) {
  if (TLS->downloads_directory) {
    tfree_str (TLS->downloads_directory);
  }
  TLS->downloads_directory = tstrdup (path);
}

void tgl_set_callback (struct tgl_state *TLS, struct tgl_update_callback *cb) {
  TLS->callback = *cb;
}

void tgl_set_rsa_key (struct tgl_state *TLS, const char *key) {
  assert (TLS->rsa_key_num < TGL_MAX_RSA_KEYS_NUM);
  TLS->rsa_key_list[TLS->rsa_key_num ++] = tstrdup(key);
}

void tgl_set_rsa_key_direct (struct tgl_state *TLS, unsigned long e, int n_bytes, const unsigned char *n) {
  assert (TLS->rsa_key_num < TGL_MAX_RSA_KEYS_NUM);
  TLS->rsa_key_list[TLS->rsa_key_num] = NULL;
  TLS->rsa_key_loaded[TLS->rsa_key_num] = TGLC_rsa_new (e, n_bytes, n);
  TLS->rsa_key_num ++;
}

int tgl_init (struct tgl_state *TLS) {
  assert (TLS->timer_methods);
  assert (TLS->net_methods);
  if (!TLS->temp_key_expire_time) {
    TLS->temp_key_expire_time = 100000;
  }

  TLS->message_list.next_use = &TLS->message_list;
  TLS->message_list.prev_use = &TLS->message_list;

  if (tglmp_on_start (TLS) < 0) {
    return -1;
  }
  
  if (!TLS->app_id) {
    TLS->app_id = TG_APP_ID;
    TLS->app_hash = tstrdup (TG_APP_HASH);
  }
  return 0;
}

int tgl_authorized_dc(struct tgl_dc *DC) {
  assert (DC);
  return DC->flags & TGLDCF_AUTHORIZED;
}

int tgl_signed_dc(struct tgl_dc *DC) {
  assert (DC);
  return (DC->flags & TGLDCF_LOGGED_IN) != 0;
}

void tgl_register_app_id (struct tgl_state *TLS, int app_id, const char *app_hash) {
  TLS->app_id = app_id;
  TLS->app_hash = tstrdup (app_hash);
}

struct tgl_state *tgl_state_alloc (void) {
  return (struct tgl_state *)talloc0 (sizeof (struct tgl_state));
}

void tgl_set_verbosity (struct tgl_state *TLS, int val) {
  TLS->verbosity = val;
}

void tgl_enable_pfs (struct tgl_state *TLS) {
  TLS->enable_pfs = 1;
}

void tgl_set_test_mode (struct tgl_state *TLS) {
  TLS->test_mode ++;
}

void tgl_set_net_methods (struct tgl_state *TLS, struct tgl_net_methods *methods) {
  TLS->net_methods = methods;
}

void tgl_set_timer_methods (struct tgl_state *TLS, struct tgl_timer_methods *methods) {
  TLS->timer_methods = methods;
}

void tgl_set_ev_base (struct tgl_state *TLS, void *ev_base) {
  TLS->ev_base = (struct event_base *)ev_base;
}

void tgl_set_app_version (struct tgl_state *TLS, const char *app_version) {
  if (TLS->app_version) {
    tfree_str (TLS->app_version);
  }
  TLS->app_version = tstrdup (app_version);
}

void tgl_enable_ipv6 (struct tgl_state *TLS) {
  TLS->ipv6_enabled = 1;
}

void tgl_disable_link_preview (struct tgl_state *TLS) {
  TLS->disable_link_preview = 1;
}

void tgl_enable_bot (struct tgl_state *TLS) {
  TLS->is_bot = 1;
}
