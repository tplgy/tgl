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
    Copyright Topology LP 2016
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tgl.h"

#include "crypto/rsa_pem.h"
#include "crypto/sha.h"
#include "tools.h"
#include "mtproto-client.h"
#include "tgl_download_manager.h"
#include "tgl-structures.h"
#include "types/tgl_update_callback.h"
#include "types/tgl_rsa_key.h"
#include "types/tgl_secret_chat.h"

#include <assert.h>

tgl_state::tgl_state()
    : encr_root(0)
    , encr_prime(NULL)
    , encr_prime_bn(NULL)
    , encr_param_version(0)
    , active_queries(0)
    , started(false)
    , locks(0)
    , DC_working(NULL)
    , temp_key_expire_time(0)
    , bn_ctx(0)
    , ev_login(NULL)
    , m_app_id(0)
    , m_error_code(0)
    , m_pts(0)
    , m_qts(0)
    , m_date(0)
    , m_seq(0)
    , m_test_mode(0)
    , m_our_id(tgl_peer_id_t())
    , m_enable_pfs(false)
    , m_ipv6_enabled(false)
{
}

tgl_state *tgl_state::instance()
{
    static tgl_state *tgl_instance = new tgl_state();
    return tgl_instance;
}

void tgl_state::set_auth_key(int num, const char *buf)
{
    assert (num > 0 && num <= MAX_DC_ID);
    assert (DC_list[num]);

    if (buf) {
        memcpy(DC_list[num]->auth_key, buf, 256);
    }

    static unsigned char sha1_buffer[20];
    TGLC_sha1 ((unsigned char *)DC_list[num]->auth_key, 256, sha1_buffer);
    DC_list[num]->auth_key_id = *(long long *)(sha1_buffer + 12);

    DC_list[num]->flags |= TGLDCF_AUTHORIZED;

    TGL_DEBUG("set auth key for DC " << num << " to " << std::hex << DC_list[num]->auth_key_id);
    m_callback->dc_update(DC_list[num]);
}

void tgl_state::set_our_id(int id)
{
    if (m_our_id.peer_id == id) {
        return;
    }
    m_our_id.peer_id = id;
    assert (our_id().peer_id > 0);
    m_callback->our_id(our_id().peer_id);
}

void tgl_state::set_dc_option(int flags, int id, std::string ip, int port)
{
    if (id < 0) {
        return;
    }

    if (static_cast<size_t>(id) >= DC_list.size()) {
        DC_list.resize(id+1, nullptr);
    }
    std::shared_ptr<tgl_dc> DC = DC_list[id];

    if (DC) {
        tgl_dc_option option = DC->options[flags & 3];
        for (auto op : option.option_list) {
            if(std::get<0>(op) == ip) {
                return;
            }
        }
    }

    tglmp_alloc_dc (flags, id, ip, port);
}

void tgl_state::set_dc_signed(int num)
{
    TGL_DEBUG2("set signed " << num);
    assert (num > 0 && num <= MAX_DC_ID);
    assert (DC_list[num]);
    DC_list[num]->flags |= TGLDCF_LOGGED_IN;
    m_callback->dc_update(DC_list[num]);
}

void tgl_state::set_working_dc(int num)
{
    if (DC_working && DC_working->id == num) {
        return;
    }
    TGL_DEBUG2("change working DC to " << num);
    assert (num > 0 && num <= MAX_DC_ID);
    DC_working = DC_list[num];
    m_callback->change_active_dc(num);
}

void tgl_state::set_qts(int qts)
{
    if (locks & TGL_LOCK_DIFF) { return; }
    if (qts <= this->qts()) { return; }
    m_qts = qts;
}

void tgl_state::set_pts(int pts, bool force)
{
    if (locks & TGL_LOCK_DIFF && !force) { return; }
    if (pts <= this->pts() && !force) { return; }
    m_pts = pts;
}

void tgl_state::set_date(int date, bool force)
{
    if (locks & TGL_LOCK_DIFF && !force) { return; }
    if (date <= m_date && !force) { return; }
    m_date = date;
}

void tgl_state::set_seq(int seq)
{
    if (locks & TGL_LOCK_DIFF) { return; }
    if (seq <= m_seq) { return; }
    m_seq = seq;
}

void tgl_state::reset_server_state()
{
    m_qts = 0;
    m_pts = 0;
    m_date = 0;
    m_seq = 0;
}

void tgl_state::add_rsa_key(const std::string& key)
{
    m_rsa_key_list.push_back(std::unique_ptr<tgl_rsa_key>(new tgl_rsa_key(key)));
}

int tgl_state::init(const std::string &&download_dir, int app_id, const std::string &app_hash, const std::string &app_version)
{
  m_download_manager = std::make_shared<tgl_download_manager>(download_dir);
  m_app_id = app_id;
  m_app_hash = app_hash;
  m_app_version = app_version;
  assert(m_timer_factory);
  assert(m_connection_factory);
  if (!temp_key_expire_time) {
    temp_key_expire_time = 100000;
  }

  if (tglmp_on_start () < 0) {
    return -1;
  }

  if (!m_app_id) {
    m_app_id = TG_APP_ID;
    m_app_hash = tstrdup (TG_APP_HASH);
  }
  return 0;
}

int tgl_authorized_dc(const std::shared_ptr<tgl_dc>& DC) {
  assert (DC);
  return DC->flags & TGLDCF_AUTHORIZED;
}

int tgl_signed_dc(const std::shared_ptr<tgl_dc>& DC) {
  assert (DC);
  return (DC->flags & TGLDCF_LOGGED_IN) != 0;
}

void tgl_state::set_enable_pfs (bool val) {
  this->m_enable_pfs = val;
}

void tgl_state::set_test_mode (bool val) {
  this->m_test_mode = val;
}

void tgl_state::set_enable_ipv6 (bool val) {
  m_ipv6_enabled = val;
}

void tgl_state::set_error(std::string error, int error_code)
{
    m_error = error;
    m_error_code = error_code;
}

std::shared_ptr<tgl_secret_chat> tgl_state::secret_chat_for_id(int peer_id) const
{
    auto secret_chat_it = m_secret_chats.find(peer_id);
    if (secret_chat_it == m_secret_chats.end()) {
        return nullptr;
    }
    return secret_chat_it->second;
}

std::shared_ptr<tgl_secret_chat> tgl_state::ensure_secret_chat(const tgl_peer_id_t& peer_id)
{
    auto& secret_chat = m_secret_chats[tgl_get_peer_id(peer_id)];
    if (!secret_chat) {
        secret_chat = std::make_shared<tgl_secret_chat>();
        secret_chat->id = peer_id;
    }
    return secret_chat;
}

void tgl_state::add_secret_chat(const std::shared_ptr<tgl_secret_chat>& secret_chat)
{
    m_secret_chats[tgl_get_peer_id(secret_chat->id)] = secret_chat;
}
