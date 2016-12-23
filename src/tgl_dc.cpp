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

    Copyright Topology LP 2016
*/

#include "tgl/tgl_dc.h"

#include <algorithm>

#include "mtproto-client.h"
#include "queries.h"
#include "tgl/tgl_net.h"
#include "tgl/tgl_timer.h"
#include "tgl_session.h"

static constexpr float SESSION_CLEANUP_TIMEOUT = 5.0;

tgl_dc::tgl_dc()
    : id(0)
    , state(tgl_dc_state::init)
    , auth_key_id(0)
    , temp_auth_key_id(0)
    , temp_auth_key_bind_query_id(0)
    , server_salt(0)
    , server_time_delta(0)
    , server_time_udelta(0)
    , auth_transfer_in_process(false)
    , m_active_queries(0)
    , m_logout_query_id(0)
    , m_authorized(false)
    , m_logged_in(false)
    , m_configured(false)
    , m_bound(false)
    , m_session_cleanup_timer(tgl_state::instance()->timer_factory()->create_timer(std::bind(&tgl_dc::cleanup_timer_expired, this)))
    , m_rsa_key()
{
    memset(auth_key, 0, sizeof(auth_key));
    memset(temp_auth_key, 0, sizeof(temp_auth_key));
    memset(nonce, 0, sizeof(nonce));
    memset(new_nonce, 0, sizeof(new_nonce));
    memset(server_nonce, 0, sizeof(server_nonce));
}

tgl_dc::~tgl_dc()
{
}

void tgl_dc::reset_authorization()
{
    reset_temp_authorization();
    state = tgl_dc_state::init;
    memset(auth_key, 0, sizeof(auth_key));
    auth_key_id = 0;
    if (!m_pending_queries.empty()) {
        send_pending_queries();
    }
}

void tgl_dc::reset_temp_authorization()
{
    if (temp_auth_key_bind_query_id) {
        tglq_query_delete(temp_auth_key_bind_query_id);
        temp_auth_key_bind_query_id = 0;
    }
    m_rsa_key = nullptr;
    memset(temp_auth_key, 0, sizeof(temp_auth_key));
    memset(nonce, 0, sizeof(nonce));
    memset(new_nonce, 0, sizeof(new_nonce));
    memset(server_nonce, 0, sizeof(server_nonce));
    temp_auth_key_id = 0;
    server_salt = 0;
    set_configured(false);
    set_bound(false);
}

void tgl_dc::send_pending_queries()
{
    std::list<std::shared_ptr<query>> queries = m_pending_queries; // make a copy since queries can get re-enqueued
    for (std::shared_ptr<query> q : queries) {
        if (q->execute_after_pending()) {
            m_pending_queries.remove(q);
        } else {
            TGL_DEBUG("sending pending query failed for DC " << id);
        }
    }
}

void tgl_dc::increase_active_queries(size_t num)
{
    m_active_queries += num;
    m_session_cleanup_timer->cancel();
}

void tgl_dc::decrease_active_queries(size_t num)
{
    if (m_active_queries >= num) {
        m_active_queries -= num;
    }

    if (!m_active_queries && m_pending_queries.empty() && tgl_state::instance()->working_dc().get() != this) {
        m_session_cleanup_timer->start(SESSION_CLEANUP_TIMEOUT);
    }
}

void tgl_dc::add_pending_query(const std::shared_ptr<query>& q)
{
    if (std::find(m_pending_queries.cbegin(), m_pending_queries.cend(), q) == m_pending_queries.cend()) {
        m_pending_queries.push_back(q);
    }
}

void tgl_dc::remove_pending_query(const std::shared_ptr<query>& q)
{
    m_pending_queries.remove(q);
}

void tgl_dc::cleanup_timer_expired()
{
    if (!m_active_queries && m_pending_queries.empty()) {
        TGL_DEBUG("cleanup timer expired for DC " << id << ", deleting session");
        if (session) {
            session->clear();
            session = nullptr;
        }
    }
}
