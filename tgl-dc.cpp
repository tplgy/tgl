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

#include "tgl-dc.h"

#include "mtproto-client.h"
#include "queries.h"
#include "tgl-net.h"
#include "tgl-timer.h"

static const float SESSION_CLEANUP_TIMEOUT = 5.0;

void tglq_query_remove(std::shared_ptr<query> q);
bool send_pending_query(std::shared_ptr<query> q) {
    assert(q->DC);
    std::string name;
    double timeout;
    if (q->is_v2()) {
        auto q2 = std::static_pointer_cast<query_v2>(q);
        name = q2->name();
        timeout = q2->timeout_interval();
    } else {
        name = q->methods->name ? q->methods->name : "";
        timeout = q->methods->timeout;
    }

    if (!q->DC->auth_key_id || !q->DC->sessions[0]) {
        TGL_DEBUG("not ready to send pending query " << q << " (" << name << "), re-queuing");
        tglmp_dc_create_session(q->DC);
        q->DC->add_pending_query(q);
        return false;
    }
    if (!tgl_signed_dc(q->DC) && !(q->flags & QUERY_LOGIN)) {
        TGL_DEBUG("not ready to send pending non-login query " << q << " (" << name << "), re-queuing");
        q->DC->add_pending_query(q);
        return false;
    }

    q->flags &= ~QUERY_ACK_RECEIVED;
    tglq_query_remove(q);
    q->session = q->DC->sessions[0];
    q->msg_id = tglmp_encrypt_send_message (q->session->c, (int*)q->data, q->data_len, (q->flags & QUERY_FORCE_SEND) | 1);
    tgl_state::instance()->queries_tree.push_back(q);
    q->session_id = q->session->session_id;
    auto dc = q->session->dc.lock();
    if (dc && !(dc->flags & TGLDCF_CONFIGURED) && !(q->flags & QUERY_FORCE_SEND)) {
        q->session_id = 0;
    }

    TGL_DEBUG("Sending pending query \"" << name << "\" (" << q->msg_id << ") of size " << 4 * q->data_len << " to DC " << q->DC->id);

    q->ev->start(timeout ? timeout : DEFAULT_QUERY_TIMEOUT);

    return true;
}

tgl_dc::tgl_dc()
    : session_cleanup_timer(tgl_state::instance()->timer_factory()->create_timer(std::bind(&tgl_dc::cleanup_timer_expired, this)))
{
}

void tgl_dc::reset()
{
    TGL_DEBUG("resetting DC " << id);
    for (size_t i = 0; i < sessions.size(); ++i) {
        std::shared_ptr<tgl_session> session = sessions[i];
        if (session) {
            session->c->close();
            session->ev->cancel();
            session->c = nullptr;
            session->ev = nullptr;
            sessions[i] = nullptr;
        }
    }
    flags = 0;
    rsa_key_idx = 0;
    state = st_init;
    memset(auth_key, 0, 256);
    memset(temp_auth_key, 0, 256);
    memset(nonce, 0, 256);
    memset(new_nonce, 0, 256);
    memset(server_nonce, 0, 256);
    auth_key_id = 0;
    temp_auth_key_id = 0;
    server_salt = 0;
}

void tgl_dc::send_pending_queries() {
    TGL_NOTICE("sending pending queries for DC " << id);
    std::list<std::shared_ptr<query>> queries = pending_queries; // make a copy since queries can get re-enqueued
    for (std::shared_ptr<query> q : queries) {
        if (send_pending_query(q)) {
            pending_queries.remove(q);
        } else {
            TGL_DEBUG("sending pending query failed for DC " << id);
        }
    }
}

void tgl_dc::add_query(std::shared_ptr<query> q) {
    active_queries.push_back(q);
    session_cleanup_timer->cancel();
}

void tgl_dc::remove_query(std::shared_ptr<query> q) {
    active_queries.remove(q);

    if (active_queries.empty() && pending_queries.empty() && tgl_state::instance()->DC_working.get() != this) {
        session_cleanup_timer->start(SESSION_CLEANUP_TIMEOUT);
    }
}

void tgl_dc::add_pending_query(std::shared_ptr<query> q) {
    pending_queries.push_back(q);
}

void tgl_dc::remove_pending_query(std::shared_ptr<query> q) {
    pending_queries.remove(q);
}

void tgl_dc::cleanup_timer_expired() {
    if (active_queries.empty() && pending_queries.empty()) {
        TGL_DEBUG("cleanup timer expired for DC " << id << ", deleting sessions");
        for (size_t i = 0; i < sessions.size(); ++i) {
            std::shared_ptr<tgl_session> session = sessions[i];
            if (session) {
                session->c->close();
                session->ev->cancel();
                session->c = nullptr;
                session->ev = nullptr;
                sessions[i] = nullptr;
            }
        }
    }
}
