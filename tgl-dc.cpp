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
    if (!q->DC->auth_key_id || !q->DC->sessions[0]) {
        TGL_WARNING("not ready to send pending query " << q << ", re-queuing");
        tglmp_dc_create_session(q->DC);
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

    TGL_DEBUG("Sending pending query \"" << (q->methods->name ? q->methods->name : "") << "\" (" << q->msg_id << ") of size " << 4 * q->data_len << " to DC " << q->DC->id);

    q->ev->start(q->methods->timeout ? q->methods->timeout : DEFAULT_QUERY_TIMEOUT);

    return true;
}

tgl_dc::tgl_dc()
    : session_cleanup_timer(tgl_state::instance()->timer_factory()->create_timer(std::bind(&tgl_dc::cleanup_timer_expired, this)))
{
}

void tgl_dc::send_pending_queries() {
    TGL_NOTICE("sending pending queries for DC " << id);
    while (!pending_queries.empty()) {
        std::shared_ptr<query> q = pending_queries.front();
        pending_queries.pop_front();
        if (!send_pending_query(q)) {
            TGL_ERROR("sending pending query failed for DC " << id);
            break;
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
