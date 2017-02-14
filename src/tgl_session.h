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

#ifndef __TGL_SESSION_H__
#define __TGL_SESSION_H__

#include "tgl/tgl_timer.h"

#include <memory>
#include <set>
#include <stdint.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

class tgl_connection;
class tgl_timer;

struct worker {
    std::shared_ptr<tgl_connection> connection;
    std::shared_ptr<tgl_timer> live_timer;
    std::set<int64_t> work_load;
    explicit worker(const std::shared_ptr<tgl_connection>& c): connection(c) { }
};

struct tgl_session {
    int64_t session_id;
    int64_t last_msg_id;
    int32_t seq_no;
    int32_t received_messages;
    std::shared_ptr<worker> primary_worker;
    std::unordered_set<std::shared_ptr<worker>> secondary_workers;
    std::set<int64_t> ack_set;
    std::shared_ptr<tgl_timer> ev;
    tgl_session()
        : session_id(0)
        , last_msg_id(0)
        , seq_no(0)
        , received_messages(0)
        , ack_set()
        , ev()
    { }

    void clear();
};

#endif
