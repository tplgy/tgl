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
    Copyright Topology LP 2016-2017
*/

#pragma once

#include "query.h"
#include "tgl/tgl_log.h"
#include "tgl/tgl_message.h"

#include <functional>
#include <memory>
#include <string>
#include <vector>

struct msg_search_state {
    msg_search_state(const tgl_input_peer_t& id, int from, int to, int limit, int offset, const std::string &query) :
        id(id), from(from), to(to), limit(limit), offset(offset), query(query) {}
    std::vector<std::shared_ptr<tgl_message>> messages;
    tgl_input_peer_t id;
    int from;
    int to;
    int limit;
    int offset;
    int max_id = 0;
    std::string query;
    std::weak_ptr<user_agent> weak_user_agent;
};

class query_search_message: public query
{
public:
    query_search_message(const std::shared_ptr<msg_search_state>& state,
            const std::function<void(bool, const std::vector<std::shared_ptr<tgl_message>>&)>& callback);
    virtual void on_answer(void* D) override;
    virtual int on_error(int error_code, const std::string& error_string) override;

private:
    std::shared_ptr<msg_search_state> m_state;
    std::function<void(bool, const std::vector<std::shared_ptr<tgl_message>>&)> m_callback;
};

//FIXME: better organize this.
void tgl_do_msg_search(const std::shared_ptr<msg_search_state>& state,
        const std::function<void(bool, const std::vector<std::shared_ptr<tgl_message>>&)>& callback);
