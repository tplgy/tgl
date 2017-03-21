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

namespace tgl {
namespace impl {

class query_get_history: public query
{
public:
    query_get_history(user_agent& ua, const tgl_input_peer_t& id, int limit, int offset, int max_id,
            const std::function<void(bool, const std::vector<std::shared_ptr<tgl_message>>&)>& callback);
    virtual void on_answer(void* D) override;
    virtual int on_error(int error_code, const std::string& error_string) override;

private:
    std::vector<std::shared_ptr<tgl_message>> m_messages;
    tgl_input_peer_t m_id;
#if 0
    int m_limit;
    int m_offset;
    int m_max_id;
#endif
    std::function<void(bool, const std::vector<std::shared_ptr<tgl_message>>&)> m_callback;
};

}
}
