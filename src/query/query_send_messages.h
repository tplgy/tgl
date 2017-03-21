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
#include "tgl/tgl_message.h"

#include <cstdint>
#include <memory>
#include <functional>
#include <string>
#include <vector>

namespace tgl {
namespace impl {

struct messages_send_extra {
    bool multi = false;
    int64_t id = 0;
    int count = 0;
    std::vector<int64_t> message_ids;
};

class query_send_messages: public query
{
public:
    query_send_messages(user_agent& ua, const std::shared_ptr<messages_send_extra>& extra,
            const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& single_callback);
    query_send_messages(user_agent& ua, const std::shared_ptr<messages_send_extra>& extra,
            const std::function<void(bool success, const std::vector<std::shared_ptr<tgl_message>>& messages)>& multi_callback);
    explicit query_send_messages(user_agent& ua, const std::function<void(bool)>& bool_callback);
    virtual void on_answer(void* D) override;
    virtual int on_error(int error_code, const std::string& error_string) override;
    void set_message(const std::shared_ptr<tgl_message>& message);

private:
    std::shared_ptr<messages_send_extra> m_extra;
    std::function<void(bool, const std::shared_ptr<tgl_message>&)> m_single_callback;
    std::function<void(bool, const std::vector<std::shared_ptr<tgl_message>>& messages)> m_multi_callback;
    std::function<void(bool)> m_bool_callback;
    std::shared_ptr<tgl_message> m_message;
};

}
}
