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

#include <cstdint>
#include <memory>
#include <functional>
#include <string>
#include <vector>

namespace tgl {
namespace impl {

class message;

class query_send_messages: public query
{
public:
    explicit query_send_messages(user_agent& ua, const std::function<void(bool)>& callback);
    virtual void on_answer(void* D) override;
    virtual int on_error(int error_code, const std::string& error_string) override;
    void set_message(const std::shared_ptr<class message>& message);

private:
    std::function<void(bool)> m_callback;
    std::shared_ptr<message> m_message;
};

}
}
