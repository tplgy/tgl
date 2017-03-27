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

    Copyright Topology LP 2017
*/

#include "sent_code.h"
#include "tgl/tgl_login_context.h"
#include "tgl/tgl_value.h"

#include <memory>
#include <string>

namespace tgl {
namespace impl {

struct login_context: public tgl_login_context
{
    virtual tgl_login_code_type sent_code_type() const override
    {
        return sent_code ? sent_code->type : tgl_login_code_type::unknown;
    }

    virtual tgl_login_code_type next_code_type() const override
    {
        return sent_code ? sent_code->next_type : tgl_login_code_type::unknown;
    }

    virtual int32_t call_for_login_code_timeout() const override
    {
        return sent_code ? sent_code->timeout : 0;
    }

    explicit login_context(const std::string& phone_number): phone(phone_number) { }

    bool register_user = false;
    std::unique_ptr<struct sent_code> sent_code;
    tgl_login_action action = tgl_login_action::none;
    std::string phone;
    std::string code;
    std::string first_name;
    std::string last_name;
};

}
}
