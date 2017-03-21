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

#include <functional>
#include <memory>
#include <string>

namespace tgl {
namespace impl {

class user;

class query_sign_in: public query
{
public:
    query_sign_in(user_agent& ua, const std::function<void(bool, const std::shared_ptr<user>&)>& callback);
    std::shared_ptr<query_sign_in> shared_from_this() { return std::static_pointer_cast<query_sign_in>(query::shared_from_this()); }
    virtual void on_answer(void* D) override;
    virtual int on_error(int error_code, const std::string& error_string) override;
    virtual void on_timeout() override;
    virtual double timeout_interval() const override;
    virtual bool should_retry_on_timeout() const override;
    virtual void will_be_pending() override;

private:
    virtual bool handle_session_password_needed(bool& should_retry) override;

private:
    std::function<void(bool, const std::shared_ptr<user>&)> m_callback;
};

}
}
