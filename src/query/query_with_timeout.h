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

#pragma once

#include "query.h"

#include <cassert>

namespace tgl {
namespace impl {

class query_with_timeout: public query
{
public:
    query_with_timeout(user_agent& ua, const std::string& name, double timeout_seconds, const paramed_type& type)
        : query(ua, name, type)
        , m_timeout_seconds(timeout_seconds)
    {
        assert(m_timeout_seconds > 0);
    }

    virtual double timeout_interval() const override { return m_timeout_seconds; }
    virtual bool should_retry_on_timeout() const override { return false; }
    virtual void will_be_pending() override { timeout_within(timeout_interval()); }
    virtual void on_timeout() override = 0;

private:
    double m_timeout_seconds;
};

}
}
