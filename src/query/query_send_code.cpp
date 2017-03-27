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

#include "query_send_code.h"

#include "auto/auto.h"
#include "auto/auto_types.h"
#include "auto/constants.h"
#include "sent_code.h"

namespace tgl {
namespace impl {

void query_send_code::on_answer(void* D)
{
    if (m_callback) {
        m_callback(std::make_unique<sent_code>(static_cast<const tl_ds_auth_sent_code*>(D)));
    }
}

int query_send_code::on_error(int error_code, const std::string& error_string)
{
    TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
    if (m_callback) {
        m_callback(nullptr);
    }
    return 0;
}

void query_send_code::on_timeout()
{
    TGL_ERROR("timed out for query #" << msg_id() << " (" << name() << ")");
    if (m_callback) {
        m_callback(nullptr);
    }
}

double query_send_code::timeout_interval() const
{
    return 20;
}

bool query_send_code::should_retry_on_timeout() const
{
    return false;
}

void query_send_code::will_be_pending()
{
    timeout_within(timeout_interval());
}

}
}
