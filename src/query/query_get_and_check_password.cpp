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

#include "query_get_and_check_password.h"

#include "tgl/tgl_update_callback.h"

query_get_and_check_password::query_get_and_check_password(const std::function<void(const tl_ds_account_password*)>& callback)
    : query("get and check password", TYPE_TO_PARAM(account_password))
    , m_callback(callback)
{ }

void query_get_and_check_password::on_answer(void* D)
{
    if (m_callback) {
        m_callback(static_cast<tl_ds_account_password*>(D));
    }
}

int query_get_and_check_password::on_error(int error_code, const std::string& error_string)
{
    TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
    if (m_callback) {
        m_callback(nullptr);
    }
    return 0;
}
