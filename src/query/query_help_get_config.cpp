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

#include "query_help_get_config.h"

#include "auto/auto-fetch-ds.h"
#include "queries.h"

query_help_get_config::query_help_get_config(const std::function<void(bool)>& callback)
    : query("get config", TYPE_TO_PARAM(config))
    , m_callback(callback)
{
}

void query_help_get_config::on_answer(void* DS)
{
    tl_ds_config* DS_C = static_cast<tl_ds_config*>(DS);

    bool success = true;
    if (auto ua = get_user_agent()) {
        int32_t count = DS_LVAL(DS_C->dc_options->cnt);
        for (int32_t i = 0; i < count; ++i) {
            ua->fetch_dc_option(DS_C->dc_options->data[i]);
        }
    } else {
        success = false;
    }

    int max_chat_size = DS_LVAL(DS_C->chat_size_max);
    int max_bcast_size = 0; //DS_LVAL(DS_C->broadcast_size_max);
    TGL_DEBUG("chat_size = " << max_chat_size << ", bcast_size = " << max_bcast_size);

    if (m_callback) {
        m_callback(success);
    }
}

int query_help_get_config::on_error(int error_code, const std::string& error_string)
{
    TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
    if (m_callback) {
        m_callback(false);
    }
    return 0;
}

double query_help_get_config::timeout_interval() const
{
    return 1;
}
