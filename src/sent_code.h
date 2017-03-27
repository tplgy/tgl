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

#include "auto/auto.h"
#include "auto/auto_types.h"
#include "auto/constants.h"
#include "tgl/tgl_value.h"

#include <cstdint>
#include <memory>
#include <string>

namespace tgl {
namespace impl {

struct sent_code
{
    explicit sent_code(const tl_ds_auth_sent_code*);
    bool registered = false;
    tgl_login_code_type type = tgl_login_code_type::unknown;
    tgl_login_code_type next_type = tgl_login_code_type::unknown;
    std::string hash;
    int32_t timeout = 0;
};

inline static tgl_login_code_type to_sent_code_type(uint32_t magic)
{
    switch (magic) {
    case CODE_auth_sent_code_type_app:
        return tgl_login_code_type::app;
    case CODE_auth_sent_code_type_sms:
        return tgl_login_code_type::sms;
    case CODE_auth_sent_code_type_call:
        return tgl_login_code_type::call;
    case CODE_auth_sent_code_type_flash_call:
        return tgl_login_code_type::flash_call;
    default:
        return tgl_login_code_type::unknown;
    }
}

inline static tgl_login_code_type to_next_code_type(uint32_t magic)
{
    switch (magic) {
    case CODE_auth_code_type_sms:
        return tgl_login_code_type::sms;
    case CODE_auth_code_type_call:
        return tgl_login_code_type::call;
    case CODE_auth_code_type_flash_call:
        return tgl_login_code_type::flash_call;
    default:
        return tgl_login_code_type::unknown;
    }
}

inline sent_code::sent_code(const tl_ds_auth_sent_code* DS_ASC)
{
    int32_t flags = DS_LVAL(DS_ASC->flags);
    registered = flags & (1 << 0);
    if (DS_ASC->type) {
        type = to_sent_code_type(DS_ASC->type->magic);
    }
    hash = DS_STDSTR(DS_ASC->phone_code_hash);
    if (flags & (1 << 1) && DS_ASC->next_type) {
        next_type = to_next_code_type(DS_ASC->next_type->magic);
    }
    if (flags & (1 << 2)) {
        timeout = DS_LVAL(DS_ASC->timeout);
    }
}

}
}
