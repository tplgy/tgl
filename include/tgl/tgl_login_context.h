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

#include <cstdint>

enum class tgl_login_code_type {
    unknown,
    app,
    sms,
    call,
    flash_call,
};

class tgl_login_context
{
public:
    virtual tgl_login_code_type sent_code_type() const = 0;
    virtual tgl_login_code_type next_code_type() const = 0;
    virtual int32_t call_for_login_code_timeout() const = 0;
    virtual ~tgl_login_context() { }
};
