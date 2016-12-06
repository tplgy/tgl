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

    Copyright Topology LP 2016
*/

#ifndef __TGL_ONLINE_STATUS_H__
#define __TGL_ONLINE_STATUS_H__

#include <cassert>
#include <iostream>
#include <string>

enum class tgl_online_status
{
    not_online,
    wwan_online,
    non_wwan_online,
};

inline static std::string to_string(tgl_online_status status)
{
    switch (status) {
    case tgl_online_status::not_online:
        return "not_online";
    case tgl_online_status::wwan_online:
        return "wwan_online (a.k.a cellular online)";
    case tgl_online_status::non_wwan_online:
        return "non_wwan_online (a.k.a non-cellular online, e.g. WiFi online)";
    default:
        assert(false);
        return "unknown online status";
    }
}

inline static std::ostream& operator<<(std::ostream& os, tgl_online_status status)
{
    os << to_string(status);
    return os;
}

#endif
