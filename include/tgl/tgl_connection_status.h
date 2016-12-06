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

#ifndef __TGL_CONNECTION_STATUS_H__
#define __TGL_CONNECTION_STATUS_H__

#include <cassert>
#include <iostream>
#include <string>

enum class tgl_connection_status {
    disconnected,
    connecting,
    connected,
};

inline static std::string to_string(tgl_connection_status status)
{
    switch (status) {
    case tgl_connection_status::disconnected:
        return "disconnected";
    case tgl_connection_status::connecting:
        return "connecting";
    case tgl_connection_status::connected:
        return "connected";
    default:
        assert(false);
        return "unknown connection status";
    }
}

inline static std::ostream& operator<<(std::ostream& os, tgl_connection_status status)
{
    os << to_string(status);
    return os;
}

#endif
