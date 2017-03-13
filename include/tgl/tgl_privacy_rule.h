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

#pragma once

#include <cassert>
#include <iostream>
#include <string>

enum class tgl_privacy_rule
{
    allow_contacts,
    allow_all,
    allow_users,
    disallow_contacts,
    disallow_all,
    disallow_users,
    unknown
};

inline static std::string to_string(tgl_privacy_rule rule)
{
    switch (rule) {
        case tgl_privacy_rule::allow_contacts:
            return "allow_contacts";
        case tgl_privacy_rule::allow_all:
            return "allow_all";
        case tgl_privacy_rule::allow_users:
            return "allow_users";
        case tgl_privacy_rule::disallow_contacts:
            return "disallow_contacts";
        case tgl_privacy_rule::disallow_all:
            return "disallow_all";
        case tgl_privacy_rule::disallow_users:
            return "disallow_users";
        default:
            assert(false);
            return "unknown privacy rule";
    }
}

inline static std::ostream& operator<<(std::ostream& os, tgl_privacy_rule rule)
{
    os << to_string(rule);
    return os;
}
