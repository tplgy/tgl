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

#include "tgl/tgl_log.h"

static tgl_log_function g_log_function;
static tgl_log_level g_log_level = tgl_log_level::level_notice;

void tgl_init_log(const tgl_log_function& log_function, tgl_log_level level)
{
    g_log_function = log_function;
    g_log_level = level;
}

void tgl_log(const std::string& str, tgl_log_level level)
{
    if (level <= g_log_level && g_log_function) {
        g_log_function(str, level);
    }
}

#if defined(__SIZEOF_INT128__)
std::ostream& operator<<(std::ostream& s, __int128 i)
{
    int32_t* i32s = (int32_t*)&i;
    s << *i32s << *(i32s + 1) << *(i32s + 2) << *(i32s + 3);
    return s;
}
#endif
