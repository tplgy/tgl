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

#include "tgl-log.h"

log_function registered_logfunction = 0;
std::stringstream str_stream;
int g_severity = E_NOTICE;

void init_tgl_log(log_function log_f, int s)
{
    registered_logfunction = log_f;
    g_severity = s;
}

void tgl_log(const std::string& str, int severity)
{
    if (severity <= g_severity) {
        if (registered_logfunction) {
            registered_logfunction(str, severity);
        }
    }
}

#if defined(__SIZEOF_INT128__)
std::ostream& operator<<(std::ostream& s, __int128 i)
{
    int32_t *i32s = (int32_t*)&i;
    s << *i32s << *(i32s + 1) << *(i32s + 2) << *(i32s + 3);
    return s;
}
#endif
