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

    Copyright Vitaly Valtman 2014-2015
*/
#include <cassert>
#include <string>
#include <iostream>
#include <sstream>

#pragma once

#define E_ERROR 0
#define E_WARNING 1
#define E_NOTICE 2
#define E_DEBUG2 3
#define E_DEBUG 6

typedef void (*log_function)(const std::string& log, int severity);
void init_tgl_log(log_function, int severity);
void tgl_log(const std::string& str, int severity);


#define TGL_CRASH() do { *reinterpret_cast<int*>(0xbadbeef) = 0; abort(); } while (false)

#define TGL_DEBUG(X) do { std::stringstream str_stream; \
                    str_stream << X ; \
                    tgl_log(str_stream.str(), E_DEBUG);} while (false)

#define TGL_DEBUG2(X) do { std::stringstream str_stream; \
                    str_stream << X; \
                    tgl_log(str_stream.str(), E_DEBUG2);} while (false)

#define TGL_NOTICE(X) do { std::stringstream str_stream; \
                    str_stream << X; \
                    tgl_log(str_stream.str(), E_NOTICE);} while (false)

#define TGL_WARNING(X) do { std::stringstream str_stream; \
                    str_stream << __FILE__ <<  "(" << __LINE__ << "): " << X; \
                    tgl_log(str_stream.str(), E_WARNING);} while (false)

#define TGL_ERROR(X) do { std::stringstream str_stream; \
                    str_stream << __FILE__ <<  "(" << __LINE__ << "): " << X; \
                    tgl_log(str_stream.str(), E_ERROR);} while (false)


#define TGL_ASSERT(x) assert(x)
#define TGL_ASSERT_UNUSED(u, x) do { static_cast<void>(u); assert(x); } while (false)

#if defined(__SIZEOF_INT128__)
std::ostream& operator<<(std::ostream& s, __int128 i);
#endif
