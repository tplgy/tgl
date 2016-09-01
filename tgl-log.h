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
    Copyright Topology LP 2016
*/

#ifndef __TGL_LOG_H__
#define __TGL_LOG_H__

#include <cassert>
#include <functional>
#include <iostream>
#include <string>
#include <sstream>

enum class tgl_log_level {
    level_error = 0,
    level_warning = 1,
    level_notice = 2,
    level_debug = 6,
};

using tgl_log_function = std::function<void(const std::string& log, tgl_log_level level)>;
void tgl_init_log(const tgl_log_function& log_function, tgl_log_level level);
void tgl_log(const std::string& str, tgl_log_level level);

#define TGL_CRASH() do { *reinterpret_cast<int*>(0xbadbeef) = 0; abort(); } while (false)

#ifndef NDEBUG
#define TGL_DEBUG(X) do { std::ostringstream str_stream; \
                    str_stream << "[" << __FILE__ << ":" << __LINE__ << "] [" << __FUNCTION__ << "]" << X ; \
                    tgl_log(str_stream.str(), tgl_log_level::level_debug);} while (false)
#else
#define TGL_DEBUG(X)
#endif

#define TGL_NOTICE(X) do { std::ostringstream str_stream; \
                    str_stream << "[" << __FILE__ << ":" << __LINE__ << "] [" << __FUNCTION__ << "]" << X ; \
                    tgl_log(str_stream.str(), tgl_log_level::level_notice);} while (false)

#define TGL_WARNING(X) do { std::ostringstream str_stream; \
                    str_stream << "[" << __FILE__ << ":" << __LINE__ << "] [" << __FUNCTION__ << "]" << X ; \
                    tgl_log(str_stream.str(), tgl_log_level::level_warning);} while (false)

#define TGL_ERROR(X) do { std::ostringstream str_stream; \
                    str_stream << "[" << __FILE__ << ":" << __LINE__ << "] [" << __FUNCTION__ << "]" << X ; \
                    tgl_log(str_stream.str(), tgl_log_level::level_error);} while (false)


#define TGL_ASSERT(x) assert(x)
#define TGL_ASSERT_UNUSED(u, x) do { static_cast<void>(u); assert(x); } while (false)

#if defined(__SIZEOF_INT128__)
std::ostream& operator<<(std::ostream& s, __int128 i);
#endif

#endif
