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

    Copyright Ben Wiederhake 2015
*/

#pragma once

#include <openssl/rand.h>

namespace tgl {
namespace impl {

inline static void TGLC_rand_add(const void* buf, int num, double entropy)
{
    RAND_add(buf, num, entropy);
}

inline static int TGLC_rand_bytes(unsigned char* buf, int num)
{
    return RAND_bytes(buf, num);
}

inline static int TGLC_rand_pseudo_bytes(unsigned char* buf, int num)
{
    return RAND_pseudo_bytes(buf, num);
}

}
}
