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

    Copyright Vitaly Valtman 2013-2015
    Copyright Topology LP 2016
*/

#ifndef __TOOLS_H__
#define __TOOLS_H__

#include "crypto/err.h"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <limits>
#include <random>

int tgl_inflate(void* input, int ilen, void* output, int olen);

static inline void check_crypto_result(int r)
{
    if (!r) {
        fprintf(stderr, "crypto error\n");
        TGLC_err_print_errors_fp(stderr);
        assert(0);
    }
}

void tglt_secure_random(unsigned char* s, int l);

template<typename IntegerType>
static inline IntegerType tgl_random()
{
    static std::random_device device;
    static std::mt19937 generator(device());
    static std::uniform_int_distribution<IntegerType> distribution(std::numeric_limits<IntegerType>::min(),
            std::numeric_limits<IntegerType>::max());

    return distribution(generator);
}

static inline void tgl_secure_free(void* ptr, size_t size)
{
    memset(ptr, 0, size);
    free(ptr);
}

static inline double tgl_get_system_time()
{
    return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count() * 1e-9;
}

static inline double tgl_get_monotonic_time()
{
    return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count() * 1e-9;
}

#endif
