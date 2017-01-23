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

#include "crypto/tgl_crypto_err.h"

#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <random>

int tgl_inflate(const void* input, int ilen, void* output, int olen);

static inline void check_crypto_result(int r)
{
    if (!r) {
        fprintf(stderr, "crypto error\n");
        TGLC_err_print_errors_fp(stderr);
        assert(0);
    }
}

template<typename IntegerType>
static inline IntegerType tgl_random()
{
#ifdef VALGRIND_FIXES
    static bool seed = false;
    if (!seed) {
        seed = true;
        srand(time(nullptr));
    }
    return static_cast<IntegerType>(rand());
#else
    static std::random_device device;
    static std::mt19937 generator(device());
    static std::uniform_int_distribution<IntegerType> distribution(std::numeric_limits<IntegerType>::min(),
            std::numeric_limits<IntegerType>::max());

    return distribution(generator);
#endif
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

static inline std::string tgl_binary_to_hex(const char* buffer, size_t length)
{
    assert(buffer);
    assert(length);

    static const char table[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    std::vector<char> result(length * 2);

    size_t j = 0;
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = buffer[i];
        result[j++] = table[c >> 4];
        result[j++] = table[c & 0xf];
    }

    return std::string(result.data(), result.size());
}

#endif
