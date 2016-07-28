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
#include <assert.h>
#include <limits>
#include <random>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "crypto/err.h"
#include "crypto/rand.h"

int tgl_inflate(void* input, int ilen, void* output, int olen);

static inline void ensure(int r)
{
    if (!r) {
        fprintf (stderr, "Crypto error\n");
        TGLC_err_print_errors_fp (stderr);
        assert (0);
    }
}

void tglt_secure_random(unsigned char* s, int l);

void tgl_my_clock_gettime(int clock_id, struct timespec* T);

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

#endif
