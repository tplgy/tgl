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
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tools.h"

#include "crypto/tgl_crypto_rand.h"
#include "tgl/tgl_log.h"
#include "tgl/tgl_secure_random.h"

#ifdef VALGRIND_FIXES
#include "valgrind/memcheck.h"
#endif

#include <zlib.h>

int tgl_inflate(const void* input, int ilen, void* output, int olen)
{
    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    if (inflateInit2(&strm, 16 + MAX_WBITS) != Z_OK) {
        TGL_ERROR("failed to call inflateInit2");
        return 0;
    }
    strm.avail_in = ilen;
    strm.next_in = (Bytef*)input;
    strm.avail_out = olen ;
    strm.next_out = (Bytef*)output;
    int err = inflate(&strm, Z_FINISH);
    int total_out = strm.total_out;

    if (err != Z_OK && err != Z_STREAM_END) {
        TGL_ERROR("inflate error = " << err << ", inflated " << strm.total_out << " bytes");
        total_out = 0;
    }
    inflateEnd(&strm);
    return total_out;
}

void tgl_secure_random(unsigned char* s, int l)
{
    if (TGLC_rand_bytes(s, l) <= 0) {
        /*if (allow_weak_random) {
          TGLC_rand_pseudo_bytes(s, l);
        } else {*/
            assert(0 && "End of random. If you want, you can start with -w");
        //}
    } else {
#ifdef VALGRIND_FIXES
        VALGRIND_MAKE_MEM_DEFINED(s, l);
        VALGRIND_CHECK_MEM_IS_DEFINED(s, l);
#endif
    }
}
