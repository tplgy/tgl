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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <zlib.h>
#include <time.h>
#include <sys/time.h>

#include "tools.h"
#include "mtproto-common.h"

#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach.h>
#endif

#ifdef __MACH__
#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
#endif

#ifdef VALGRIND_FIXES
#include "valgrind/memcheck.h"
#endif

int tgl_snprintf (char *buf, int len, const char *format, ...) {
  va_list ap;
  va_start (ap, format);
  int r = vsnprintf (buf, len, format, ap);
  va_end (ap);
  assert (r <= len && "tsnprintf buffer overflow");
  return r;
}

char *tgl_strdup (const char *s) {
  int l = strlen (s);
  char *p = (char*)malloc (l + 1);
  memcpy (p, s, l + 1);
  return p;
}

char *tgl_strndup (const char *s, size_t n) {
  size_t l = 0;
  for (l = 0; l < n && s[l]; l++) { }
  char *p = (char*)malloc (l + 1);
  memcpy (p, s, l);
  p[l] = 0;
  return p;
}

void *tgl_memdup (const void *s, size_t n) {
  void *r = malloc (n);
  memcpy (r, s, n);
  return r;
}

int tgl_inflate (void *input, int ilen, void *output, int olen) {
  z_stream strm;
  memset (&strm, 0, sizeof (strm));
  assert (inflateInit2 (&strm, 16 + MAX_WBITS) == Z_OK);
  strm.avail_in = ilen;
  strm.next_in = (Bytef*)input;
  strm.avail_out = olen ;
  strm.next_out = (Bytef*)output;
  int err = inflate (&strm, Z_FINISH); 
  int total_out = strm.total_out;

  if (err != Z_OK && err != Z_STREAM_END) {
    fprintf(stderr, "inflate error = %d\n", err);
    fprintf(stderr, "inflated %d bytes\n", (int) strm.total_out);
    total_out = 0;
  }
  inflateEnd (&strm);
  return total_out;
}

double tglt_get_double_time (void) {
  struct timespec tv;
  tgl_my_clock_gettime (CLOCK_REALTIME, &tv);
  return tv.tv_sec + 1e-9 * tv.tv_nsec;
}

void tglt_secure_random (unsigned char *s, int l) {
  if (RAND_bytes (s, l) <= 0) {
    /*if (allow_weak_random) {
      RAND_pseudo_bytes (s, l);
    } else {*/
      assert (0 && "End of random. If you want, you can start with -w");
    //}
  } else {
    #ifdef VALGRIND_FIXES
      VALGRIND_MAKE_MEM_DEFINED (s, l);
      VALGRIND_CHECK_MEM_IS_DEFINED (s, l);
    #endif
  }
}
