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
#include "crypto/rand.h"
#include <zlib.h>
#include <time.h>
#include <sys/time.h>

#include "tools.h"

extern "C" {
#include "mtproto-common.h"
}

#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach.h>
#endif

#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
#endif

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
int vasprintf(char ** __restrict__ ret,
                      const char * __restrict__ format,
                      va_list ap) {
  int len;
  /* Get Length */
  len = _vsnprintf(NULL,0,format,ap);
  if (len < 0) return -1;
  /* +1 for \0 terminator. */
  *ret = malloc(len + 1);
  /* Check malloc fail*/
  if (!*ret) return -1;
  /* Write String */
  _vsnprintf(*ret,len+1,format,ap);
  /* Terminate explicitly */
  (*ret)[len] = '\0';
  return len;
}

int clock_gettime(int ignored, struct timespec *spec)      
{
  __int64 wintime;
  GetSystemTimeAsFileTime((FILETIME*)&wintime);
  wintime      -= 116444736000000000;  //1jan1601 to 1jan1970
  spec->tv_sec  = wintime / 10000000;           //seconds
  spec->tv_nsec = wintime % 10000000 *100;      //nano-seconds
  return 0;
}
#endif

#ifdef VALGRIND_FIXES
#include "valgrind/memcheck.h"
#endif

void logprintf (const char *format, ...) __attribute__ ((format (printf, 1, 2), weak));
void logprintf (const char *format, ...) {
  va_list ap;
  va_start (ap, format);
  vfprintf (stdout, format, ap);
  va_end (ap);
}

int tgl_snprintf (char *buf, int len, const char *format, ...) {
  va_list ap;
  va_start (ap, format);
  int r = vsnprintf (buf, len, format, ap);
  va_end (ap);
  assert (r <= len && "tsnprintf buffer overflow");
  return r;
}

int tgl_asprintf (char **res, const char *format, ...) {
  va_list ap;
  va_start (ap, format);
  int r = vasprintf (res, format, ap);
  assert (r >= 0);
  va_end (ap);
  char *rs = (char *)talloc (strlen (*res) + 1);
  memcpy (rs, *res, strlen (*res) + 1);
  free (*res);
  *res = rs;
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
    logprintf ( "inflate error = %d\n", err);
    logprintf ( "inflated %d bytes\n", (int) strm.total_out);
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
  if (TGLC_rand_bytes (s, l) <= 0) {
    /*if (allow_weak_random) {
      TGLC_rand_pseudo_bytes (s, l);
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
