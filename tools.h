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

#ifndef __TOOLS_H__
#define __TOOLS_H__
#include <time.h>
#include <stdarg.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "crypto/err.h"
#include "crypto/rand.h"

#define talloc0(X) calloc(1,X)
#define talloc(x) malloc(x)
#define tfree(x, size) free(x)
#define tfree_str(x) free(x)
#define tfree_secure(x, size) free(x)
#define trealloc(x, old_size, size) realloc(x, size)
#define tstrdup tgl_strdup
#define tmemdup tgl_memdup
#define tstrndup tgl_strndup
#define tsnprintf tgl_snprintf


double tglt_get_double_time (void);

int tgl_inflate (void *input, int ilen, void *output, int olen);

static inline void ensure (int r) {
  if (!r) {
    fprintf (stderr, "Crypto error\n");
    TGLC_err_print_errors_fp (stderr);
    assert (0);
  }
}

static inline void ensure_ptr (void *p) {
  if (p == NULL) {
      fprintf(stderr, "Out of memory");
      exit (1);
  }
}

char *tgl_strdup (const char *s);
char *tgl_strndup (const char *s, size_t n);

void *tgl_memdup (const void *s, size_t n);

int tgl_snprintf (char *buf, int len, const char *format, ...) __attribute__ ((format (__printf__, 3, 4)));
int tgl_asprintf (char **res, const char *format, ...) __attribute__ ((format (__printf__, 2, 3)));

void tglt_secure_random (unsigned char *s, int l);


static inline void hexdump (void *ptr, void *end_ptr) {
  int total = 0;
  unsigned char *bptr = (unsigned char *)ptr;
  while (bptr < (unsigned char *)end_ptr) {
    fprintf (stderr, "%02x", (int)*bptr);
    bptr ++;
    total ++;
    if (total == 16) {
      fprintf (stderr, "\n");
      total = 0;
    }
  }
  if (total) { fprintf (stderr, "\n"); }
}

#endif
