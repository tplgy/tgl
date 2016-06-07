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
#ifndef __AUTO_H__
#define __AUTO_H__

#include <assert.h>
#include <stdlib.h>
#include <string.h>

struct tl_type_descr {
  unsigned name;
  const char *id;
  int params_num;
  long long params_types;
};

struct paramed_type {
  const struct tl_type_descr& type;
  const struct paramed_type* params;
};

#define NAME_ARRAY 0x89932ad9

#define TGL_UNUSED(x) (void)x;

#define TYPE_TO_PARAM(NAME) ((struct paramed_type) {.type = tl_type_## NAME, .params=0})
#define TYPE_TO_PARAM_1(NAME,PARAM1) ((struct paramed_type) {.type = tl_type_## NAME, .params=(struct paramed_type [1]){PARAM1}})
#define ODDP(x) (((long)(x)) & 1)
#define EVENP(x) (!ODDP(x))
#define INT2PTR(x) (struct paramed_type *)(long)(((long)x) * 2 + 1)
#define PTR2INT(x) ((((long)x) - 1) / 2)

static inline void *memdup (const void *d, int len) {
  assert (d || !len);
  if (!d) { return 0; }
  void *r = malloc(len);
  memcpy (r, d, len);
  return r;
}

#define DS_LVAL(x) ((x) ? *(x) : 0)
#define DS_STR(x) ((x) ? (x)->data : NULL), ((x) ? (x)->len : 0)
#define DS_CSTR(varname, x) char *varname = (char*)malloc((x ? x->len : 0) + 1); \
                            if (x) {memcpy(varname, x->data, x->len); varname[x->len]='\0';} \
                            else {varname[0]='\0';}
#define DS_RSTR(x) ((x) ? (x)->len : 0), ((x) ? (x)->data : NULL)
#define DS_STR_DUP(x) (char*)(memdup(((x) ? (x)->data : NULL), ((x) ? (x)->len + 1: 0)))
#define DS_BVAL(x) ((x) && ((x)->magic == CODE_bool_true))

void tgl_paramed_type_free (struct paramed_type *P);

#endif
