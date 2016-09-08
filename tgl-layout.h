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
#ifndef __TGL_LAYOUT_H__
#define __TGL_LAYOUT_H__

#define TGLMF_UNREAD 1
#define TGLMF_OUT (1<<1)
#define TGLMF_DISABLE_PREVIEW (1<<2)
#define TGLMF_MENTION (1<<4)
#define TGLMF_CREATED (1 << 8)
#define TGLMF_PENDING (1 << 9)
#define TGLMF_DELETED (1 << 10)
#define TGLMF_ENCRYPTED (1 << 11)
#define TGLMF_EMPTY (1 << 12)
#define TGLMF_SERVICE (1 << 13)
#define TGLMF_SESSION_OUTBOUND (1 << 14)
#define TGLMF_TEMP_MSG_ID (1 << 15)
#define TGLMF_CREATE (1 << 16)
#define TGLMF_POST_AS_CHANNEL (1 << 17)
#define TGLMF_HTML (1 << 18)
#define TGLMF_SEND_FAILED (1 << 19)
#define TGLMF_HISTORY (1 << 20)

#endif
