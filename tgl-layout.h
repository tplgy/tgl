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

#define TGLDF_IMAGE 1
#define TGLDF_STICKER 2
#define TGLDF_ANIMATED 4
#define TGLDF_AUDIO 8
#define TGLDF_VIDEO 16

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

#define TGLPF_CREATED (1 << 0)
#define TGLPF_CREATE 0x80000000
#define TGLPF_HAS_PHOTO (1 << 1)
#define TGLPF_DELETED (1 << 2)
#define TGLPF_OFFICIAL (1 << 3)
#define TGLPF_KICKED (1 << 4)
#define TGLPF_ADMIN (1 << 5)
#define TGLPF_CREATOR (1 << 6)
#define TGLPF_LEFT (1 << 7)
#define TGLPF_DEACTIVATED (1 << 8)

#define TGLUF_CONTACT (1 << 16)
#define TGLUF_MUTUAL_CONTACT (1 << 17)
#define TGLUF_BLOCKED (1 << 18)
#define TGLUF_SELF (1 << 19)
#define TGLUF_CREATED TGLPF_CREATED
#define TGLUF_DELETED TGLPF_DELETED
#define TGLUF_HAS_PHOTO TGLPF_HAS_PHOTO
#define TGLUF_CREATE TGLPF_CREATE
#define TGLUF_BOT (1 << 20)
#define TGLUF_OFFICIAL TGLPF_OFFICIAL

#define TGLUF_TYPE_MASK \
  (TGLUF_CONTACT | TGLUF_MUTUAL_CONTACT | TGLUF_BLOCKED | TGLUF_SELF | TGLUF_CREATED | TGLUF_DELETED | TGLUF_OFFICIAL)

#define TGLCF_CREATED TGLPF_CREATED
#define TGLCF_CREATE TGLPF_CREATE
#define TGLCF_HAS_PHOTO TGLPF_HAS_PHOTO
#define TGLCF_KICKED TGLPF_KICKED
#define TGLCF_CREATOR TGLPF_CREATOR
#define TGLCF_ADMIN TGLPF_ADMIN
#define TGLCF_OFFICIAL TGLPF_OFFICIAL
#define TGLCF_LEFT TGLPF_LEFT
#define TGLCF_DEACTIVATED TGLPF_DEACTIVATED
#define TGLCF_ADMINS_ENABLED (1 << 16)

#define TGLCF_TYPE_MASK \
  (TGLCF_CREATED | TGLCF_KICKED | TGLCF_CREATOR | TGLCF_ADMIN | TGLCF_OFFICIAL | TGLCF_LEFT | TGLCF_DEACTIVATED | TGLCF_ADMINS_ENABLED)

#define TGLECF_CREATED TGLPF_CREATED
#define TGLECF_CREATE TGLPF_CREATE
#define TGLECF_HAS_PHOTO TGLPF_HAS_PHOTO
#define TGLECF_KICKED TGLPF_KICKED
#define TGLECF_CREATOR TGLPF_CREATOR
#define TGLECF_ADMIN TGLPF_ADMIN

#define TGLECF_TYPE_MASK \
  (TGLECF_CREATED | TGLECF_KICKED | TGLECF_CREATOR | TGLECF_ADMIN)

#define TGLCHF_CREATED TGLPF_CREATED
#define TGLCHF_CREATE TGLPF_CREATE
#define TGLCHF_HAS_PHOTO TGLPF_HAS_PHOTO
#define TGLCHF_KICKED TGLPF_KICKED
#define TGLCHF_CREATOR TGLPF_CREATOR
#define TGLCHF_ADMIN TGLPF_ADMIN
#define TGLCHF_OFFICIAL TGLPF_OFFICIAL
#define TGLCHF_LEFT TGLPF_LEFT
#define TGLCHF_DEACTIVATED TGLPF_DEACTIVATED
#define TGLCHF_BROADCAST (1 << 16)
#define TGLCHF_EDITOR (1 << 17)
#define TGLCHF_MODERATOR (1 << 18)
#define TGLCHF_MEGAGROUP (1 << 19)

#define TGLCHF_TYPE_MASK \
  (TGLCHF_CREATED | TGLCHF_KICKED | TGLCHF_CREATOR | TGLCHF_ADMIN | TGLCHF_OFFICIAL | TGLCHF_LEFT | TGLCHF_DEACTIVATED | TGLCHF_BROADCAST | TGLCHF_EDITOR | TGLCHF_MODERATOR | TGLCHF_MEGAGROUP)


#define TGLCHF_DIFF 0x20000000

#define TGL_FLAGS_UNCHANGED 0x40000000

#endif
