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

#ifndef __TGL_TYPING_STATUS_H__
#define __TGL_TYPING_STATUS_H__

enum tgl_typing_status {
    tgl_typing_none,
    tgl_typing_typing,
    tgl_typing_cancel,
    tgl_typing_record_video,
    tgl_typing_upload_video,
    tgl_typing_record_audio,
    tgl_typing_upload_audio,
    tgl_typing_upload_photo,
    tgl_typing_upload_document,
    tgl_typing_geo,
    tgl_typing_choose_contact
};

#endif
