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
    Copyright Topology LP 2016-2017
*/

#include "download_task.h"

#include "auto/constants.h"
#include "crypto/tgl_crypto_md5.h"

#include <cstring>

download_task::download_task(int64_t id, int32_t size, const tgl_file_location& location)
    : id(id)
    , offset(0)
    , size(size)
    , type(0)
    , fd(-1)
    , location(location)
    , status(tgl_download_status::waiting)
    , iv()
    , key()
    , valid(true)
{
}

download_task::download_task(int64_t id, const std::shared_ptr<tgl_document>& document)
    : id(id)
    , offset(0)
    , size(document->size)
    , type(0)
    , fd(-1)
    , location()
    , status(tgl_download_status::waiting)
    , iv()
    , key()
    , valid(true)
{
    location.set_dc(document->dc_id);
    location.set_local_id(0);
    location.set_secret(document->access_hash);
    location.set_volume(document->id);
    init_from_document(document);
}

download_task::~download_task()
{
    memset(iv.data(), 0, iv.size());
    memset(key.data(), 0, key.size());
}

void download_task::init_from_document(const std::shared_ptr<tgl_document>& document)
{
    if (document->is_encrypted()) {
        type = CODE_input_encrypted_file_location;
        auto encr_document = std::static_pointer_cast<tgl_encr_document>(document);
        iv = std::move(encr_document->iv);
        key = std::move(encr_document->key);
        unsigned char md5[16];
        unsigned char str[64];
        memcpy(str, key.data(), 32);
        memcpy(str + 32, iv.data(), 32);
        TGLC_md5(str, 64, md5);
        if (encr_document->key_fingerprint != ((*(int *)md5) ^ (*(int *)(md5 + 4)))) {
            valid = false;
            return;
        }
        return;
    }

    switch (document->type) {
    case tgl_document_type::audio:
        type = CODE_input_audio_file_location;
        break;
    case tgl_document_type::video:
        type = CODE_input_video_file_location;
        break;
    default:
        type = CODE_input_document_file_location;
        break;
    }
}
