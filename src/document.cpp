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
    Copyright Topology LP 2016-2017
*/

#include "document.h"

#include "auto/auto.h"
#include "auto/auto_skip.h"
#include "auto/auto_types.h"
#include "auto/auto_free_ds.h"
#include "auto/auto_fetch_ds.h"
#include "auto/constants.h"
#include "photo.h"
#include "tools.h"

#include <algorithm>
#include <cassert>
#include <cctype>
#include <cstring>

inline static void str_to_32(unsigned char* dst, const char* src, int src_len)
{
    if (src_len >= 32) {
        memcpy(dst, src + src_len - 32, 32);
    } else {
        memset(dst, 0, 32 - src_len);
        memcpy(dst + 32 - src_len, src, src_len);
    }
}

namespace tgl {
namespace impl {

document::document()
    : m_id(0)
    , m_access_hash(0)
    , m_date(0)
    , m_size(0)
    , m_dc_id(0)
    , m_width(0)
    , m_height(0)
    , m_duration(0)
    , m_type(tgl_document_type::unknown)
    , m_is_animated(false)
    , m_thumb_width(0)
    , m_thumb_height(0)
    , m_key_fingerprint(0)
{
}

document::document(const tl_ds_document* DS_D)
    : document()
{
    if (!DS_D) {
        return;
    }

    if (DS_D->magic == CODE_document_empty) {
        return;
    }

    m_id = DS_LVAL(DS_D->id);
    m_access_hash = DS_LVAL(DS_D->access_hash);
    m_date = DS_LVAL(DS_D->date);
    m_mime_type = DS_STDSTR(DS_D->mime_type);
    m_size = DS_LVAL(DS_D->size);
    m_dc_id = DS_LVAL(DS_D->dc_id);

    if (DS_D->thumb && DS_D->thumb->magic != CODE_photo_size_empty) {
        m_thumb = create_photo_size(DS_D->thumb);
    }

    if (DS_D->attributes) {
        int32_t n = DS_LVAL(DS_D->attributes->cnt);
        for (int32_t i = 0; i < n; i++) {
            init_attribute(DS_D->attributes->data[i]);
        }
    }
}

document::document(const tl_ds_audio* DS_A)
    : document()
{
    if (!DS_A) {
        return;
    }

    if (DS_A->magic == CODE_audio_empty) {
        return;
    }

    m_id = DS_LVAL(DS_A->id);
    m_type = tgl_document_type::audio;
    m_access_hash = DS_LVAL(DS_A->access_hash);
    m_date = DS_LVAL(DS_A->date);
    m_duration = DS_LVAL(DS_A->duration);
    m_mime_type = DS_STDSTR(DS_A->mime_type);
    m_size = DS_LVAL(DS_A->size);
    m_dc_id = DS_LVAL(DS_A->dc_id);
}

document::document(const tl_ds_video* DS_V)
    : document()
{
    if (!DS_V) {
        return;
    }

    if (DS_V->magic == CODE_video_empty) {
        return;
    }

    m_id = DS_LVAL(DS_V->id);
    m_type = tgl_document_type::video;
    m_access_hash = DS_LVAL(DS_V->access_hash);
    m_date = DS_LVAL(DS_V->date);
    m_duration = DS_LVAL(DS_V->duration);
    m_mime_type = DS_STDSTR(DS_V->mime_type);
    if (m_mime_type.empty()) {
        m_mime_type = "video/";
    }
    m_size = DS_LVAL(DS_V->size);

    if (DS_V->thumb && DS_V->thumb->magic != CODE_photo_size_empty) {
        m_thumb = create_photo_size(DS_V->thumb);
    }

    m_dc_id = DS_LVAL(DS_V->dc_id);
    m_width = DS_LVAL(DS_V->w);
    m_height = DS_LVAL(DS_V->h);
}

document::document(const tl_ds_decrypted_message_media* DS_DMM)
    : document()
{
    if (!(DS_DMM->magic == CODE_decrypted_message_media_photo
            || DS_DMM->magic == CODE_decrypted_message_media_video
            || DS_DMM->magic == CODE_decrypted_message_media_video_l12
            || DS_DMM->magic == CODE_decrypted_message_media_document
            || DS_DMM->magic == CODE_decrypted_message_media_audio))
    {
        assert(false);
        return;
    }

    if (DS_DMM->mime_type && DS_DMM->mime_type->data) {
        m_mime_type.resize(DS_DMM->mime_type->len);
        std::transform(DS_DMM->mime_type->data, DS_DMM->mime_type->data + DS_DMM->mime_type->len,
                m_mime_type.begin(), A_Z_to_a_z);
    }

    switch (DS_DMM->magic) {
    case CODE_decrypted_message_media_photo:
        m_type = tgl_document_type::image;
        if (m_mime_type.empty()) {
            m_mime_type = "image/jpeg"; // Default mime in case there is no mime from the message media
        }
        break;
    case CODE_decrypted_message_media_video:
    case CODE_decrypted_message_media_video_l12:
        m_type = tgl_document_type::video;
        break;
    case CODE_decrypted_message_media_document:
        if (m_mime_type.size() >= 6) {
            if (!m_mime_type.compare(0, 6, "image/")) {
                m_type = tgl_document_type::image;
                if (!m_mime_type.compare(0, 9, "image/gif")) {
                    m_is_animated = true;
                }
            } else if (!m_mime_type.compare(0, 6, "video/")) {
                m_type = tgl_document_type::video;
            } else if (!m_mime_type.compare(0, 6, "audio/")) {
                m_type = tgl_document_type::audio;
            }
        }
        break;
    case CODE_decrypted_message_media_audio:
        m_type = tgl_document_type::audio;
        break;
    }

    m_width = DS_LVAL(DS_DMM->w);
    m_height = DS_LVAL(DS_DMM->h);
    m_size = DS_LVAL(DS_DMM->size);
    m_duration = DS_LVAL(DS_DMM->duration);

    if (DS_DMM->thumb && DS_DMM->magic != CODE_photo_size_empty) {
        m_thumb = create_photo_size(DS_DMM->thumb);
    }

    if (DS_DMM->str_thumb && DS_DMM->str_thumb->data) {
        m_thumb_width = DS_LVAL(DS_DMM->thumb_w);
        m_thumb_height = DS_LVAL(DS_DMM->thumb_h);
        m_thumb_data.resize(DS_DMM->str_thumb->len);
        memcpy(m_thumb_data.data(), DS_DMM->str_thumb->data, DS_DMM->str_thumb->len);
    }

    m_key.resize(32);
    str_to_32(m_key.data(), DS_STR(DS_DMM->key));
    m_iv.resize(32);
    str_to_32(m_iv.data(), DS_STR(DS_DMM->iv));
}

void document::init_attribute(const tl_ds_document_attribute* DS_DA)
{
    switch (DS_DA->magic) {
    case CODE_document_attribute_image_size:
        m_type = tgl_document_type::image;
        m_width = DS_LVAL(DS_DA->w);
        m_height = DS_LVAL(DS_DA->h);
        return;
    case CODE_document_attribute_animated:
        m_is_animated = true;
        return;
    case CODE_document_attribute_sticker:
        m_type = tgl_document_type::sticker;
        m_caption = DS_STDSTR(DS_DA->alt);
        return;
    case CODE_document_attribute_video:
        m_type = tgl_document_type::video;
        m_duration = DS_LVAL(DS_DA->duration);
        m_width = DS_LVAL(DS_DA->w);
        m_height = DS_LVAL(DS_DA->h);
        return;
    case CODE_document_attribute_audio:
        m_type = tgl_document_type::audio;
        m_duration = DS_LVAL(DS_DA->duration);
        return;
    case CODE_document_attribute_filename:
        m_file_name = DS_STDSTR(DS_DA->file_name);
        return;
    default:
        assert(false);
    }
}

void document::update(const tl_ds_encrypted_file* DS_EF)
{
    m_id = DS_LVAL(DS_EF->id);
    m_access_hash = DS_LVAL(DS_EF->access_hash);
    m_size = DS_LVAL(DS_EF->size);
    m_dc_id = DS_LVAL(DS_EF->dc_id);
    m_key_fingerprint = DS_LVAL(DS_EF->key_fingerprint);
}

}
}
