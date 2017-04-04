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

inline static bool is_decrypted_photo(uint32_t magic)
{
    return magic == CODE_decrypted_message_media_photo
            || magic == CODE_decrypted_message_media_photo_layer8;
}

inline static bool is_decrypted_video(uint32_t magic)
{
    return magic == CODE_decrypted_message_media_video
            || magic == CODE_decrypted_message_media_video_layer8
            || magic == CODE_decrypted_message_media_video_layer17;
}

inline static bool is_decrypted_audio(uint32_t magic)
{
    return magic == CODE_decrypted_message_media_audio
            || magic == CODE_decrypted_message_media_audio_layer8;
}

inline static bool is_decrypted_document(uint32_t magic)
{
    return magic == CODE_decrypted_message_media_document
            || magic == CODE_decrypted_message_media_external_document;
}

document::document(const tl_ds_decrypted_message_media* DS_DMM)
    : document()
{
    if (!is_decrypted_photo(DS_DMM->magic)
            && !is_decrypted_video(DS_DMM->magic)
            && !is_decrypted_document(DS_DMM->magic)
            && !is_decrypted_audio(DS_DMM->magic))
    {
        assert(false);
        return;
    }

    if (DS_DMM->mime_type && DS_DMM->mime_type->data) {
        m_mime_type.resize(DS_DMM->mime_type->len);
        std::transform(DS_DMM->mime_type->data, DS_DMM->mime_type->data + DS_DMM->mime_type->len,
                m_mime_type.begin(), A_Z_to_a_z);
    }

    if (is_decrypted_photo(DS_DMM->magic)) {
        m_type = tgl_document_type::image;
        if (m_mime_type.empty()) {
            m_mime_type = "image/jpeg"; // Default mime in case there is no mime from the message media
        }
    } else if (is_decrypted_video(DS_DMM->magic)) {
        m_type = tgl_document_type::video;
    } else if (is_decrypted_document(DS_DMM->magic)) {
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
    } else if (is_decrypted_audio(DS_DMM->magic)) {
        m_type = tgl_document_type::audio;
    } else {
        assert(false);
        return;
    }

    m_width = DS_LVAL(DS_DMM->w);
    m_height = DS_LVAL(DS_DMM->h);
    m_size = DS_LVAL(DS_DMM->size);
    m_duration = DS_LVAL(DS_DMM->duration);

    if (DS_DMM->thumb && DS_DMM->magic != CODE_photo_size_empty) {
        m_thumb = create_photo_size(DS_DMM->thumb);
    }

    if (DS_DMM->thumb_bytes && DS_DMM->thumb_bytes->data) {
        m_thumb_width = DS_LVAL(DS_DMM->thumb_w);
        m_thumb_height = DS_LVAL(DS_DMM->thumb_h);
        m_thumb_data.resize(DS_DMM->thumb_bytes->len);
        memcpy(m_thumb_data.data(), DS_DMM->thumb_bytes->data, DS_DMM->thumb_bytes->len);
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
