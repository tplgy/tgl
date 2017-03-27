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

#pragma once

#include "tgl/tgl_document.h"

namespace tgl {
namespace impl {

struct tl_ds_decrypted_message_media;
struct tl_ds_document;
struct tl_ds_document_attribute;
struct tl_ds_encrypted_file;

class document: public tgl_document
{
public:
    explicit document(const tl_ds_document*);
    explicit document(const tl_ds_decrypted_message_media*);

    virtual tgl_document_type type() const override { return m_type; }
    virtual int64_t id() const override { return m_id; }
    virtual int64_t access_hash() const override { return m_access_hash; }
    virtual int32_t date() const override { return m_date; }
    virtual int32_t size() const override { return m_size; }
    virtual int32_t dc_id() const override { return m_dc_id; }
    virtual int32_t width() const override { return m_width; }
    virtual int32_t height() const override { return m_height; }
    virtual int32_t duration() const override { return m_duration; }
    virtual bool is_animated() const override { return m_is_animated; }
    virtual const std::shared_ptr<tgl_photo_size>& thumb() const override { return m_thumb; }
    virtual const std::string& caption() const override { return m_caption; }
    virtual const std::string& mime_type() const override { return m_mime_type; }
    virtual const std::string& file_name() const override { return m_file_name; }

    // For encrypted document.
    virtual const std::vector<unsigned char>& key() const override { return m_key; }
    virtual const std::vector<unsigned char>& iv() const override { return m_iv; }
    virtual const std::vector<char> thumb_data() const override { return m_thumb_data; }
    virtual int32_t thumb_width() const override { return m_thumb_width; }
    virtual int32_t thumb_height() const override { return m_thumb_height; }
    virtual int32_t key_fingerprint() const override { return m_key_fingerprint; }

    bool empty() const { return !m_id; }
    void set_type(tgl_document_type type) { m_type = type; }
    void set_animated(bool b) { m_is_animated = b; }

    void update(const tl_ds_encrypted_file*);

private:
    document();
    void init_attribute(const tl_ds_document_attribute*);

private:
    int64_t m_id;
    int64_t m_access_hash;
    int32_t m_date;
    int32_t m_size;
    int32_t m_dc_id;
    int32_t m_width;
    int32_t m_height;
    int32_t m_duration;
    tgl_document_type m_type;
    bool m_is_animated;
    std::shared_ptr<tgl_photo_size> m_thumb;
    std::string m_caption;
    std::string m_mime_type;
    std::string m_file_name;

    std::vector<unsigned char> m_key;
    std::vector<unsigned char> m_iv;
    std::vector<char> m_thumb_data;
    int32_t m_thumb_width;
    int32_t m_thumb_height;
    int32_t m_key_fingerprint;
};

}
}
