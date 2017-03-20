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

#include "tgl_photo.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

enum class tgl_document_type
{
    unknown,
    image,
    sticker,
    audio,
    video,
};

class tgl_document
{
public:
    virtual ~tgl_document() { }

    virtual tgl_document_type type() const = 0;
    virtual int64_t id() const = 0;
    virtual int64_t access_hash() const = 0;
    virtual int32_t date() const = 0;
    virtual int32_t size() const = 0;
    virtual int32_t dc_id() const = 0;
    virtual int32_t width() const = 0;
    virtual int32_t height() const = 0;
    virtual int32_t duration() const = 0;
    virtual bool is_animated() const = 0;
    virtual const std::shared_ptr<tgl_photo_size>& thumb() const = 0;
    virtual const std::string& caption() const = 0;
    virtual const std::string& mime_type() const = 0;
    virtual const std::string& file_name() const = 0;

    bool is_encrypted() const { return !key().empty() && !iv().empty() && key_fingerprint() != 0; }

    // For encrypted document.
    virtual const std::vector<unsigned char>& key() const = 0;
    virtual const std::vector<unsigned char>& iv() const = 0;
    virtual const std::vector<char> thumb_data() const = 0;
    virtual int32_t thumb_width() const = 0;
    virtual int32_t thumb_height() const = 0;
    virtual int32_t key_fingerprint() const = 0;
};
