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

#pragma once

#include "tgl_document.h"
#include "tgl_file_location.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

enum class tgl_message_media_type {
    none,
    photo,
    document,
    geo,
    contact,
    unsupported,
    webpage,
    venue,
    video,
    audio,
};

struct tgl_geo {
    double longitude;
    double latitude;
    tgl_geo(): longitude(0), latitude(0) { }
};

struct tgl_photo {
    int64_t id;
    int64_t access_hash;
    int32_t date;
    std::string caption;
    std::vector<std::shared_ptr<tgl_photo_size>> sizes;
    tgl_photo()
        : id(0)
        , access_hash(0)
        , date(0)
    { }
};

struct tgl_webpage {
    int64_t id;
    int32_t embed_width;
    int32_t embed_height;
    int32_t duration;
    std::string url;
    std::string display_url;
    std::string type;
    std::string site_name;
    std::string title;
    std::string description;
    std::shared_ptr<tgl_photo> photo;
    std::string embed_url;
    std::string embed_type;
    std::string author;

    tgl_webpage()
        : id(0)
        , embed_width(0)
        , embed_height(0)
        , duration(0)
    { }
};

struct tgl_message_media {
    virtual tgl_message_media_type type() = 0;
    virtual ~tgl_message_media() { }
};

struct tgl_message_media_none: public tgl_message_media {
    virtual tgl_message_media_type type() override { return tgl_message_media_type::none; }
};

struct tgl_message_media_photo: public tgl_message_media {
    virtual tgl_message_media_type type() override { return tgl_message_media_type::photo; }
    std::shared_ptr<tgl_photo> photo;
    std::string caption;
};

struct tgl_message_media_document: public tgl_message_media {
    virtual tgl_message_media_type type() override { return tgl_message_media_type::document; }
    std::shared_ptr<tgl_document> document;
    std::string caption;
};

struct tgl_message_media_geo: public tgl_message_media {
    virtual tgl_message_media_type type() override { return tgl_message_media_type::geo; }
    tgl_geo geo;
};

struct tgl_message_media_contact: public tgl_message_media {
    tgl_message_media_contact(): user_id(0) { }
    virtual tgl_message_media_type type() override { return tgl_message_media_type::contact; }
    std::string phone;
    std::string first_name;
    std::string last_name;
    int32_t user_id;
};

struct tgl_message_media_unsupported: public tgl_message_media {
    virtual tgl_message_media_type type() override { return tgl_message_media_type::unsupported; }
};

struct tgl_message_media_webpage: public tgl_message_media {
    virtual tgl_message_media_type type() override { return tgl_message_media_type::webpage; }
    std::shared_ptr<tgl_webpage> webpage;
};

struct tgl_message_media_venue: public tgl_message_media {
    virtual tgl_message_media_type type() override { return tgl_message_media_type::venue; }
    struct tgl_geo geo;
    std::string title;
    std::string address;
    std::string provider;
    std::string venue_id;
};

struct tgl_message_media_video: public tgl_message_media {
    virtual tgl_message_media_type type() override { return tgl_message_media_type::video; }
    std::shared_ptr<tgl_document> document;
    std::string caption;
};

struct tgl_message_media_audio: public tgl_message_media {
    virtual tgl_message_media_type type() override { return tgl_message_media_type::audio; }
    std::shared_ptr<tgl_document> document;
    std::string caption;
};
