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

#ifndef __TGL_MESSAGE_MEDIA_H__
#define __TGL_MESSAGE_MEDIA_H__

#include "types/tgl_file_location.h"

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
    //photo_encr,
    //video_encr,
    //audio_encr,
    document_encr,
    webpage,
    venue,
    video,
    audio,
};

struct tgl_photo_size {
    std::string type;
    struct tgl_file_location loc;
    int32_t w;
    int32_t h;
    int32_t size;
    //char* data;
    //std::vector<char> data;
    tgl_photo_size()
        : w(0)
        , h(0)
        , size(0)
    { }
};

struct tgl_geo {
    double longitude;
    double latitude;
    tgl_geo(): longitude(0), latitude(0) { }
};

struct tgl_photo {
    int64_t id;
    int64_t access_hash;
    //int32_t user_id;
    int32_t date;
    std::string caption;
    //struct tgl_geo geo;
    std::vector<std::shared_ptr<tgl_photo_size>> sizes;
    tgl_photo()
        : id(0)
        , access_hash(0)
        , date(0)
    { }
};

enum class tgl_document_type {
    unknown,
    image,
    sticker,
    audio,
    video,
};

struct tgl_document {
    int64_t id;
    int64_t access_hash;
    //int32_t user_id;
    int32_t date;
    int32_t size;
    int32_t dc_id;
    int32_t w;
    int32_t h;
    int32_t duration;
    tgl_document_type type;
    bool is_animated;
    std::shared_ptr<tgl_photo_size> thumb;
    std::string caption;
    std::string mime_type;

    tgl_document()
        : id(0)
        , access_hash(0)
        , date(0)
        , size(0)
        , dc_id(0)
        , w(0)
        , h(0)
        , duration(0)
        , type(tgl_document_type::unknown)
        , is_animated(false)
    { }

    virtual bool is_encrypted() const { return false; }
};

struct tgl_encr_document: public tgl_document {
    std::vector<unsigned char> key;
    std::vector<unsigned char> iv;
    std::vector<char> thumb_data;
    int32_t thumb_width;
    int32_t thumb_height;
    int32_t key_fingerprint;
    tgl_encr_document() : thumb_width(0), thumb_height(0), key_fingerprint(0) { }
    virtual bool is_encrypted() const override { return true; }
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

struct tgl_message_media_document_encr: public tgl_message_media {
    virtual tgl_message_media_type type() override { return tgl_message_media_type::document_encr; }
    std::shared_ptr<tgl_encr_document> encr_document;
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

#endif
