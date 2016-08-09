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

enum tgl_message_media_type {
    tgl_message_media_type_none,
    tgl_message_media_type_photo,
    tgl_message_media_type_document,
    tgl_message_media_type_geo,
    tgl_message_media_type_contact,
    tgl_message_media_type_unsupported,
    //tgl_message_media_type_photo_encr,
    //tgl_message_media_type_video_encr,
    //tgl_message_media_type_audio_encr,
    tgl_message_media_type_document_encr,
    tgl_message_media_type_webpage,
    tgl_message_media_type_venue,
    tgl_message_media_type_video,
    tgl_message_media_type_audio
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

struct tgl_document {
    int64_t id;
    int64_t access_hash;
    //int32_t user_id;
    int32_t date;
    int32_t size;
    int32_t dc_id;
    int32_t w;
    int32_t h;
    int32_t flags;
    int32_t duration;
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
        , flags(0)
        , duration(0)
    { }
};

struct tgl_encr_document: public tgl_document {
    std::vector<unsigned char> key;
    std::vector<unsigned char> iv;
    std::vector<char> thumb_data;
    int32_t thumb_width;
    int32_t thumb_height;
    int32_t key_fingerprint;
    tgl_encr_document() : thumb_width(0), thumb_height(0), key_fingerprint(0) { }
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
    virtual tgl_message_media_type type() override { return tgl_message_media_type_none; }
};

struct tgl_message_media_photo: public tgl_message_media {
    virtual tgl_message_media_type type() override { return tgl_message_media_type_photo; }
    std::shared_ptr<tgl_photo> photo;
    std::string caption;
};

struct tgl_message_media_document: public tgl_message_media {
    virtual tgl_message_media_type type() override { return tgl_message_media_type_document; }
    std::shared_ptr<tgl_document> document;
    std::string caption;
};

struct tgl_message_media_geo: public tgl_message_media {
    virtual tgl_message_media_type type() override { return tgl_message_media_type_geo; }
    tgl_geo geo;
};

struct tgl_message_media_contact: public tgl_message_media {
    tgl_message_media_contact(): user_id(0) { }
    virtual tgl_message_media_type type() override { return tgl_message_media_type_contact; }
    std::string phone;
    std::string first_name;
    std::string last_name;
    int32_t user_id;
};

struct tgl_message_media_unsupported: public tgl_message_media {
    virtual tgl_message_media_type type() override { return tgl_message_media_type_unsupported; }
};

struct tgl_message_media_document_encr: public tgl_message_media {
    virtual tgl_message_media_type type() override { return tgl_message_media_type_document_encr; }
    std::shared_ptr<tgl_encr_document> encr_document;
};

struct tgl_message_media_webpage: public tgl_message_media {
    virtual tgl_message_media_type type() override { return tgl_message_media_type_webpage; }
    std::shared_ptr<tgl_webpage> webpage;
};

struct tgl_message_media_venue: public tgl_message_media {
    virtual tgl_message_media_type type() override { return tgl_message_media_type_venue; }
    struct tgl_geo geo;
    std::string title;
    std::string address;
    std::string provider;
    std::string venue_id;
};

struct tgl_message_media_video: public tgl_message_media {
    virtual tgl_message_media_type type() override { return tgl_message_media_type_video; }
    std::shared_ptr<tgl_document> document;
    std::string caption;
};

struct tgl_message_media_audio: public tgl_message_media {
    virtual tgl_message_media_type type() override { return tgl_message_media_type_audio; }
    std::shared_ptr<tgl_document> document;
    std::string caption;
};

#endif
