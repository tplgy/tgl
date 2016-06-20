#ifndef __TGL_MESSAGE_MEDIA_H__
#define __TGL_MESSAGE_MEDIA_H__

#include "types/tgl_file_location.h"

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
    int w;
    int h;
    int size;
    //char *data;
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
    long long id;
    long long access_hash;
    //int user_id;
    int date;
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
    long long id;
    long long access_hash;
    //int user_id;
    int date;
    int size;
    int dc_id;
    std::shared_ptr<tgl_photo_size> thumb;
    std::string caption;
    std::string mime_type;

    int w;
    int h;
    int flags;
    int duration;

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
    int thumb_width;
    int thumb_height;
    int key_fingerprint;
    tgl_encr_document() : thumb_width(0), thumb_height(0), key_fingerprint(0) { }
};

struct tgl_webpage {
    long long id;
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
    int embed_width;
    int embed_height;
    int duration;
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
    int user_id;
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
