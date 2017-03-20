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

#include "tgl/tgl_webpage.h"

#include <memory>

namespace tgl {
namespace impl {

struct tl_ds_web_page;

class webpage: public tgl_webpage
{
public:
    static std::shared_ptr<webpage> create(const tl_ds_web_page*);

    virtual int64_t id() const override { return m_id; }
    virtual int32_t embed_width() const override { return m_embed_width; }
    virtual int32_t embed_height() const override { return m_embed_height; }
    virtual int32_t duration() const override { return m_duration; }
    virtual const std::string url() const override { return m_url; }
    virtual const std::string display_url() const override { return m_display_url; }
    virtual const std::string type() const override { return m_type; }
    virtual const std::string site_name() const override { return m_site_name; }
    virtual const std::string title() const override { return m_title; }
    virtual const std::string description() const override { return m_description; }
    virtual const std::string embed_url() const override { return m_embed_url; }
    virtual const std::string embed_type() const override { return m_embed_type; }
    virtual const std::string author() const override { return m_author; }
    virtual const std::shared_ptr<tgl_photo> photo() const override { return m_photo; }

private:
    webpage();

private:
    int64_t m_id;
    int32_t m_embed_width;
    int32_t m_embed_height;
    int32_t m_duration;
    std::string m_url;
    std::string m_display_url;
    std::string m_type;
    std::string m_site_name;
    std::string m_title;
    std::string m_description;
    std::string m_embed_url;
    std::string m_embed_type;
    std::string m_author;
    std::shared_ptr<tgl_photo> m_photo;
};

}
}
