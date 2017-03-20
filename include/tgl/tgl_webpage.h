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

class tgl_webpage
{
public:
    virtual ~tgl_webpage() { }
    virtual int64_t id() const = 0;
    virtual int32_t embed_width() const = 0;
    virtual int32_t embed_height() const = 0;
    virtual int32_t duration() const = 0;
    virtual const std::string url() const = 0;
    virtual const std::string display_url() const = 0;
    virtual const std::string type() const = 0;
    virtual const std::string site_name() const = 0;
    virtual const std::string title() const = 0;
    virtual const std::string description() const = 0;
    virtual const std::string embed_url() const = 0;
    virtual const std::string embed_type() const = 0;
    virtual const std::string author() const = 0;
    virtual const std::shared_ptr<tgl_photo> photo() const = 0;
};

