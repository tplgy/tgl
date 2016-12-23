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

    Copyright Vitaly Valtman 2014-2015
    Copyright Topology LP 2016
*/
#ifndef __TGL_DC_H__
#define __TGL_DC_H__

#include <array>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

static const char* TG_SERVER_1 = "149.154.175.50";
static const char* TG_SERVER_2 = "149.154.167.51";
static const char* TG_SERVER_3 = "149.154.175.100";
static const char* TG_SERVER_4 = "149.154.167.91";
static const char* TG_SERVER_5 = "149.154.171.5";
static const char* TG_SERVER_IPV6_1 = "2001:b28:f23d:f001::a";
static const char* TG_SERVER_IPV6_2 = "2001:67c:4e8:f002::a";
static const char* TG_SERVER_IPV6_3 = "2001:b28:f23d:f003::a";
static const char* TG_SERVER_IPV6_4 = "2001:67c:4e8:f004::a";
static const char* TG_SERVER_IPV6_5 = "2001:b28:f23f:f005::a";
static constexpr int TG_SERVER_DEFAULT = 2;

static const char* TG_SERVER_TEST_1 = "149.154.175.40";
static const char* TG_SERVER_TEST_2 = "149.154.167.40";
static const char* TG_SERVER_TEST_3 = "149.154.175.117";
static const char* TG_SERVER_TEST_IPV6_1 = "2001:b28:f23d:f001::e";
static const char* TG_SERVER_TEST_IPV6_2 = "2001:67c:4e8:f002::e";
static const char* TG_SERVER_TEST_IPV6_3 = "2001:b28:f23d:f003::e";
static constexpr int TG_SERVER_TEST_DEFAULT = 1;

class tgl_dc {
public:
    virtual int32_t id() const = 0;
    virtual bool is_logged_in() const = 0;
    virtual const std::vector<std::pair<std::string, int>>& ipv4_options() const = 0;
    virtual const std::vector<std::pair<std::string, int>>& ipv6_options() const = 0;
    virtual int64_t auth_key_id() const = 0;
    virtual const std::array<unsigned char, 256>& auth_key() const = 0;
    virtual ~tgl_dc() { }
};

#endif
