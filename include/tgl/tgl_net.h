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

#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include "tgl_connection_status.h"

struct tgl_net_stats
{
    uint64_t bytes_sent;
    uint64_t bytes_received;
};

class tgl_connection {
public:
    virtual void open() = 0;
    virtual void close() = 0;
    virtual ssize_t write(const void* data, size_t len) = 0;
    virtual ssize_t read(void* data, size_t len) = 0;
    virtual ssize_t peek(void* data, size_t len) = 0;
    virtual size_t available_bytes_for_read() = 0;
    virtual void flush() = 0;
    virtual tgl_connection_status status() const = 0;

    virtual ~tgl_connection() { }
};

class tgl_mtproto_client;

class tgl_connection_factory {
public:
    virtual std::shared_ptr<tgl_connection> create_connection(
            const std::vector<std::pair<std::string, int>>& ipv4_options,
            const std::vector<std::pair<std::string, int>>& ipv6_options,
            const std::weak_ptr<tgl_mtproto_client>& client) = 0;

    virtual ~tgl_connection_factory() { }
};
