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
#ifndef __TGL_NET_H__
#define __TGL_NET_H__

#include <memory>

class tgl_dc;
class tgl_session;

class tgl_connection {
public:
    virtual bool open() = 0;
    virtual void close() = 0;
    virtual ssize_t write(const void* data, size_t len) = 0;
    virtual ssize_t read(void* data, size_t len) = 0;
    virtual void flush() = 0;
    virtual void incr_out_packet_num() = 0;
    virtual std::shared_ptr<tgl_dc> get_dc() = 0;
    virtual std::shared_ptr<tgl_session> get_session() = 0;

    virtual ~tgl_connection() { }
};

class mtproto_client;

class tgl_connection_factory {
public:
    virtual std::shared_ptr<tgl_connection> create_connection(
            const std::string& host,
            int port,
            const std::shared_ptr<tgl_session>& session,
            const std::shared_ptr<tgl_dc>& dc,
            const std::shared_ptr<mtproto_client>& client) = 0;

    virtual ~tgl_connection_factory() { }
};

#endif
