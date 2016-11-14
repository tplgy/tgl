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

    Copyright Nikolay Durov, Andrey Lopatin 2012-2013
              Vitaly Valtman 2013-2015
    Copyright Topology LP 2016
*/
#ifndef __TGL_MTPROTO_CLIENT_H__
#define __TGL_MTPROTO_CLIENT_H__

#include <memory>

class tgl_connection;
struct tgl_dc;
struct tgl_session;

class tgl_mtproto_client
{
public:
    enum class execute_result {
        ok,
        bad_connection,
        bad_session,
        bad_dc,
    };

    virtual int ready(const std::shared_ptr<tgl_connection>& c) = 0;
    virtual execute_result try_rpc_execute(const std::shared_ptr<tgl_connection>& c) = 0;

    virtual ~tgl_mtproto_client() { }
};

#endif
