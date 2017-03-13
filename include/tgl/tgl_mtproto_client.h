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
    Copyright Topology LP 2016-2017
*/

#pragma once

#include <memory>

#include "tgl_connection_status.h"
#include "tgl_online_status.h"
#include "tgl_online_status_observer.h"
#include "tgl_timer.h"

class tgl_connection;

class tgl_mtproto_client
{
public:
    virtual ~tgl_mtproto_client() { }
    virtual int32_t id() const = 0;
    virtual void connection_status_changed(const std::shared_ptr<tgl_connection>& c) = 0;
    virtual bool try_rpc_execute(const std::shared_ptr<tgl_connection>& c) = 0;
    virtual void ping() = 0;
    virtual tgl_online_status online_status() const = 0;
    virtual bool ipv6_enabled() const = 0;
    virtual std::shared_ptr<tgl_timer_factory> timer_factory() const = 0;
    virtual void add_online_status_observer(const std::weak_ptr<tgl_online_status_observer>& observer) = 0;
    virtual void remove_online_status_observer(const std::weak_ptr<tgl_online_status_observer>& observer) = 0;
    virtual void bytes_sent(size_t bytes) = 0;
    virtual void bytes_received(size_t bytes) = 0;
};
