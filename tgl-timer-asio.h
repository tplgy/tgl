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

    Copyright Topology LP 2016
*/

#ifndef __TGL_TIMER_ASIO_H__
#define __TGL_TIMER_ASIO_H__

#include "tgl-timer.h"

#include <boost/asio.hpp>

class tgl_timer_asio : public std::enable_shared_from_this<tgl_timer_asio>
        , public tgl_timer
{
public:
    explicit tgl_timer_asio(boost::asio::io_service& io_service,
            const std::function<void()>& cb)
        : m_timer(io_service)
        , m_cb(cb)
        , m_cancelled(false)
    { }

    virtual void start(double seconds_from_now) override
    {
        if (seconds_from_now < 0) {
            seconds_from_now = 0;
        }

        double us = seconds_from_now - static_cast<long long>(seconds_from_now);
        if (us < 0) {
            us = 0;
        }

        m_cancelled = false;

        m_timer.expires_from_now(boost::posix_time::seconds(static_cast<long long>(seconds_from_now))
                + boost::posix_time::microseconds(static_cast<long long>(us * 1e6)));
        m_timer.async_wait(std::bind(&tgl_timer_asio::timeout,
                shared_from_this(), std::placeholders::_1));
    }


    virtual void cancel() override
    {
        if (!m_cancelled) {
            m_cancelled = true;
            m_timer.cancel();
        }
    }

private:
    void timeout(const boost::system::error_code& error) {
        if (!m_cancelled && error != boost::asio::error::operation_aborted) {
            m_cb();
        }
    }

private:
    boost::asio::deadline_timer m_timer;
    std::function<void()> m_cb;
    bool m_cancelled;
};

class tgl_timer_factory_asio : public tgl_timer_factory {
public:
    explicit tgl_timer_factory_asio(boost::asio::io_service& io_service)
        : m_io_service(io_service)
    { }

    virtual std::shared_ptr<tgl_timer> create_timer(const std::function<void()>& cb) override
    {
        return std::make_shared<tgl_timer_asio>(m_io_service, cb);
    }

private:
    boost::asio::io_service& m_io_service;
};

#endif
