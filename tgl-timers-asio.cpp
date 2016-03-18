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

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include "tgl.h"
#include "auto.h"
#include <stdlib.h>

class tgl_asio_timer : public std::enable_shared_from_this<tgl_asio_timer> {
public:
    tgl_asio_timer(boost::asio::io_service& io_service, void (*cb)(std::shared_ptr<void> ), std::shared_ptr<void> arg)
        : std::enable_shared_from_this<tgl_asio_timer>()
        , timer(io_service)
        , cb(cb)
        , arg(arg)
        , cancelled(false)
    {}

    ~tgl_asio_timer() {
    }

    void schedule(double seconds_from_now) {
        if (seconds_from_now < 0) { seconds_from_now = 0; }
        double us = seconds_from_now - (int)seconds_from_now;
        if (us < 0) { us = 0; }
        cancelled = false;
        timer.expires_from_now(boost::posix_time::seconds(int(seconds_from_now)) + boost::posix_time::microseconds(int(us * 1e6)));
        timer.async_wait(boost::bind(&tgl_asio_timer::handler, shared_from_this(), boost::asio::placeholders::error));
    }

    void cancel() {
        cancelled = true;
        timer.cancel();
    }

private:
    void handler(const boost::system::error_code& error) {
        if (!cancelled && error != boost::asio::error::operation_aborted) {
            cb(arg);
        }
    }

    boost::asio::deadline_timer timer;
    void (*cb)(std::shared_ptr<void>);
    std::shared_ptr<void> arg;
    bool cancelled;
};

struct tgl_timer {
    tgl_timer(boost::asio::io_service& io_service, void (*cb)(std::shared_ptr<void>), std::shared_ptr<void> arg)
        : timer(std::make_shared<tgl_asio_timer>(io_service, cb, arg))
    {}

    void schedule(double seconds_from_now) {
        timer->schedule(seconds_from_now);
    }

    void cancel() {
        timer->cancel();
    }

private:
    std::shared_ptr<tgl_asio_timer> timer;
};

struct tgl_timer *tgl_timer_alloc(void (*cb)(std::shared_ptr<void> arg), std::shared_ptr<void> arg) {
    return new tgl_timer(*tgl_state::instance()->io_service, cb, arg);
}

void tgl_timer_insert(struct tgl_timer *t, double p) {
    t->schedule(p);
}

void tgl_timer_delete(struct tgl_timer *t) {
    t->cancel();
}

void tgl_timer_free(struct tgl_timer *t) {
    delete t;
}

struct tgl_timer_methods tgl_asio_timer = {
    .alloc = tgl_timer_alloc,
    .insert = tgl_timer_insert,
    .remove = tgl_timer_delete,
    .free = tgl_timer_free
};
