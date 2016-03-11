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

struct tgl_timer {
  tgl_timer(boost::asio::io_service& io_service, void (*cb)(void *), void *arg)
    : timer(io_service)
    , cb(cb)
    , arg(arg)
  {}

  ~tgl_timer() {
    free(arg);
  }

  void handler(const boost::system::error_code& error) {
    if (error != boost::asio::error::operation_aborted) {
      cb(arg);
    }
  }

  boost::asio::deadline_timer timer;
  void (*cb)(void *);
  void *arg;
};

struct tgl_timer *tgl_timer_alloc(void (*cb)(void *arg), void *arg) {
  return new tgl_timer(*tgl_state::instance()->io_service, cb, arg);
}

void tgl_timer_insert(struct tgl_timer *t, double p) {
  if (p < 0) { p = 0; }
  double e = p - (int)p;
  if (e < 0) { e = 0; }
  t->timer.expires_from_now(boost::posix_time::seconds(int(p)) + boost::posix_time::microseconds(int(e * 1e6)));
  t->timer.async_wait(boost::bind(&tgl_timer::handler, t, boost::asio::placeholders::error));
}

void tgl_timer_delete(struct tgl_timer *t) {
  t->timer.cancel();
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
