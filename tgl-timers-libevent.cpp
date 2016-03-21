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
*/
#include <event.h>

#include "tgl.h"
#include "auto.h"
#include <stdlib.h>

struct tgl_timer_callback_libevent {
    void (*cb)(std::shared_ptr<void> arg);
    std::shared_ptr<void> arg;
};

static void timer_alarm (evutil_socket_t fd, short what, void *arg) {
  TGL_UNUSED(fd);
  TGL_UNUSED(what);
  tgl_timer_callback_libevent* p = static_cast<tgl_timer_callback_libevent*>(arg);
  p->cb(p->arg);
}

struct tgl_timer *tgl_timer_alloc (void (*cb)(std::shared_ptr<void> arg), std::shared_ptr<void> arg) {
  tgl_timer_callback_libevent* p = new tgl_timer_callback_libevent();
  p->cb = cb;
  p->arg = arg;
  return (struct tgl_timer *)evtimer_new ((struct event_base *)tgl_state::instance()->ev_base, timer_alarm, p);
}

void tgl_timer_insert (struct tgl_timer *t, double p) {
  if (p < 0) { p = 0; }
  double e = p - (int)p;
  if (e < 0) { e = 0; }
  struct timeval pv = { (int)p, (int)(e * 1e6)};
  event_add ((struct event *)t, &pv);
}

void tgl_timer_delete (struct tgl_timer *t) {
  event_del ((struct event*)t);
}

void tgl_timer_free (struct tgl_timer *t) {
  void *arg = event_get_callback_arg ((struct event *)t);
  delete static_cast<tgl_timer_callback_libevent*>(arg);
  event_free ((struct event *)t);
}

struct tgl_timer_methods tgl_libevent_timers = {
  .alloc = tgl_timer_alloc, 
  .insert = tgl_timer_insert,
  .remove = tgl_timer_delete,
  .free = tgl_timer_free
};
