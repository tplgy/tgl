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

#ifndef __TGL_TIMER_H__
#define __TGL_TIMER_H__

#include <memory>
#include <functional>

class tgl_timer {
public:
    virtual void start(double timeout) = 0;
    virtual void cancel() = 0;
    virtual ~tgl_timer() { }
};

class tgl_timer_factory {
public:
    virtual std::shared_ptr<tgl_timer> create_timer(const std::function<void()>& cb) = 0;
    virtual ~tgl_timer_factory() { }
};

#endif
