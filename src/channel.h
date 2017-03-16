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

#include "chat.h"
#include "tgl/tgl_channel.h"

namespace tgl {
namespace impl {

struct tl_ds_chat;

class channel: public chat, virtual public tgl_channel
{
public:
    static std::shared_ptr<channel> create_bare(const tgl_input_peer_t& id);

    virtual bool is_channel() const override { return true; }

    virtual int32_t admins_count() const override { return m_admins_count; }
    virtual int32_t kicked_count() const override { return m_kicked_count; }
    virtual bool is_official() const override { return m_is_official; }
    virtual bool is_broadcast() const override { return m_is_broadcast; }

    int32_t pts() const { return m_pts; }
    void set_pts(int32_t pts) { m_pts = pts; }
    bool is_diff_locked() const { return m_is_diff_locked; }
    void set_diff_locked(bool b) { m_is_diff_locked = b; }

private:
    friend class chat;
    explicit channel(const tl_ds_chat*);

private:
    int32_t m_admins_count;
    int32_t m_kicked_count;
    int32_t m_pts;
    bool m_is_official;
    bool m_is_broadcast;
    bool m_is_diff_locked;
};

}
}
