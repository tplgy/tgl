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

#include "tgl/tgl_chat.h"

struct tl_ds_chat;

class chat: virtual public tgl_chat
{
public:
    static std::shared_ptr<chat> create(const tl_ds_chat*);

    virtual const tgl_input_peer_t& id() const override { return m_id; }
    virtual int64_t date() const override { return m_date; }
    virtual int32_t participants_count() const override { return m_participants_count; }
    virtual bool is_creator() const override { return m_is_creator; }
    virtual bool is_kicked() const override { return m_is_kicked; }
    virtual bool is_left() const override { return m_is_left; }
    virtual bool is_admins_enabled() const override { return m_is_admins_enabled; }
    virtual bool is_deactivated() const override { return m_is_deactivated; }
    virtual bool is_admin() const override { return m_is_admin; }
    virtual bool is_editor() const override { return m_is_editor; }
    virtual bool is_moderator() const override { return m_is_moderator; }
    virtual bool is_verified() const override { return m_is_verified; }
    virtual bool is_mega_group() const override { return m_is_mega_group; }
    virtual bool is_restricted() const override { return m_is_restricted; }
    virtual bool is_forbidden() const override { return m_is_forbidden; }
    virtual const std::string& title() const override { return m_title; }
    virtual const std::string& user_name() const override { return m_user_name; }
    virtual const tgl_file_location& photo_big() const override { return m_photo_big; }
    virtual const tgl_file_location& photo_small() const override { return m_photo_small; }

    virtual bool is_channel() const { return false; }
    bool empty() const { return m_id.empty(); }

protected:
    class dont_check_magic { };
    chat(const tl_ds_chat*, dont_check_magic);

private:
    explicit chat(const tl_ds_chat*);

protected:
    tgl_input_peer_t m_id;
    int64_t m_date;
    int32_t m_participants_count;
    bool m_is_creator;
    bool m_is_kicked;
    bool m_is_left;
    bool m_is_admins_enabled;
    bool m_is_deactivated;
    bool m_is_admin;
    bool m_is_editor;
    bool m_is_moderator;
    bool m_is_verified;
    bool m_is_mega_group;
    bool m_is_restricted;
    bool m_is_forbidden;
    std::string m_title;
    std::string m_user_name;
    tgl_file_location m_photo_big;
    tgl_file_location m_photo_small;
};
