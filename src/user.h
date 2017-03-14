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

#include "tgl/tgl_user.h"

struct tl_ds_user;
struct tl_ds_user_full;

class user: public tgl_user
{
public:
    explicit user(const tl_ds_user*);
    explicit user(const tl_ds_user_full*);

    virtual const tgl_input_peer_t& id() override { return m_id; }
    virtual const tgl_user_status& status() override { return m_status; }
    virtual const std::string& user_name() override { return m_user_name; }
    virtual const std::string& first_name() override { return m_first_name; }
    virtual const std::string& last_name() override { return m_last_name; }
    virtual const std::string& phone_number() override { return m_phone_number; }
    virtual bool is_contact() const override { return m_contact; }
    virtual bool is_mutual_contact() const override { return m_mutual_contact; }
    virtual bool is_blocked() const override { return m_blocked; }
    virtual bool is_blocked_confirmed() const override { return m_blocked_confirmed; }
    virtual bool is_self() const override { return m_self; }
    virtual bool is_bot() const override { return m_bot; }
    virtual bool is_deleted() const override { return m_deleted; }
    virtual bool is_official() const override { return m_official; }

    tgl_user& set_contact(bool b) { m_contact = b; return *this; }
    tgl_user& set_mutual_contact(bool b) { m_mutual_contact = b; return *this; }
    tgl_user& set_blocked(bool b) { m_blocked = b; m_blocked_confirmed = true; return *this; }
    tgl_user& set_self(bool b) { m_self = b; return *this; }
    tgl_user& set_bot(bool b) { m_bot = b; return *this; }
    tgl_user& set_deleted(bool b) { m_deleted = b; return *this; }
    tgl_user& set_official(bool b) { m_official = b; return *this; }

    const tgl_file_location& photo_big() const { return m_photo_big; }
    const tgl_file_location& photo_small() const { return m_photo_small; }

private:
    tgl_input_peer_t m_id;
    struct tgl_user_status m_status;
    std::string m_user_name;
    std::string m_first_name;
    std::string m_last_name;
    std::string m_phone_number;
    tgl_file_location m_photo_big;
    tgl_file_location m_photo_small;
    bool m_contact;
    bool m_mutual_contact;
    bool m_blocked;
    bool m_blocked_confirmed;
    bool m_self;
    bool m_bot;
    bool m_deleted;
    bool m_official;
};
