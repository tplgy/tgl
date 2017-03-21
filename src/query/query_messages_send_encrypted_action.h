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

#include "query_messages_send_encrypted_base.h"

namespace tgl {
namespace impl {

class secret_chat;

class query_messages_send_encrypted_action: public query_messages_send_encrypted_base
{
public:
    query_messages_send_encrypted_action(user_agent& ua,
            const std::shared_ptr<secret_chat>& sc,
            const std::shared_ptr<message>& m,
            const std::function<void(bool, const std::shared_ptr<message>&)>& callback)
        : query_messages_send_encrypted_base(ua, "send encrypted action", sc, m, callback, false)
    {
    }

    query_messages_send_encrypted_action(user_agent& ua,
            const std::shared_ptr<secret_chat>& sc,
            const std::shared_ptr<tgl_unconfirmed_secret_message>& m,
            const std::function<void(bool, const std::shared_ptr<message>&)>& callback) throw(std::runtime_error);

    virtual void assemble() override;
};

}
}
