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

#ifndef __TGL_QUERY_MESSAGES_DISCARD_ENCRYPTION_H__
#define __TGL_QUERY_MESSAGES_DISCARD_ENCRYPTION_H__

#include "query.h"
#include "tgl/tgl_secret_chat.h"

class query_messages_discard_encryption: public query
{
public:
    query_messages_discard_encryption(
            const std::shared_ptr<tgl_secret_chat>& secret_chat,
            const std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)>& callback)
        : query("send encrypted (chat discard)", TYPE_TO_PARAM(bool))
        , m_secret_chat(secret_chat)
        , m_callback(callback)
    { }

    virtual void on_answer(void*) override
    {
        if (m_callback) {
            m_callback(true, m_secret_chat);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " << error_code << " " << error_string);
        if (m_callback) {
            m_callback(false, m_secret_chat);
        }
        return 0;
    }

private:
    std::shared_ptr<tgl_secret_chat> m_secret_chat;
    std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)> m_callback;
};

#endif
