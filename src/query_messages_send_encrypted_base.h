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

#ifndef __TGL_QUERY_MESSAGES_SEND_ENCRYPTED_BASE_H__
#define __TGL_QUERY_MESSAGES_SEND_ENCRYPTED_BASE_H__

#include <functional>
#include <memory>
#include "auto/auto.h"
#include "auto/constants.h"
#include "queries.h"
#include "queries-encrypted.h"
#include "tgl/tgl.h"
#include "tgl/tgl_message.h"
#include "tgl/tgl_secret_chat.h"
#include "tgl/tgl_update_callback.h"
#include "tgl_secret_chat_private.h"

class query_messages_send_encrypted_base: public query {
public:
    query_messages_send_encrypted_base(const std::string& name,
            const std::shared_ptr<tgl_secret_chat>& secret_chat,
            const std::shared_ptr<tgl_message>& message,
            const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback)
        : query(name, TYPE_TO_PARAM(messages_sent_encrypted_message))
        , m_secret_chat(secret_chat)
        , m_message(message)
        , m_callback(callback)
        , m_assembled(false)
    {
    }

    virtual void on_answer(void*) override
    {
        tgl_state::instance()->callback()->message_id_updated(m_message->permanent_id, m_message->permanent_id, m_message->to_id);
        if (m_callback) {
            m_callback(true, m_message);
        }
    }

    virtual int on_error(int error_code, const std::string& error_string) override
    {
        TGL_ERROR("RPC_CALL_FAIL " <<  error_code << " " << error_string);

        if (m_secret_chat && m_secret_chat->state() != tgl_secret_chat_state::deleted && error_code == 400 && error_string == "ENCRYPTION_DECLINED") {
            tgl_secret_chat_deleted(m_secret_chat);
        }

        if (m_callback) {
            m_callback(false, m_message);
        }

        if (m_message) {
            m_message->set_pending(false).set_send_failed(true);
            //bl_do_message_delete(&M->permanent_id);
            // FIXME: is this correct?
            // tgl_state::instance()->callback()->message_deleted(m_message->permanent_id);
            tgl_state::instance()->callback()->new_messages({m_message});
        }
        return 0;
    }

    virtual void will_send() override
    {
        if (m_assembled) {
            return;
        }

        m_assembled = true;

        auto depending_query_id = m_secret_chat->private_facet()->last_depending_query_id();
        if (depending_query_id) {
            out_i32(CODE_invoke_after_msg);
            out_i64(depending_query_id);
        }

        assemble();
    }

    virtual void sent() override
    {
        m_secret_chat->private_facet()->set_last_depending_query_id(msg_id());
    }

    virtual void assemble() = 0;

protected:
    std::shared_ptr<tgl_secret_chat> m_secret_chat;
    std::shared_ptr<tgl_message> m_message;
    std::function<void(bool, const std::shared_ptr<tgl_message>&)> m_callback;
    bool m_assembled;
};

#endif
