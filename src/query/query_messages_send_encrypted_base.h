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

#include <exception>
#include <functional>
#include <memory>
#include <tuple>
#include <vector>

#include "auto/auto.h"
#include "auto/constants.h"
#include "queries.h"
#include "queries-encrypted.h"
#include "tgl/tgl.h"
#include "tgl/tgl_message.h"
#include "tgl/tgl_secret_chat.h"
#include "tgl/tgl_unconfirmed_secret_message.h"
#include "tgl/tgl_update_callback.h"
#include "tgl_secret_chat_private.h"

class query_messages_send_encrypted_base: public query {
public:
    query_messages_send_encrypted_base(const std::string& name,
            const std::shared_ptr<tgl_secret_chat>& secret_chat,
            const std::shared_ptr<tgl_message>& message,
            const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback,
            bool assembled)
        : query(name, TYPE_TO_PARAM(messages_sent_encrypted_message))
        , m_secret_chat(secret_chat)
        , m_message(message)
        , m_callback(callback)
        , m_assembled(assembled)
    { }

    virtual void on_answer(void*) override;
    virtual int on_error(int error_code, const std::string& error_string) override;
    virtual void will_send() override;
    virtual void sent() override;
    virtual void assemble() = 0;

    static std::vector<std::shared_ptr<query_messages_send_encrypted_base>>
    create_by_out_seq_no(const std::shared_ptr<tgl_secret_chat>& secret_chat, int32_t out_seq_no_start, int32_t out_seq_no_end);

protected:
    size_t begin_unconfirmed_message(uint32_t constructor_code);
    void append_blob_to_unconfirmed_message(size_t buffer_position_start);
    void end_unconfirmed_message();
    void construct_message(int64_t message_id, int64_t date,
            const std::string& layer_blob) throw(std::runtime_error);

protected:
    std::shared_ptr<tgl_secret_chat> m_secret_chat;
    std::shared_ptr<tgl_message> m_message;
    std::function<void(bool, const std::shared_ptr<tgl_message>&)> m_callback;
    bool m_assembled;

private:
    std::shared_ptr<tgl_unconfirmed_secret_message> m_unconfirmed_message;
};

#endif
