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

    Copyright Vitaly Valtman 2014-2015
    Copyright Topology LP 2016-2017
*/

#ifndef __QUERY_MESSAGES_SEND_ENCRYPTED_FILE__
#define __QUERY_MESSAGES_SEND_ENCRYPTED_FILE__

#include "query_messages_send_encrypted_base.h"

#include <functional>
#include <memory>

class tgl_secret_chat;
struct tgl_message;
struct tgl_upload;
struct tl_ds_decrypted_message_media;

class query_messages_send_encrypted_file: public query_messages_send_encrypted_base
{
public:
    query_messages_send_encrypted_file(const std::shared_ptr<tgl_secret_chat>& secret_chat,
            const std::shared_ptr<tgl_upload>& upload,
            const std::shared_ptr<tgl_message>& message,
            const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback)
        : query_messages_send_encrypted_base("send encrypted file message", secret_chat, message, callback, false)
        , m_upload(upload)
    { }

    query_messages_send_encrypted_file(
            const std::shared_ptr<tgl_secret_chat>& secret_chat,
            const std::shared_ptr<tgl_unconfirmed_secret_message>& message,
            const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback) throw(std::runtime_error);

    virtual void assemble() override;

private:
    void set_message_media(const tl_ds_decrypted_message_media*);

private:
    std::shared_ptr<tgl_upload> m_upload;
};

#endif
