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

#include <memory>

class tgl_secret_chat;

namespace tgl {
namespace impl {

class mtprotocol_serializer;

class secret_chat_encryptor
{
public:
    secret_chat_encryptor(const std::shared_ptr<tgl_secret_chat>& secret_chat,
            const std::shared_ptr<mtprotocol_serializer>& serializer)
        : m_secret_chat(secret_chat)
        , m_serializer(serializer)
        , m_encr_base(0)
    { }

    void start();
    void end();

private:
    std::shared_ptr<tgl_secret_chat> m_secret_chat;
    std::shared_ptr<mtprotocol_serializer> m_serializer;
    size_t m_encr_base;
};

}
}
