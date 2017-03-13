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

#include "query.h"

#include <array>

class tgl_secret_chat;

class query_messages_get_dh_config: public query
{
public:
    query_messages_get_dh_config(const std::shared_ptr<tgl_secret_chat>& secret_chat,
            const std::function<void(const std::shared_ptr<tgl_secret_chat>&,
                    std::array<unsigned char, 256>& random,
                    const std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)>&)>& callback,
            const std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)>& final_callback,
            double timeout = 0);
    virtual void on_answer(void* D) override;
    virtual int on_error(int error_code, const std::string& error_string) override;
    virtual void on_timeout() override;
    virtual double timeout_interval() const override;
    virtual bool should_retry_on_timeout() const override;
    virtual void will_be_pending() override;

private:
    std::shared_ptr<tgl_secret_chat> m_secret_chat;
    std::function<void(const std::shared_ptr<tgl_secret_chat>&,
             std::array<unsigned char, 256>& random,
             const std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)>&)> m_callback;
    std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)> m_final_callback;
    double m_timeout;
};
