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

    Copyright Topology LP 2017
*/

#ifndef __UNCONFIRMED_SECRET_MESSAGE_H__
#define __UNCONFIRMED_SECRET_MESSAGE_H__

#include "tgl/tgl_unconfirmed_secret_message.h"

class unconfirmed_secret_message: public tgl_unconfirmed_secret_message {
public:
    unconfirmed_secret_message(int64_t message_id, int64_t date, int32_t chat_id,
            int32_t in_seq_no, int32_t out_seq_no,
            bool is_out_going, uint32_t constructor_code)
        : m_message_id(message_id)
        , m_date(date)
        , m_chat_id(chat_id)
        , m_in_seq_no(in_seq_no)
        , m_out_seq_no(out_seq_no)
        , m_constructor_code(constructor_code)
        , m_is_out_going(is_out_going)
    {
    }

    virtual int64_t message_id() const override { return m_message_id; }
    virtual int64_t date() const override { return m_date; }
    virtual int32_t chat_id() const override { return m_chat_id; }
    virtual int32_t in_seq_no() const override { return m_in_seq_no; }
    virtual int32_t out_seq_no() const override { return m_out_seq_no; }
    virtual bool is_out_going() const override { return m_is_out_going; }
    virtual const std::vector<std::string>& blobs() const override { return m_blobs; }
    virtual void append_blob(std::string&& blob) override
    {
        m_blobs.push_back(std::move(blob));
    }
    virtual uint32_t constructor_code() const override { return m_constructor_code; }
    virtual void clear_blobs() override { m_blobs.clear(); }

private:
    int64_t m_message_id;
    int64_t m_date;
    int32_t m_chat_id;
    int32_t m_in_seq_no;
    int32_t m_out_seq_no;
    uint32_t m_constructor_code;
    bool m_is_out_going;
    std::vector<std::string> m_blobs;
};

#endif
