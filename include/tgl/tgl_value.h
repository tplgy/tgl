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

#ifndef __TGL_VALUE_H__
#define __TGL_VALUE_H__

#include <cassert>
#include <iostream>
#include <functional>
#include <string>

enum class tgl_value_type {
    phone_number,               // user phone number
    login_code,                 // telegram login code and tgl_login_action
    register_info,              // register_user bool flag, first name, last name
    new_password,               // new password, confirm new password
    current_and_new_password,   // current password, new password, confirm new password
    current_password,           // current password
    bot_hash,
};

enum class tgl_login_action {
    none,
    call_me,
    resend_code,
};

inline static std::string to_string(tgl_value_type type)
{
    switch (type) {
    case tgl_value_type::phone_number:
        return "phone_number";
    case tgl_value_type::login_code:
        return "login_code";
    case tgl_value_type::register_info:
        return "register_info";
    case tgl_value_type::new_password:
        return "new_password";
    case tgl_value_type::current_and_new_password:
        return "current_and_new_password";
    case tgl_value_type::current_password:
        return "current_password";
    case tgl_value_type::bot_hash:
        return "bot_hash";
    default:
        assert(false);
        return "unknown tgl_value_type";
    }
}

inline std::ostream& operator<<(std::ostream& os, tgl_value_type type)
{
    os << to_string(type);
    return os;
}

class tgl_value
{
public:
    virtual ~tgl_value() { }
    virtual tgl_value_type type() const = 0;
};

class tgl_value_phone_number: public tgl_value
{
public:
    using acceptor = std::function<void(const std::string& phone_number)>;
    explicit tgl_value_phone_number(const acceptor& a): m_acceptor(a) { }
    virtual tgl_value_type type() const override { return tgl_value_type::phone_number; }
    void accept(const std::string& phone_number) { m_acceptor(phone_number); }
private:
    acceptor m_acceptor;
};

class tgl_value_login_code: public tgl_value
{
public:
    using acceptor = std::function<void(const std::string& login_code, tgl_login_action action)>;
    explicit tgl_value_login_code(const acceptor& a): m_acceptor(a) { }
    virtual tgl_value_type type() const override { return tgl_value_type::login_code; }
    void accept(const std::string& login_code) { m_acceptor(login_code, tgl_login_action::none); }
    void accept(tgl_login_action action) { assert(action != tgl_login_action::none); m_acceptor("", action); }
private:
    acceptor m_acceptor;
};

class tgl_value_register_info: public tgl_value
{
public:
    using acceptor = std::function<void(bool register_user, const std::string& frist_name, const std::string& last_name)>;
    explicit tgl_value_register_info(const acceptor& a): m_acceptor(a) { }
    virtual tgl_value_type type() const override { return tgl_value_type::register_info; }
    void accept(bool register_user, const std::string& first_name, const std::string& last_name) { m_acceptor(register_user, first_name, last_name); }
private:
    acceptor m_acceptor;
};

class tgl_value_new_password: public tgl_value
{
public:
    using acceptor = std::function<void(const std::string& new_password, const std::string& confirm_password)>;
    explicit tgl_value_new_password(const acceptor& a): m_acceptor(a) { }
    virtual tgl_value_type type() const override { return tgl_value_type::new_password; }
    void accept(const std::string& new_password, const std::string& confirm_password) { m_acceptor(new_password, confirm_password); }
private:
    acceptor m_acceptor;
};

class tgl_value_current_and_new_password: public tgl_value
{
public:
    using acceptor = std::function<void(const std::string& current_password, const std::string& new_password, const std::string& confirm_password)>;
    explicit tgl_value_current_and_new_password(const acceptor& a): m_acceptor(a) { }
    virtual tgl_value_type type() const override { return tgl_value_type::current_password; }
    void accept(const std::string& current_password, const std::string& new_password, const std::string& confirm_password) { m_acceptor(current_password, new_password, confirm_password); }
private:
    acceptor m_acceptor;
};

class tgl_value_current_password: public tgl_value
{
public:
    using acceptor = std::function<void(const std::string& current_password)>;
    explicit tgl_value_current_password(const acceptor& a): m_acceptor(a) { }
    virtual tgl_value_type type() const override { return tgl_value_type::current_password; }
    void accept(const std::string& current_password) { m_acceptor(current_password); }
private:
    acceptor m_acceptor;
};

class tgl_value_bot_hash: public tgl_value
{
public:
    using acceptor = std::function<void(const std::string& bot_hash)>;
    explicit tgl_value_bot_hash(const acceptor& a): m_acceptor(a) { }
    virtual tgl_value_type type() const override { return tgl_value_type::bot_hash; }
    void accept(const std::string& bot_hash) { m_acceptor(bot_hash); }
private:
    acceptor m_acceptor;
};

#endif
