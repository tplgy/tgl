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
    Copyright Topology LP 2016
*/

#ifndef __TGL_RSA_KEY_H__
#define __TGL_RSA_KEY_H__

#include <cassert>
#include <cstdint>
#include <memory>
#include <string>

#include "crypto/tgl_crypto_rsa_pem.h"
#include "mtproto-common.h"

class tgl_rsa_key
{
public:
    explicit tgl_rsa_key(const std::string& key)
        : m_key(key)
        , m_public_key()
        , m_fingerprint(0)
    { }

    bool is_loaded() const { return !!m_public_key; }
    bool load()
    {
        m_public_key.reset(TGLC_pem_read_RSAPublicKey(m_key.c_str()));
        if (!m_public_key) {
            return false;
        }

        m_fingerprint = tgl_do_compute_rsa_key_fingerprint(m_public_key.get());
        return true;
    }

    const TGLC_rsa* public_key() const { return m_public_key.get(); }
    const std::string& public_key_string() const { return m_key; }
    int64_t fingerprint() const { return m_fingerprint; }

private:
    struct RSA_deleter
    {
        void operator()(TGLC_rsa* rsa) {
            TGLC_rsa_free(rsa);
        }
    };

private:
    std::string m_key;
    std::unique_ptr<TGLC_rsa, RSA_deleter> m_public_key;
    int64_t m_fingerprint;
};

#endif
