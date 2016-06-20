#ifndef __TGL_RSA_KEY_H__
#define __TGL_RSA_KEY_H__

#include <cassert>
#include <cstdint>
#include <memory>
#include <string>

#include "../crypto/rsa_pem.h"
#include "../mtproto-common.h"

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
