#ifndef __TGL_SECRET_CHAT_H__
#define __TGL_SECRET_CHAT_H__

#include "crypto/bn.h"
#include "crypto/sha.h"
#include "tgl-layout.h"
#include "tgl_file_location.h"
#include "tgl_peer_id.h"

#include <algorithm>
#include <string.h>
#include <memory>

enum tgl_secret_chat_state {
    sc_none,
    sc_waiting,
    sc_request,
    sc_ok,
    sc_deleted
};

enum tgl_secret_chat_exchange_state {
    tgl_sce_none,
    tgl_sce_requested,
    tgl_sce_accepted,
    tgl_sce_committed,
    tgl_sce_confirmed,
    tgl_sce_aborted
};

struct TGLC_bn_deleter {
    void operator()(TGLC_bn* bn)
    {
        TGLC_bn_free(bn);
    }
};

struct tgl_secret_chat {
    tgl_peer_id_t id;
    int flags;
    struct tgl_message *last;
    std::string print_name;
    std::string username;
    int structure_version;
    struct tgl_file_location photo_big;
    struct tgl_file_location photo_small;
    struct tgl_photo *photo;
    void *extra;
    int user_id;
    int admin_id;
    int date;
    int ttl;
    int layer;
    int in_seq_no;
    int out_seq_no;
    int last_in_seq_no;
    long long access_hash;
    std::vector<unsigned char> g_key;

    enum tgl_secret_chat_state state;

    long long temp_key_fingerprint;

    long long exchange_id;
    enum tgl_secret_chat_exchange_state exchange_state;
    int exchange_key[64];
    long long exchange_key_fingerprint;

    int encr_root;
    int encr_param_version;

    TGLC_bn* encr_prime_bn()
    {
        return m_encr_prime_bn.get();
    }

    const std::vector<unsigned char>& encr_prime() const
    {
        return m_encr_prime;
    }

    void set_encr_prime(const unsigned char* prime, size_t length)
    {
        m_encr_prime.resize(length);
        m_encr_prime_bn.reset(TGLC_bn_new());
        std::copy(prime, prime + length, m_encr_prime.begin());
        TGLC_bn_bin2bn(m_encr_prime.data(), length, m_encr_prime_bn.get());
    }

    void set_key(const unsigned char* key)
    {
        TGLC_sha1(key, key_size(), m_key_sha);
        memcpy(m_key, key, key_size());
    }

    const unsigned char* key() const { return m_key; }
    long long key_fingerprint() const { return *reinterpret_cast<const long long*>(m_key_sha + 12); }
    const unsigned char* key_sha() const { return m_key_sha; }

    static size_t key_size() { return 256; }
    static size_t key_sha_size() { return 20; }

    tgl_secret_chat()
        : flags(0)
        , last(nullptr)
        , print_name()
        , username()
        , structure_version(0)
        , photo_big()
        , photo_small()
        , photo(nullptr)
        , extra(nullptr)
        , user_id(0)
        , admin_id(0)
        , date(0)
        , ttl(0)
        , layer(0)
        , in_seq_no(0)
        , out_seq_no(0)
        , last_in_seq_no(0)
        , access_hash(0)
        , g_key()
        , state(sc_none)
        , temp_key_fingerprint(0)
        , exchange_id(0)
        , exchange_state(tgl_sce_none)
        , exchange_key_fingerprint(0)
        , encr_root(0)
        , encr_param_version(0)
        , m_encr_prime()
        , m_encr_prime_bn(nullptr)
    {
        memset(m_key, 0, sizeof(m_key));
        memset(m_key_sha, 0, sizeof(m_key_sha));
        memset(exchange_key, 0, sizeof(exchange_key));
    }

private:
    std::vector<unsigned char> m_encr_prime;
    std::unique_ptr<TGLC_bn, TGLC_bn_deleter> m_encr_prime_bn;
    unsigned char m_key[256];
    unsigned char m_key_sha[20];
};

#endif
