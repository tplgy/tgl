#ifndef __TGL_QUERIES_ENCRYPTED_H__
#define __TGL_QUERIES_ENCRYPTED_H__

#include "types/tgl_peer_id.h"
#include "types/tgl_secret_chat.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

struct tgl_message;
struct tgl_secret_chat;
class mtprotocol_serializer;

class secret_chat_encryptor
{
public:
    secret_chat_encryptor(const std::shared_ptr<tgl_secret_chat>& secret_chat,
            const std::shared_ptr<mtprotocol_serializer>& serializer)
        : m_secret_chat(secret_chat)
        , m_serializer(serializer)
    { }

    void start();
    void end();

private:
    std::shared_ptr<tgl_secret_chat> m_secret_chat;
    std::shared_ptr<mtprotocol_serializer> m_serializer;
    size_t m_encr_base;
};

void tgl_do_send_encr_msg(const std::shared_ptr<tgl_secret_chat>& secret_chat,
        const std::shared_ptr<tgl_message>& M,
        const std::function<void(bool, const std::shared_ptr<tgl_message>& M, float progress)>& callback);
void tgl_do_messages_mark_read_encr(const std::shared_ptr<tgl_secret_chat>& secret_chat,
        const std::function<void(bool)>& callback);
void tgl_do_send_location_encr(const tgl_input_peer_t& to_id, double latitude, double longitude,
        unsigned long long flags,
        const std::function<void(bool success, const std::shared_ptr<tgl_message>& M, float progress)>& callback);
void tgl_do_create_encr_chat_request(const tgl_input_peer_t& user_id,
        const std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)>& callback);
void tgl_do_send_encr_chat_layer(const std::shared_ptr<tgl_secret_chat>& secret_chat);
void tgl_do_request_exchange(const std::shared_ptr<tgl_secret_chat>& secret_chat);
void tgl_do_confirm_exchange(const std::shared_ptr<tgl_secret_chat>& secret_chat, int sen_nop);
void tgl_do_accept_exchange(const std::shared_ptr<tgl_secret_chat>& secret_chat, int64_t exchange_id, const std::vector<unsigned char>& g_a);
void tgl_do_commit_exchange(const std::shared_ptr<tgl_secret_chat>& secret_chat, const std::vector<unsigned char>& g_a);
void tgl_do_abort_exchange(const std::shared_ptr<tgl_secret_chat>& secret_chat);
void tgl_do_send_encr_chat_request_resend(const std::shared_ptr<tgl_secret_chat>& secret_chat, int32_t start_seq_no, int32_t end_seq_no);

void tgl_update_secret_chat(const std::shared_ptr<tgl_secret_chat>& secret_chat,
        const int64_t* access_hash,
        const int32_t* date,
        const int32_t* admin,
        const int32_t* user_id,
        const unsigned char* key,
        const unsigned char* g_key,
        const tgl_secret_chat_state* state,
        const int32_t* ttl,
        const int32_t* layer,
        const int32_t* in_seq_no,
        int32_t flags);

void tgl_secret_chat_deleted(const std::shared_ptr<tgl_secret_chat>& secret_chat);

#endif
