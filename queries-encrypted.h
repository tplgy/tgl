#ifndef __TGL_QUERIES_ENCRYPTED_H__
#define __TGL_QUERIES_ENCRYPTED_H__

#ifdef ENABLE_SECRET_CHAT

#include "types/tgl_peer_id.h"
#include "types/tgl_secret_chat.h"

#include <functional>
#include <memory>
#include <vector>

struct tgl_message;
struct tgl_secret_chat;

void tgl_do_send_encr_msg(const std::shared_ptr<tgl_message>& M, std::function<void(bool, const std::shared_ptr<tgl_message>& M)> callback);
void tgl_do_messages_mark_read_encr(const std::shared_ptr<tgl_secret_chat>& secret_chat, std::function<void(bool)> callback);
void tgl_do_send_location_encr(const tgl_peer_id_t& id, double latitude, double longitude,
        unsigned long long flags,
        std::function<void(bool success, const std::shared_ptr<tgl_message>& M)> callback);
void tgl_do_create_encr_chat_request(const tgl_peer_id_t& user_id,
        const std::function<void(bool, const std::shared_ptr<tgl_secret_chat>&)>& callback);
void tgl_do_create_keys_end(const std::shared_ptr<tgl_secret_chat>& secret_chat);
void tgl_do_send_encr_chat_layer(const std::shared_ptr<tgl_secret_chat>& secret_chat);
void tgl_do_request_exchange(const std::shared_ptr<tgl_secret_chat>& secret_chat);
void tgl_do_confirm_exchange(const std::shared_ptr<tgl_secret_chat>& secret_chat, int sen_nop);
void tgl_do_accept_exchange(const std::shared_ptr<tgl_secret_chat>& secret_chat, long long exchange_id, const std::vector<unsigned char>& g_a);
void tgl_do_commit_exchange(const std::shared_ptr<tgl_secret_chat>& secret_chat, const std::vector<unsigned char>& g_a);
void tgl_do_abort_exchange(const std::shared_ptr<tgl_secret_chat>& secret_chat);
void tgl_do_send_encr_chat_request_resend(const std::shared_ptr<tgl_secret_chat>& secret_chat, int start_seq_no, int end_seq_no);

void tgl_update_secret_chat(const std::shared_ptr<tgl_secret_chat>& secret_chat,
        const long long* access_hash,
        const int* date,
        const int* admin,
        const int* user_id,
        const unsigned char* key,
        const unsigned char* g_key,
        const tgl_secret_chat_state* state,
        const int* ttl,
        const int* layer,
        const int* in_seq_no,
        const int* last_in_seq_no,
        const int* out_seq_no,
        int flags);

#endif

#endif
