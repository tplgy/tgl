// normally you should not use these methods 
// use them with caution


#ifndef __TGL_METHODS_IN_H__
#define __TGL_METHODS_IN_H__

/* {{{ AUTHORIZATION METHODS. NORMALLY YOU DON'T NEED THEM */

// send query to updated DCs' ips
// automatically renews data on update
void tgl_do_help_get_config (void (*callback)(std::shared_ptr<void>, bool success), std::shared_ptr<void> callback_extra);

// requests server to send code to specified phone number
// if user is logged in elsewhere message will first appear as telegram message
// and SMS will be sent some time after
void tgl_do_send_code (const char *phone, int phone_len, std::function<void(bool success, int registered, const char *hash)> callback);

// request server to send code via phone call
void tgl_do_phone_call (const char *phone, int phone_len, const char *hash, int hash_len, std::function<void(bool success)> callback);

// sends code from SMS to server. This step should end authorization, unless user have password
int tgl_do_send_code_result (const char *phone, int phone_len, const char *hash, int hash_len, const char *code, int code_len, std::function<void(bool success)> callback);


// sends code from SMS, username and lastname to server. This step should end new user registration
int tgl_do_send_code_result_auth (const char *phone, int phone_len, const char *hash, int hash_len, const char *code, int code_len, const char *first_name,
        int first_name_len, const char *last_name, int last_name_len, std::function<void(bool success, struct tgl_user *Self)> callback);

/* }}} */
void tgl_do_send_msg (const std::shared_ptr<tgl_message>& M, std::function<void(bool success, const std::shared_ptr<tgl_message>& M)> callback);

void tgl_do_check_password (std::function<void(bool success)> callback);

void tgl_do_export_auth (int num, std::function<void(bool success)> callback);

void tgl_do_create_secret_chat(const tgl_peer_id_t& user_id, std::function<void(bool success, std::shared_ptr<tgl_secret_chat> E)> callback);

void tgl_do_get_difference (int sync_from_start, std::function<void(bool success)> callback);

void tgl_do_lookup_state ();

void tgl_do_help_get_config_dc (std::shared_ptr<tgl_dc> D);

void tgl_do_request_exchange (struct tgl_secret_chat *E);

void tgl_do_create_keys_end (struct tgl_secret_chat *U);

void tgl_do_send_encr_chat_layer(const std::shared_ptr<tgl_secret_chat>& secret_chat);

void tgl_do_send_encr_chat_request_resend(const std::shared_ptr<tgl_secret_chat>& secret_chat, int start_seq_no, int end_seq_no);
#endif
