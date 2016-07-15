#ifndef __TGL_UPDATE_CALLBACK__
#define __TGL_UPDATE_CALLBACK__

#include "types/tgl_connection_status.h"
#include "types/tgl_secret_chat.h"
#include "types/tgl_typing_status.h"
#include <map>
#include <memory>

struct tgl_user_status;

class tgl_update_callback {
public:
    virtual void qts_changed(int32_t new_value) = 0;
    virtual void pts_changed(int32_t new_value) = 0;
    virtual void date_changed(int32_t new_value) = 0;
    virtual void new_messages(const std::vector<std::shared_ptr<tgl_message>>& msgs) = 0;
    virtual void message_sent(const std::shared_ptr<tgl_message>& M, int64_t new_msg_id, int32_t seq_no) = 0;
    virtual void message_deleted(int64_t msg_id) = 0;
    virtual void messages_mark_read_in(tgl_peer_id_t peer, int msg_id) = 0;
    virtual void messages_mark_read_out(tgl_peer_id_t peer, int msg_id) = 0;
    virtual void get_values(enum tgl_value_type type, const char *prompt, int num_values,
            std::function<void(const void *answer)>) = 0;
    virtual void logged_in() = 0;
    virtual void logged_out(bool success) = 0;
    virtual void started() = 0;
    virtual void typing_status_changed(int user_id, int chat_id, tgl_peer_type chat_type, enum tgl_typing_status status) = 0;
    virtual void status_notification(int user_id, const tgl_user_status& status) = 0;
    virtual void user_registered(int user_id) = 0;
    virtual void new_authorization(const std::string& device, const std::string& location) = 0;
    virtual void new_user(int user_id, const std::string &phone, const std::string &firstname,
                     const std::string &lastname, const std::string &username, int64_t access_hash,
                     const tgl_user_status& status, int32_t flags) = 0;
    virtual void user_update(int32_t user_id, const std::map<tgl_user_update_type, std::string>& updates) = 0;
    virtual void user_deleted(int32_t id) = 0;
    virtual void avatar_update(int32_t peer_id, tgl_peer_type peer_type, const tgl_file_location &photo_small, const tgl_file_location &photo_big) = 0;
    virtual void chat_update(int32_t chat_id, int peers_num, const std::string &title, int date, bool creator, bool admin, bool admin_enabled, bool kicked, bool left, bool deactivated,
            bool editor, bool moderator, bool megagroup, bool verified, bool restricted) = 0;
    virtual void chat_add_user(int32_t chat_id, int32_t user, int32_t inviter, int date, bool admin, bool creator) = 0;
    virtual void chat_delete_user(int32_t chat_id, int user) = 0;
    virtual void secret_chat_update(const std::shared_ptr<tgl_secret_chat>& secret_chat, tgl_secret_chat_state old_state) = 0;
    virtual void channel_update(int32_t channel_id, int64_t access_hash, int date, const std::string &title, const std::string &username) = 0;
    virtual void our_id(int32_t id) = 0;
    virtual void notification(const std::string& type, const std::string& message) = 0;
    virtual void user_status_update(struct tgl_user *U) = 0;
    virtual void dc_update(const std::shared_ptr<tgl_dc>& dc) = 0;
    virtual void change_active_dc(int new_dc_id) = 0;
    virtual void on_failed_login() = 0;
    virtual void connection_status_changed(tgl_connection_status status) = 0;
    virtual ~tgl_update_callback() { }
};

#endif
