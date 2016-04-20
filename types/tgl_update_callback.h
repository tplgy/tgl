#ifndef __TGL_UPDATE_CALLBACK__
#define __TGL_UPDATE_CALLBACK__

#include "types/tgl_secret_chat.h"

class tgl_update_callback {
public:
    virtual void new_message(struct tgl_message *M) = 0;
    virtual void message_sent(long long old_msg_id, long long new_msg_id, tgl_peer_id_t chat_id) = 0;
    virtual void message_deleted(long long msg_id) = 0;
    //virtual void marked_read(int num, struct tgl_message *list[]) =0
    virtual void get_values(enum tgl_value_type type, const char *prompt, int num_values,
            void (*callback)(const void *answer, std::shared_ptr<void> arg), std::shared_ptr<void> arg) = 0;
    virtual void logged_in() = 0;
    virtual void started() = 0;
    virtual void type_notification(int user_id, enum tgl_typing_status status) = 0;
    virtual void type_in_chat_notification(int user_id, int chat_id, enum tgl_typing_status status) = 0;
    virtual void type_in_secret_chat_notification(int chat_id) = 0;
    virtual void status_notification(int user_id, enum tgl_user_status_type, int expires) = 0;
    virtual void user_registered(int user_id) = 0;
    virtual void new_authorization(const std::string& device, const std::string& location) = 0;
    virtual void new_user(int user_id, const std::string &phone, const std::string &firstname,
                     const std::string &lastname, const std::string &username, long long access_hash, int last_seen) = 0;
    virtual void user_update(int user_id, void *value, enum tgl_user_update_type update_type) = 0;
    virtual void user_deleted(int id) = 0;
    virtual void avatar_update(int peer_id, const tgl_file_location &photo_small, const tgl_file_location &photo_big) = 0;
    virtual void chat_update(int chat_id, int peers_num, const std::string &title, int date, bool creator, bool admin, bool admin_enabled, bool kicked, bool left, bool deactivated) = 0;
    virtual void chat_add_user(int chat_id, int user, int inviter, int date) = 0;
    virtual void chat_delete_user(int chat_id, int user) = 0;
    virtual void secret_chat_update(const std::shared_ptr<tgl_secret_chat>& secret_chat, tgl_secret_chat_state old_state) = 0;
    virtual void channel_update(struct tgl_channel *C, unsigned flags) = 0;
    virtual void our_id(int id) = 0;
    virtual void notification(const std::string& type, const std::string& message) = 0;
    virtual void user_status_update(struct tgl_user *U) = 0;
    virtual void dc_update(const std::shared_ptr<tgl_dc>& dc) = 0;
    virtual void change_active_dc(int new_dc_id) = 0;
    virtual void on_failed_login() = 0;
    virtual ~tgl_update_callback() { }
};

#endif
