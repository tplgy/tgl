#ifndef TGL_DOWNLOAD_MANAGER_H
#define TGL_DOWNLOAD_MANAGER_H


#include "types/tgl_file_location.h"
#include "types/tgl_peer_id.h"
#include "types/tgl_message.h"

#include <string.h>
#include <array>
#include <functional>
#include <memory>
#include <vector>
#include <string>

struct tgl_document;
struct tgl_encr_document;
struct tgl_photo_size;
struct tgl_message;
struct tgl_photo;
struct tl_ds_storage_file_type;
struct send_file;
struct download;
class query_download;
class query_send_file_part;

using tgl_download_callback = std::function<void(bool success, const std::string& file_name, float progress)>;
using tgl_upload_callback = std::function<void(bool success, const std::shared_ptr<tgl_message>& message, float progress)>;

class tgl_download_manager
{
public:
    tgl_download_manager(std::string download_directory);
    std::string download_directory() { return m_download_directory; }

    bool file_exists(const tgl_file_location &location);

    bool currently_donwloading(const tgl_file_location& location);

    std::string get_file_path(long long int secret);  // parameter is either secret or access hash depending on file type

    void download_encr_document(const std::shared_ptr<tgl_encr_document>& document, const tgl_download_callback& callback);
    void download_audio(const std::shared_ptr<tgl_document>& document, const tgl_download_callback& callback);
    void download_video(const std::shared_ptr<tgl_document>& document, const tgl_download_callback& callback);
    void download_document_thumb(const std::shared_ptr<tgl_document>& document, const tgl_download_callback& callback);
    void download_photo(const std::shared_ptr<tgl_photo>& photo, const tgl_download_callback& callback);
    void download_by_photo_size(const std::shared_ptr<tgl_photo_size>& photo_size, const tgl_download_callback& callback);
    void download_by_file_location(const tgl_file_location& location, int32_t file_size, const tgl_download_callback& callback);
    void download_document(const std::shared_ptr<tgl_document>& document, const tgl_download_callback& callback);

    void send_document(const tgl_peer_id_t& to_id, const tgl_message_id_t& message_id,
            const std::string& file_name, int32_t width, int32_t height, int32_t duration, const std::string& caption,
            const std::string& thumb_path, int32_t thumb_width, int32_t thumb_height, unsigned long long flags,
            const tgl_upload_callback& callback);

    // sets self profile photo
    // server will cut central square from this photo
    void set_profile_photo(const std::string &file_name, const std::function<void(bool success)>& callback);
    void set_chat_photo(tgl_peer_id_t chat_id, const std::string &file_name, const std::function<void(bool success)>& callback);

private:
    friend class query_download;
    friend class query_send_file_part;

    // Callbacks
    int download_on_answer(const std::shared_ptr<query_download>& q, void* answer);
    int download_on_error(const std::shared_ptr<query_download>& q, int error_code, const std::string &error);
    int send_file_part_on_answer(const std::shared_ptr<query_send_file_part>& q, void* answer);

    void send_avatar_end(const std::shared_ptr<send_file>& f, const std::function<void(bool)>& callback);
    void send_file_end(const std::shared_ptr<send_file>& f, const tgl_upload_callback& callback);
    void send_unencrypted_file_end(const std::shared_ptr<send_file>& f, const tgl_upload_callback& callback);
    void send_encrypted_file_end(const std::shared_ptr<send_file>& f, const tgl_upload_callback& callback);
    void send_file_thumb(const std::shared_ptr<send_file>& f, const tgl_upload_callback& callback);

    void send_part(const std::shared_ptr<send_file>& f, const tgl_upload_callback& callback);

    void send_document(const tgl_peer_id_t& to_id, const tgl_message_id_t& message_id, const std::string &file_name, int avatar, int w, int h, int duration,
            const std::string& caption, unsigned long long flags,
            const std::string& thumb_path, int thumb_w, int thumb_h,
            const tgl_upload_callback& callback);

    void download_document(const std::shared_ptr<tgl_document>& document, const std::shared_ptr<download>& d,
             const tgl_download_callback& callback);

    void begin_download(const std::shared_ptr<download>&);
    void download_next_part(const std::shared_ptr<download>&, const tgl_download_callback& callback);
    void end_download(const std::shared_ptr<download>&, const tgl_download_callback& callback);

    std::vector<std::shared_ptr<download>> m_downloads;
    std::string m_download_directory;

    long long m_current_uploading_bytes;
    long long m_current_uploaded_bytes;
    long long m_current_downloading_bytes;
    long long m_current_downloaded_bytes;
};

#endif // TGL_DOWNLOAD_MANAGER_H
