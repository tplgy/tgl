#ifndef TGL_DOWNLOAD_MANAGER_H
#define TGL_DOWNLOAD_MANAGER_H


#include "types/tgl_file_location.h"
#include "types/tgl_peer_id.h"

#include <functional>
#include <memory>
#include <vector>
#include <string>

struct tgl_document;
struct tgl_encr_document;
struct tgl_photo_size;
struct tgl_message;

struct send_file {
    int fd;
    long long size;
    long long offset;
    int part_num;
    int part_size;
    long long id;
    long long thumb_id;
    tgl_peer_id_t to_id;
    int flags;
    std::string file_name;
    int encr;
    int avatar;
    int reply;
    unsigned char *iv;
    unsigned char *init_iv;
    unsigned char *key;
    int w;
    int h;
    int duration;
    std::string caption;
};

struct download {
    download(int size, tgl_file_location location)
        : location(location), offset(0), size(size), fd(-1), iv(), key(), type(0), refcnt(0)
    {
    }

    download(int type, std::shared_ptr<tgl_document>);
    download(int type, std::shared_ptr<tgl_encr_document>);

    tgl_file_location location;
    int offset;
    int size;
    int fd;
    std::string name;
    std::string ext;
    //encrypted documents
    std::vector<unsigned char> iv;
    std::vector<unsigned char> key;
    // ---
    int type;
    int refcnt; //Probably intended for being able to load multiple file parts simultaniously...however downloading is done sequentially
};

class query_download;
class query_send_file_part;

class tgl_download_manager
{
public:
    tgl_download_manager(std::string download_directory);
    std::string download_directory() { return m_download_directory; }

    bool file_exists(const tgl_file_location &location);

    std::string get_file_path(long long int secret);  // parameter is either secret or access hash depending on file type

    void download_encr_document(std::shared_ptr<tgl_encr_document> V, std::function<void(bool success, const std::string &filename)> callback);
    void download_audio(std::shared_ptr<tgl_document> V, std::function<void(bool success, const std::string &filename)> callback);
    void download_video(std::shared_ptr<tgl_document> V, std::function<void(bool success, const std::string &filename)> callback);
    void download_document_thumb(struct tgl_document *video, std::function<void(bool success, const std::string &filename)> callback);
    void download_photo(struct tgl_photo *photo, std::function<void(bool success, const std::string &filename)> callback);

    void download_photo_size(const std::shared_ptr<tgl_photo_size>& P, std::function<void(bool success, const std::string &filename)> callback);

    void download_file_location(const tgl_file_location& P, std::function<void(bool success, const std::string &filename)> callback);

    void download_document(std::shared_ptr<tgl_document> document, std::function<void(bool success, const std::string &filename)>);

    void send_document(tgl_peer_id_t to_id, const std::string &file_name, const std::string &caption, unsigned long long flags,
            const std::function<void(bool success, const std::shared_ptr<tgl_message>& M)>& callback);
    // sets self profile photo
    // server will cut central square from this photo
    void set_profile_photo(const std::string &file_name, const std::function<void(bool success)>& callback);
    void set_chat_photo(tgl_peer_id_t chat_id, const std::string &file_name, const std::function<void(bool success)>& callback);

private:
    friend class query_download;
    friend class query_send_file_part;

    // Callbacks
    int download_on_answer(const std::shared_ptr<query_download>& q, void *DD);
    int download_on_error(const std::shared_ptr<query_download>& q, int error_code, const std::string &error);
    int send_file_part_on_answer(const std::shared_ptr<query_send_file_part>& q, void *D);

    void send_avatar_end(std::shared_ptr<send_file> f, const std::function<void(bool)>& callback);
    void send_file_end(std::shared_ptr<send_file> f, const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback);
    void send_file_unencrypted_end(std::shared_ptr<send_file> f, const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback);
    void send_file_thumb(std::shared_ptr<send_file> f, const void *thumb_data, int thumb_len, const std::function<void(bool, const std::shared_ptr<tgl_message>&)>& callback);

    void send_part(std::shared_ptr<send_file> f, const std::function<void(bool success, const std::shared_ptr<tgl_message>& M)>& callback);

    void _tgl_do_send_photo(tgl_peer_id_t to_id, const std::string &file_name, int avatar, int w, int h, int duration,
            const void *thumb_data, int thumb_len, const std::string& caption, unsigned long long flags,
            const std::function<void(bool success, const std::shared_ptr<tgl_message>& M)>& callback);
    void _tgl_do_load_document(std::shared_ptr<tgl_document> V, std::shared_ptr<download> D,
             std::function<void(bool success, const std::string &filename)> callback);

    void begin_download(std::shared_ptr<download>);
    void load_next_part(std::shared_ptr<download>, std::function<void(bool, const std::string &)> callback);
    void end_load(std::shared_ptr<download>, std::function<void(bool, const std::string &)> callback);

    std::vector<std::shared_ptr<download>> m_downloads;
    std::string m_download_directory;

    long long cur_uploading_bytes;
    long long cur_uploaded_bytes;
    long long cur_downloading_bytes;
    long long cur_downloaded_bytes;
};

#endif // TGL_DOWNLOAD_MANAGER_H
