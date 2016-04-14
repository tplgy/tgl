#ifndef TGL_DOWNLOAD_MANAGER_H
#define TGL_DOWNLOAD_MANAGER_H

#include <vector>
#include <string>
#include "types/tgl_file_location.h"
#include "types/tgl_peer_id.h"
#include "types/query_methods.h"

struct tgl_document;
struct tgl_encr_document;

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
        : location(location), offset(0), size(size), fd(-1), iv(NULL), key(NULL), type(0), refcnt(0)
    {
    }

    download(int type, tgl_document*);
    download(int type, tgl_encr_document*);

    tgl_file_location location;
    int offset;
    int size;
    int fd;
    std::string name;
    std::string ext;
    //encrypted documents
    unsigned char *iv;
    unsigned char *key;
    // ---
    int type;
    int refcnt; //Probably intended for being able to load multiple file parts simultaniously...however downloading is done sequentially
};

class tgl_download_manager
{
public:
    tgl_download_manager(std::string download_directory);
    std::string download_directory() { return m_download_directory; }

    bool file_exists(const tgl_file_location &location);

    std::string get_file_path(long long int secret);  // parameter is either secret or access hash depending on file type

    void download_encr_document(struct tgl_encr_document *V, void (*callback)(std::shared_ptr<void> callback_extra,
            bool success, const std::string &filename), std::shared_ptr<void> callback_extra);
    void download_audio(struct tgl_document *V, void (*callback)(std::shared_ptr<void> callback_extra, bool success, const std::string &filename),
            std::shared_ptr<void> callback_extra);
    void download_video(struct tgl_document *V, void (*callback)(std::shared_ptr<void> callback_extra, bool success, const std::string &filename),
            std::shared_ptr<void> callback_extra);
    void download_document_thumb(struct tgl_document *video, void (*callback)(std::shared_ptr<void> callback_extra, bool success, const std::string &filename),
            std::shared_ptr<void> callback_extra);
    void download_photo(struct tgl_photo *photo, void (*callback)(std::shared_ptr<void> callback_extra, bool success, const std::string &filename), std::shared_ptr<void> callback_extra);

    void download_photo_size(struct tgl_photo_size *P, void (*callback)(std::shared_ptr<void> callback_extra, bool success, const std::string &filename),
            std::shared_ptr<void> callback_extra);

    void download_file_location(const tgl_file_location& P, void (*callback)(std::shared_ptr<void> callback_extra, bool success, const std::string &filename),
            std::shared_ptr<void> callback_extra);

    void download_document(struct tgl_document *V, void (*callback)(std::shared_ptr<void> callback_extra, bool success, const std::string &filename),
            std::shared_ptr<void> callback_extra);

    void send_document(tgl_peer_id_t to_id, const std::string &file_name, const std::string &caption, unsigned long long flags,
            void (*callback)(std::shared_ptr<void> callback_extra, bool success, struct tgl_message *M), std::shared_ptr<void> callback_extra);
    // sets self profile photo
    // server will cut central square from this photo
    void set_profile_photo(const std::string &file_name, void (*callback)(std::shared_ptr<void> callback_extra, bool success), std::shared_ptr<void> callback_extra);
    void set_chat_photo(tgl_peer_id_t chat_id, const std::string &file_name, void (*callback)(std::shared_ptr<void> callback_extra, bool success), std::shared_ptr<void> callback_extra);

private:
    // Callbacks
    int download_on_answer(std::shared_ptr<query> q, void *DD);
    int download_on_error(std::shared_ptr<query> q, int error_code, const std::string &error);
    int send_file_part_on_answer(std::shared_ptr<query> q, void *D);
    int send_file_part_on_error(std::shared_ptr<query> q, int error_code, const std::string &error);
    int set_photo_on_answer(std::shared_ptr<query> q, void *D);
    int download_error(std::shared_ptr<query> q, int error_code, const std::string &error);

    void send_avatar_end(std::shared_ptr<send_file> f, void *callback, std::shared_ptr<void>callback_extra);
    void send_file_end(std::shared_ptr<send_file> f, void *callback, std::shared_ptr<void>callback_extra);
    void send_file_unencrypted_end (std::shared_ptr<send_file> f, void *callback, std::shared_ptr<void> callback_extra);
    void send_file_thumb(std::shared_ptr<send_file> f, const void *thumb_data, int thumb_len, void *callback, std::shared_ptr<void>callback_extra);

    void send_part(std::shared_ptr<send_file> f, void *callback, std::shared_ptr<void> callback_extra);

    void _tgl_do_send_photo(tgl_peer_id_t to_id, const std::string &file_name, int avatar, int w, int h, int duration,
                                    const void *thumb_data, int thumb_len, const std::string &caption, unsigned long long flags,
                                    void (*callback)(std::shared_ptr<void> callback_extra, bool success, struct tgl_message *M), std::shared_ptr<void> callback_extra);
    void _tgl_do_load_document(struct tgl_document *V, std::shared_ptr<download> D, void (*callback)(std::shared_ptr<void> callback_extra,
                                    bool success, const std::string &filename), std::shared_ptr<void> callback_extra);

    void begin_download(std::shared_ptr<download>);
    void load_next_part(std::shared_ptr<download>, void *callback, std::shared_ptr<void> callback_extra);
    void end_load(std::shared_ptr<download>, void *callback, std::shared_ptr<void>callback_extra);

    std::vector<std::shared_ptr<download>> m_downloads;

    std::string m_download_directory;

    query_methods m_send_file_part_methods;
    query_methods m_download_methods;
    query_methods m_set_photo_methods;

    long long cur_uploading_bytes;
    long long cur_uploaded_bytes;
    long long cur_downloading_bytes;
    long long cur_downloaded_bytes;
};

#endif // TGL_DOWNLOAD_MANAGER_H
