#ifndef TGL_FILE_LOCATION
#define TGL_FILE_LOCATION

#include <cstdint>

struct tgl_file_location {
    tgl_file_location()
        : m_dc(0)
        , m_local_id(0)
        , m_volume(0)
        , m_secret(0)
    { }

    int32_t dc() const { return m_dc; }
    void set_dc(int d) { m_dc = d; }

    // regular files
    int64_t volume() const { return m_volume; }
    void set_volume(int64_t v) { m_volume = v; }
    int32_t local_id() const { return m_local_id; }
    void set_local_id(int32_t id) { m_local_id = id; }
    int64_t secret() const { return m_secret; }
    void set_secret(int64_t s) { m_secret = s; }

    // documents
    int64_t document_id() const { return m_volume; }
    int64_t access_hash() const { return m_secret; }

private:
    int32_t m_dc;
    int32_t m_local_id;  // not used for documents
    int64_t m_volume; // == id in documents
    int64_t m_secret; // == access hash for documents
};

#endif // TGL_FILE_LOCATION
