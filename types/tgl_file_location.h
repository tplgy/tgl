#ifndef TGL_FILE_LOCATION
#define TGL_FILE_LOCATION

struct tgl_file_location {
    tgl_file_location() :m_dc(0), m_volume(0), m_local_id(0), m_secret(0) {}
    tgl_file_location(int dc, long long volume, int local_id, long long secret) :
        m_dc(dc), m_volume(volume), m_local_id(local_id), m_secret(secret) {}

    tgl_file_location(int dc, long long id, long long access_hash) :
        m_dc(dc), m_volume(id), m_secret(access_hash) {}

    int dc() const { return m_dc; }

    // regular files
    long long volume() const { return m_volume; }
    int local_id() const { return m_local_id; }
    long long secret() const { return m_secret; }

    // documents
    long long document_id() const { return m_volume; }
    long long access_hash() const { return m_secret; }
private:
    int m_dc;
    long long m_volume; // == id in documents
    int m_local_id;  // not used for documents
    long long m_secret; // == access hash for documents
};

#endif // TGL_FILE_LOCATION

