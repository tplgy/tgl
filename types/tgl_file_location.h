#ifndef TGL_FILE_LOCATION
#define TGL_FILE_LOCATION

struct tgl_file_location {
    tgl_file_location()
        : m_dc(0)
        , m_volume(0)
        , m_local_id(0)
        , m_secret(0)
    { }

    int dc() const { return m_dc; }
    void set_dc(int d) { m_dc = d; }

    // regular files
    long long volume() const { return m_volume; }
    void set_volume(long long v) { m_volume = v; }
    int local_id() const { return m_local_id; }
    void set_local_id(int id) { m_local_id = id; }
    long long secret() const { return m_secret; }
    void set_secret(long long s) { m_secret = s; }

    // documents
    long long document_id() const { return m_volume; }
    long long access_hash() const { return m_secret; }

    int m_dc;
    long long m_volume; // == id in documents
    int m_local_id;  // not used for documents
    long long m_secret; // == access hash for documents
};

#endif // TGL_FILE_LOCATION
