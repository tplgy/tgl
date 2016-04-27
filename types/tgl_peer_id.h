#ifndef __TGL_PEER_ID_H__
#define __TGL_PEER_ID_H__

struct tgl_peer_id_t{
    int peer_type;
    int peer_id;
    long long access_hash;
    tgl_peer_id_t(): peer_type(0), peer_id(0), access_hash(0) { }
};

#endif
