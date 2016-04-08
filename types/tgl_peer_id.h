#ifndef __TGL_PEER_ID_H__
#define __TGL_PEER_ID_H__

struct tgl_peer_id_t{
    int peer_type;
    int peer_id;
    long long access_hash;
};

static const tgl_peer_id_t no_peer_id = { 0, 0, 0 };

#endif
