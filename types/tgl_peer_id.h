#ifndef PEER_ID_H
#define PEER_ID_H

struct tgl_peer_id {
    int type;
    int id;
    long long access_hash;
};

#endif // PEER_ID_H

