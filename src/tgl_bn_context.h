#include "crypto/tgl_crypto_bn.h"

struct tgl_bn_context {
    std::unique_ptr<TGLC_bn_ctx, TGLC_bn_ctx_deleter> ctx;
};
