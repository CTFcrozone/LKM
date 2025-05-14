#include "./cipher.h"
#include <crypto/ecdh.h>
#include <crypto/internal/aead.h>
#include <crypto/kpp.h>
#include <linux/crypto.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <linux/version.h>

#define ALG_NAME "ecdh"

struct kpp_ctx {
  struct crypto_kpp *tfm;
  u8 private_key[AES_GCM_KEY_SIZE];
};

static int init_kpp_ctx(struct kpp_ctx *kpp_ctx, struct aes_gcm_ctx *ctx) {
  int err = 0;
  struct ecdh ecdh;
  u8 *enc_key = NULL;
  unsigned int enc_len;
  kpp_ctx->tfm = crypto_alloc_kpp(ALG_NAME, 0, 0);
  if (IS_ERR(kpp_ctx->tfm)) {
    err = PTR_ERR(kpp_ctx->tfm);
    printk("crypto_alloc_kpp() failed: %d\n", err);
    return err;
  }

  memcpy(kpp_ctx->private_key, ctx->key, AES_GCM_KEY_SIZE);

  ecdh.key = kpp_ctx->private_key;
  ecdh.key_size = AES_GCM_KEY_SIZE;
  // ecdh.curve_id = ECC_CURVE_NIST_P256; fuck the docs :/

  enc_len = crypto_ecdh_key_len(&ecdh);
  enc_key = kmalloc(enc_len, GFP_KERNEL);
  if (enc_key == NULL) {
    err = -ENOMEM;
    goto error;
  }

  err = crypto_ecdh_encode_key(enc_key, enc_len, &ecdh);
  if (err != 0) {
    printk("crypto_ecdh_encode_key failed: %d\n", err);
    kfree(enc_key);
    goto error;
  }

  err = crypto_kpp_set_secret(kpp_ctx->tfm, enc_key, enc_len);
  if (err != 0) {
    printk("crypto_kpp_set_secret failed: %d\n", err);
    kfree(enc_key);
    goto error;
  }
  kfree(enc_key);
  return 0;
error:
  crypto_free_kpp(kpp_ctx->tfm);
  return err;
}
