#include <crypto/internal/aead.h>
#include <linux/crypto.h>
#include <linux/ctype.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <linux/version.h>

#define AES_GCM_TAG_SIZE 16
#define AES_GCM_IV_SIZE 12
#define AES_GCM_KEY_SIZE 32
#define CRYPTO_ALG "gcm(aes)"

struct aes_gcm_ctx {
  struct crypto_aead *tfm;
  u8 iv[AES_GCM_IV_SIZE];
  u8 key[AES_GCM_KEY_SIZE];
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 18)

struct crypto_wait {
  struct completion completion;
  int err;
};

void crypto_req_done(struct crypto_async_request *req, int err) {
  struct crypto_wait *wait = req->data;

  if (err == -EINPROGRESS)
    return;

  wait->err = err;
  complete(&wait->completion);
}

EXPORT_SYMBOL_GPL(crypto_req_done);

static inline int crypto_wait_req(int err, struct crypto_wait *wait) {
  switch (err) {
  case -EINPROGRESS:
  case -EBUSY:
    wait_for_completion(&wait->completion);
    reinit_completion(&wait->completion);
    err = wait->err;
    break;
  }

  return err;
}

#define DECLARE_CRYPTO_WAIT(_wait)                                             \
  struct crypto_wait _wait = {                                                 \
      COMPLETION_INITIALIZER_ONSTACK((_wait).completion)}

#endif

static void cleanup_crypto_ctx(struct aes_gcm_ctx *ctx) {
  if (!ctx)
    return;

  if (ctx->tfm)
    crypto_free_aead(ctx->tfm);

  kfree(ctx);
}

void gen_key(u8 *buf, size_t len) { get_random_bytes(buf, len); }

static int init_ctx(struct aes_gcm_ctx *ctx) {
  int err = 0;
  ctx->tfm = crypto_alloc_aead(CRYPTO_ALG, 0, 0);
  if (IS_ERR(ctx->tfm)) {
    err = PTR_ERR(ctx->tfm);
    printk("crypto_alloc_aead() failed: %d\n", err);
    return err;
  }

  err = crypto_aead_setauthsize(ctx->tfm, AES_GCM_TAG_SIZE);
  if (err) {
    printk("crypto_aead_setauthsize() failed: %d\n", err);
    goto error;
  }

  get_random_bytes(ctx->key, sizeof(ctx->key));
  err = crypto_aead_setkey(ctx->tfm, ctx->key, sizeof(ctx->key));
  if (err) {
    pr_err("crypto_aead_setkey() failed: %d\n", err);
    goto error;
  }
  get_random_bytes(ctx->iv, sizeof(ctx->iv));
  return 0;
error:
  crypto_free_aead(ctx->tfm);
  return err;
}

int encrypt(struct aes_gcm_ctx *ctx, u8 *plaintext, u8 *ciphertext,
            size_t len) {
  struct aead_request *req = NULL;
  struct scatterlist sg_in, sg_out;
  DECLARE_CRYPTO_WAIT(wait);
  int err = 0;

  req = aead_request_alloc(ctx->tfm, GFP_KERNEL);
  if (req == NULL) {
    pr_err(KERN_ERR "aead_request_alloc() has failed.\n");
    return -ENOMEM;
  }

  sg_init_one(&sg_in, plaintext, len);
  sg_init_one(&sg_out, ciphertext, len + AES_GCM_TAG_SIZE);

  aead_request_set_callback(
      req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
      crypto_req_done, &wait);

  aead_request_set_crypt(req, &sg_in, &sg_out, len, ctx->iv);
  req->assoclen = 0;

  err = crypto_wait_req(crypto_aead_encrypt(req), &wait);
  if (err != 0) {
    pr_err(KERN_ERR "crypto_wait_req() error when encrypting data\n");
    goto out;
  }

  return 0;

out:
  aead_request_free(req);
  return err;
}

int decrypt(struct aes_gcm_ctx *ctx, u8 *plaintext, u8 *ciphertext,
            size_t len) {
  struct aead_request *req = NULL;
  struct scatterlist sg_in, sg_out;
  DECLARE_CRYPTO_WAIT(wait);
  int err = 0;

  req = aead_request_alloc(ctx->tfm, GFP_KERNEL);
  if (req == NULL) {
    pr_err(KERN_ERR "aead_request_alloc() has failed.\n");
    return -ENOMEM;
  }

  sg_init_one(&sg_in, ciphertext, len);
  sg_init_one(&sg_out, plaintext, len - AES_GCM_TAG_SIZE);

  aead_request_set_callback(
      req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
      crypto_req_done, &wait);

  aead_request_set_crypt(req, &sg_in, &sg_out, len, ctx->iv);
  req->assoclen = 0;

  err = crypto_wait_req(crypto_aead_decrypt(req), &wait);
  if (err != 0) {
    pr_err(KERN_ERR "crypto_wait_req() error when decrypting data\n");
    goto out;
  }

  return 0;

out:
  aead_request_free(req);
  return err;
}
