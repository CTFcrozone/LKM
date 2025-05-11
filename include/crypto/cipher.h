#include <crypto/internal/aead.h>
#include <linux/crypto.h>
#include <linux/ctype.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <linux/version.h>

#define AES_KEY_SIZE 16
#define AES_TAG_SIZE 16
#define CRYPTO_ALG "gcm(aes)"

static struct crypto_aead *gcm_tfm;

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

void cleanup(struct crypto_aead *tfm, struct aead_request *aead_req,
             u8 *buffer) {
  if (aead_req) {
    aead_request_free(aead_req);
    printk(KERN_INFO "Cleaned up AEAD request\n");
  }

  if (tfm) {
    crypto_free_aead(tfm);
    printk(KERN_INFO "Cleaned up AEAD transform\n");
  }

  if (buffer) {
    kfree(buffer);
    printk(KERN_INFO "Cleaned up buffer\n");
  }
}

// maybe some better KDF but works anyways
void gen_key(u8 *buf) { get_random_bytes(buf, sizeof(buf)); }

int aes_gcm_crypto_init(struct crypto_aead **gcm_tfm) {
  DECLARE_CRYPTO_WAIT(wait);

  // u8 iv[12] = {0};
  u8 key[32] = {0};

  int err = -1;

  *gcm_tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
  if (IS_ERR(*gcm_tfm)) {
    printk(KERN_ERR "AES_GCM: Failed to allocate TFM\n");
    crypto_free_aead(*gcm_tfm);
    return PTR_ERR(*gcm_tfm);
  }

  err = crypto_aead_setauthsize(*gcm_tfm, AES_TAG_SIZE);

  if (err != 0) {
    printk(KERN_ERR "AES_GCM: Failed to set authsize\n");
    crypto_free_aead(*gcm_tfm);
    return err;
  }

  gen_key(key);

  err = crypto_aead_setkey(*gcm_tfm, key, sizeof(key));
  if (err != 0) {
    printk(KERN_ERR "AES_GCM: Failed to set the key\n");
    crypto_free_aead(*gcm_tfm);
    return err;
  }

  return 0;
}

// void crypt(...){}
