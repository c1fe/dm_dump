
 /*
  * context holding the current state of a multi-part conversion
  */
 struct convert_context {
         struct completion restart;
         struct bio *bio_in;
         struct bio *bio_out;
         unsigned int offset_in;
         unsigned int offset_out;
         unsigned int idx_in;
         unsigned int idx_out;
         sector_t cc_sector;
         atomic_t cc_pending;
 };
 
 /*
  * per bio private data
  */
 struct dm_crypt_io {
         struct crypt_config *cc;
         struct bio *base_bio;
         struct work_struct work;
 
         struct convert_context ctx;
 
         atomic_t io_pending;
         int error;
         sector_t sector;
         struct dm_crypt_io *base_io;
 };
 
 struct dm_crypt_request {
         struct convert_context *ctx;
         struct scatterlist sg_in;
         struct scatterlist sg_out;
         sector_t iv_sector;
 };
 
 struct crypt_config;
 
 struct crypt_iv_operations {
         int (*ctr)(struct crypt_config *cc, struct dm_target *ti,
                    const char *opts);
         void (*dtr)(struct crypt_config *cc);
         int (*init)(struct crypt_config *cc);
         int (*wipe)(struct crypt_config *cc);
         int (*generator)(struct crypt_config *cc, u8 *iv,
                          struct dm_crypt_request *dmreq);
         int (*post)(struct crypt_config *cc, u8 *iv,
                     struct dm_crypt_request *dmreq);
 };
 
 struct iv_essiv_private {
         struct crypto_hash *hash_tfm;
         u8 *salt;
 };
 
 struct iv_benbi_private {
         int shift;
 };
 
 #define LMK_SEED_SIZE 64 /* hash + 0 */
 struct iv_lmk_private {
         struct crypto_shash *hash_tfm;
         u8 *seed;
 };
 
 /*
  * Crypt: maps a linear range of a block device
  * and encrypts / decrypts at the same time.
  */
 enum flags { DM_CRYPT_SUSPENDED, DM_CRYPT_KEY_VALID };
 
 /*
  * Duplicated per-CPU state for cipher.
  */
 struct crypt_cpu {
         struct ablkcipher_request *req;
 };
 
 /*
  * The fields in here must be read only after initialization,
  * changing state should be in crypt_cpu.
  */
 struct crypt_config {
         struct dm_dev *dev;
         sector_t start;
 
         /*
          * pool for per bio private data, crypto requests and
          * encryption requeusts/buffer pages
          */
         mempool_t *io_pool;
         mempool_t *req_pool;
         mempool_t *page_pool;
         struct bio_set *bs;
 
         struct workqueue_struct *io_queue;
         struct workqueue_struct *crypt_queue;
 
         char *cipher;
         char *cipher_string;
 
         struct crypt_iv_operations *iv_gen_ops;
         union {
                 struct iv_essiv_private essiv;
                 struct iv_benbi_private benbi;
                 struct iv_lmk_private lmk;
         } iv_gen_private;
         sector_t iv_offset;
         unsigned int iv_size;
 
         /*
          * Duplicated per cpu state. Access through
          * per_cpu_ptr() only.
          */
         struct crypt_cpu __percpu *cpu;
 
         /* ESSIV: struct crypto_cipher *essiv_tfm */
         void *iv_private;
         struct crypto_ablkcipher **tfms;
         unsigned tfms_count;
 
         /*
          * Layout of each crypto request:
          *
          *   struct ablkcipher_request
          *      context
          *      padding
          *   struct dm_crypt_request
          *      padding
          *   IV
          *
          * The padding is added so that dm_crypt_request and the IV are
          * correctly aligned.
          */
         unsigned int dmreq_start;
 
         unsigned long flags;
         unsigned int key_size;
         unsigned int key_parts;
         u8 key[0];
 };
