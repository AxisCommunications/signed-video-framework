/**
 * MIT License
 *
 * Copyright (c) 2021 Axis Communications AB
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next paragraph) shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include <assert.h>  // assert
// Include all openssl header files explicitly.
#include <openssl/asn1.h>  // ASN1_*
#include <openssl/bio.h>  // BIO_*
#include <openssl/bn.h>  // BN_*
#include <openssl/crypto.h>  // OPENSSL_malloc, OPENSSL_free
#include <openssl/ec.h>  // EC_*
#include <openssl/evp.h>  // EVP_*
#include <openssl/objects.h>  // OBJ_*
#include <openssl/opensslv.h>  // OPENSSL_VERSION_*
#include <openssl/pem.h>  // PEM_*
#include <openssl/rsa.h>  // RSA_*
#include <openssl/sha.h>  // SHA256
#include <stdbool.h>  // bool
#include <stdio.h>  // FILE, fopen, fclose
#include <stdlib.h>  // malloc, free, calloc

// We do not support creating keys on Windows. Adding dummy defines for Linux specific functions.
#if defined(_WIN32) || defined(_WIN64)
#define F_OK 0
#define R_OK 0x04
#define access(p, m) 0
#define unlink(p) ((void)0)
#else
#include <unistd.h>  // access, unlink, F_OK, R_OK
#endif

#include "includes/signed_video_openssl.h"
#include "signed_video_defines.h"
#include "signed_video_internal.h"  // svi_rc_to_signed_video_rc(), sv_rc_to_svi_rc()
#include "signed_video_openssl_internal.h"

/**
 * Object to keep the path structure used to create and read pem-files.
 */
typedef struct {
  // Null-terminated character string specifying the location of keys.
  char *path_to_key;
  // Null-terminated character string specifying the full path location to the private-key pem-file.
  char *full_path_to_private_key;
  // Buffer pointers to store the private key content.
  char **private_key;
  size_t *private_key_size;
} key_paths_t;

/**
 * Object to keep a message digest as both an EVP_MD type and on serialized OID form. This
 * holds for both the hash algorithm used to hash NAL Units and the message digest used in
 * signing.
 */
typedef struct {
  unsigned char *encoded_oid;  // Serialized OID form
  size_t encoded_oid_size;  // Size of serialized OID form
  // Ownership NOT transferred to this struct
  const EVP_MD *type;
} message_digest_t;

/**
 * OpenSSL cryptographic object.
 */
typedef struct {
  EVP_MD_CTX *ctx;  // Hashing context
  message_digest_t hash_algo;
} openssl_crypto_t;

static svi_rc
write_private_key_to_file(EVP_PKEY *pkey, const key_paths_t *key_paths);
static svi_rc
write_private_key_to_buffer(EVP_PKEY *pkey, const key_paths_t *key_paths);
static svi_rc
create_rsa_private_key(const key_paths_t *key_paths);
static svi_rc
create_ecdsa_private_key(const key_paths_t *key_paths);
static char *
get_path_to_key(const char *path_to_key, const char *key_filename);
static svi_rc
create_full_path(sign_algo_t algo, const char *path_to_key, key_paths_t *key_paths);
static svi_rc
openssl_create_private_key(sign_algo_t algo, const char *path_to_key, key_paths_t *key_paths);

#define PRIVATE_RSA_KEY_FILE "private_rsa_key.pem"
#define PRIVATE_ECDSA_KEY_FILE "private_ecdsa_key.pem"

#define DEFAULT_HASH_ALGO "sha256"

/* Frees an EVP_PKEY object. */
void
openssl_free_key(void *pkey)
{
  EVP_PKEY_CTX_free((EVP_PKEY_CTX *)pkey);
}

/* Reads the |private_key| which is expected to be on PEM form and creates an EVP_PKEY
 * object out of it and sets it in |signature_info|. Further, enough memory for the signature
 * is allocated. */
SignedVideoReturnCode
openssl_private_key_malloc(signature_info_t *signature_info,
    const char *private_key,
    size_t private_key_size)
{
  // Sanity check input
  if (!signature_info || !private_key || private_key_size == 0) return SV_INVALID_PARAMETER;

  EVP_PKEY_CTX *ctx = NULL;
  EVP_PKEY *signing_key = NULL;
  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    // Read private key
    BIO *bp = BIO_new_mem_buf(private_key, private_key_size);
    signing_key = PEM_read_bio_PrivateKey(bp, NULL, NULL, NULL);
    BIO_free(bp);
    SVI_THROW_IF(!signing_key, SVI_EXTERNAL_FAILURE);

    // Read the maximum size of the signature that the |private_key| can generate
    size_t max_signature_size = EVP_PKEY_size(signing_key);
    SVI_THROW_IF(max_signature_size == 0, SVI_EXTERNAL_FAILURE);
    signature_info->signature = malloc(max_signature_size);
    SVI_THROW_IF(!signature_info->signature, SVI_MEMORY);
    // Create a context from the |signing_key|
    ctx = EVP_PKEY_CTX_new(signing_key, NULL /* no engine */);
    SVI_THROW_IF(!ctx, SVI_EXTERNAL_FAILURE);
    // Initialize key
    SVI_THROW_IF(EVP_PKEY_sign_init(ctx) <= 0, SVI_EXTERNAL_FAILURE);

    if (EVP_PKEY_base_id(signing_key) == EVP_PKEY_RSA) {
      SVI_THROW_IF(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0, SVI_EXTERNAL_FAILURE);
    }
    // Set message digest type to sha256
    SVI_THROW_IF(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0, SVI_EXTERNAL_FAILURE);

    // Set the content in |signature_info|
    signature_info->max_signature_size = max_signature_size;
    signature_info->private_key = ctx;
  SVI_CATCH()
  {
    free(signature_info->signature);
    signature_info->signature = NULL;
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;
  }
  SVI_DONE(status)

  EVP_PKEY_free(signing_key);

  return svi_rc_to_signed_video_rc(status);
}

/* Reads the |pem_public_key| which is expected to be on PEM form and creates an EVP_PKEY
 * object out of it and sets it in |signature_info|. */
svi_rc
openssl_public_key_malloc(signature_info_t *signature_info, pem_pkey_t *pem_public_key)
{
  // Sanity check input
  if (!signature_info || !pem_public_key) return SVI_INVALID_PARAMETER;

  EVP_PKEY_CTX *ctx = NULL;
  EVP_PKEY *verification_key = NULL;
  const void *buf = pem_public_key->pkey;
  int buf_size = (int)(pem_public_key->pkey_size);
  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    // Read public key
    SVI_THROW_IF(!buf, SVI_INVALID_PARAMETER);
    SVI_THROW_IF(buf_size == 0, SVI_INVALID_PARAMETER);

    BIO *bp = BIO_new_mem_buf(buf, buf_size);
    verification_key = PEM_read_bio_PUBKEY(bp, NULL, NULL, NULL);
    BIO_free(bp);

    SVI_THROW_IF(!verification_key, SVI_EXTERNAL_FAILURE);
    // Create an EVP context
    ctx = EVP_PKEY_CTX_new(verification_key, NULL /* No engine */);
    SVI_THROW_IF(!ctx, SVI_EXTERNAL_FAILURE);
    SVI_THROW_IF(EVP_PKEY_verify_init(ctx) <= 0, SVI_EXTERNAL_FAILURE);
    if (EVP_PKEY_base_id(verification_key) == EVP_PKEY_RSA) {
      SVI_THROW_IF(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0, SVI_EXTERNAL_FAILURE);
    }
    SVI_THROW_IF(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0, SVI_EXTERNAL_FAILURE);

    // Free any existing key
    EVP_PKEY_CTX_free(signature_info->public_key);
    // Set the content in |signature_info|
    signature_info->public_key = ctx;
  SVI_CATCH()
  {
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;
  }
  SVI_DONE(status)

  EVP_PKEY_free(verification_key);

  return status;
}

/* Signs a hash. */
SignedVideoReturnCode
openssl_sign_hash(signature_info_t *signature_info)
{
  // Sanity check input
  if (!signature_info) return SV_INVALID_PARAMETER;

  unsigned char *signature = signature_info->signature;
  const size_t max_signature_size = signature_info->max_signature_size;
  // Return if no memory has been allocated for the signature.
  if (!signature || max_signature_size == 0) return SV_INVALID_PARAMETER;

  EVP_PKEY_CTX *ctx = (EVP_PKEY_CTX *)signature_info->private_key;
  size_t siglen = 0;
  const uint8_t *hash_to_sign = signature_info->hash;
  size_t hash_size = signature_info->hash_size;

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    SVI_THROW_IF(!ctx, SVI_INVALID_PARAMETER);
    // Determine required buffer length of the signature
    SVI_THROW_IF(
        EVP_PKEY_sign(ctx, NULL, &siglen, hash_to_sign, hash_size) <= 0, SVI_EXTERNAL_FAILURE);
    // Check allocated space for signature
    SVI_THROW_IF(siglen > max_signature_size, SVI_MEMORY);
    // Finally sign hash with context
    SVI_THROW_IF(
        EVP_PKEY_sign(ctx, signature, &siglen, hash_to_sign, hash_size) <= 0, SVI_EXTERNAL_FAILURE);
    // Set the actually written size of the signature. Depending on signing algorithm a shorter
    // signature may have been written.
    signature_info->signature_size = siglen;
  SVI_CATCH()
  SVI_DONE(status)

  return svi_rc_to_signed_video_rc(status);
}

/* Verifies the |signature|. */
svi_rc
openssl_verify_hash(const signature_info_t *signature_info, int *verified_result)
{
  if (!signature_info || !verified_result) return SVI_INVALID_PARAMETER;

  int verified_hash = -1;  // Initialize to 'error'.

  const unsigned char *signature = signature_info->signature;
  const size_t signature_size = signature_info->signature_size;
  const uint8_t *hash_to_verify = signature_info->hash;
  size_t hash_size = signature_info->hash_size;

  if (!signature || (signature_size == 0) || !hash_to_verify) return SVI_INVALID_PARAMETER;

  EVP_PKEY_CTX *ctx = (EVP_PKEY_CTX *)signature_info->public_key;

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    SVI_THROW_IF(!ctx, SVI_INVALID_PARAMETER);
    // EVP_PKEY_verify returns 1 indicates success, 0 verify failure and < 0 for some other error.
    verified_hash = EVP_PKEY_verify(ctx, signature, signature_size, hash_to_verify, hash_size);
  SVI_CATCH()
  SVI_DONE(status)

  *verified_result = verified_hash;

  return status;
}

/* Writes the content of |pkey| to a file in PEM format. */
static svi_rc
write_private_key_to_file(EVP_PKEY *pkey, const key_paths_t *key_paths)
{
  FILE *f_private = NULL;

  assert(key_paths && pkey);
  if (!key_paths->full_path_to_private_key) return SVI_OK;

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    f_private = fopen(key_paths->full_path_to_private_key, "wb");
    SVI_THROW_IF(!f_private, SVI_FILE);
    SVI_THROW_IF(
        !PEM_write_PrivateKey(f_private, pkey, NULL, 0, 0, NULL, NULL), SVI_EXTERNAL_FAILURE);
  SVI_CATCH()
  {
    if (f_private) unlink(key_paths->full_path_to_private_key);
  }
  SVI_DONE(status)

  if (f_private) fclose(f_private);

  return status;
}

/* Writes the content of |pkey| to a buffer in PEM format. */
static svi_rc
write_private_key_to_buffer(EVP_PKEY *pkey, const key_paths_t *key_paths)
{
  BIO *pkey_bio = NULL;
  char *private_key = NULL;
  long private_key_size = 0;

  assert(key_paths && pkey);
  if (!key_paths->private_key || !key_paths->private_key_size) return SVI_OK;

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    pkey_bio = BIO_new(BIO_s_mem());
    SVI_THROW_IF(!pkey_bio, SVI_EXTERNAL_FAILURE);
    SVI_THROW_IF(
        !PEM_write_bio_PrivateKey(pkey_bio, pkey, NULL, 0, 0, NULL, NULL), SVI_EXTERNAL_FAILURE);

    private_key_size = BIO_get_mem_data(pkey_bio, &private_key);
    SVI_THROW_IF(private_key_size == 0 || !private_key, SVI_EXTERNAL_FAILURE);

    *(key_paths->private_key) = malloc(private_key_size);
    SVI_THROW_IF(!*(key_paths->private_key), SVI_MEMORY);
    memcpy(*(key_paths->private_key), private_key, private_key_size);
    *(key_paths->private_key_size) = private_key_size;

  SVI_CATCH()
  SVI_DONE(status)

  if (pkey_bio) BIO_free(pkey_bio);

  return status;
}

/* Creates a RSA private key and stores it as a PEM file in the designated location. Existing key
 * will be overwritten. */
static svi_rc
create_rsa_private_key(const key_paths_t *key_paths)
{
  if (!key_paths) return SVI_INVALID_PARAMETER;

  EVP_PKEY *pkey = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
  BIGNUM *bn = NULL;
  RSA *rsa = NULL;

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    // Init RSA context, evp key and big number
    rsa = RSA_new();
    SVI_THROW_IF(!rsa, SVI_EXTERNAL_FAILURE);
    pkey = EVP_PKEY_new();
    SVI_THROW_IF(!pkey, SVI_EXTERNAL_FAILURE);
    bn = BN_new();
    SVI_THROW_IF(!bn, SVI_EXTERNAL_FAILURE);

    // Set exponent to 65537
    BN_set_word(bn, RSA_F4);

    SVI_THROW_IF(!RSA_generate_key_ex(rsa, 2048, bn, NULL), SVI_EXTERNAL_FAILURE);

    // Set |pkey| to use the newly generated RSA key
    SVI_THROW_IF(!EVP_PKEY_assign_RSA(pkey, rsa), SVI_EXTERNAL_FAILURE);

    SVI_THROW(write_private_key_to_file(pkey, key_paths));
    SVI_THROW(write_private_key_to_buffer(pkey, key_paths));
  SVI_CATCH()
  {
    if (rsa && !pkey) RSA_free(rsa);
  }
  SVI_DONE(status)

  BN_free(bn);
#else
  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    pkey = EVP_RSA_gen(2048);
    SVI_THROW_IF(!pkey, SVI_EXTERNAL_FAILURE);

    SVI_THROW(write_private_key_to_file(pkey, key_paths));
    SVI_THROW(write_private_key_to_buffer(pkey, key_paths));
  SVI_CATCH()
  SVI_DONE(status)

#endif
  EVP_PKEY_free(pkey);  // Free |pkey|, |rsa| struct will be freed automatically as well

  return status;
}

/* Creates a ECDSA private key and stores it as a PEM file in the designated location. Existing key
 * will be overwritten. */
static svi_rc
create_ecdsa_private_key(const key_paths_t *key_paths)
{
  if (!key_paths) return SVI_INVALID_PARAMETER;

  EVP_PKEY *pkey = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
  EC_KEY *ec_key = NULL;

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    SVI_THROW_IF(!ec_key, SVI_EXTERNAL_FAILURE);
    SVI_THROW_IF(EC_KEY_generate_key(ec_key) != 1, SVI_EXTERNAL_FAILURE);

    pkey = EVP_PKEY_new();
    SVI_THROW_IF(!pkey, SVI_EXTERNAL_FAILURE);
    SVI_THROW_IF(EVP_PKEY_assign_EC_KEY(pkey, ec_key) != 1, SVI_EXTERNAL_FAILURE);

    SVI_THROW(write_private_key_to_file(pkey, key_paths));
    SVI_THROW(write_private_key_to_buffer(pkey, key_paths));

  SVI_CATCH()
  {
    if (ec_key && !pkey) EC_KEY_free(ec_key);
  }
  SVI_DONE(status)
#else

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    pkey = EVP_EC_gen(OSSL_EC_curve_nid2name(NID_X9_62_prime256v1));
    SVI_THROW_IF(!pkey, SVI_EXTERNAL_FAILURE);

    SVI_THROW(write_private_key_to_file(pkey, key_paths));
    SVI_THROW(write_private_key_to_buffer(pkey, key_paths));
  SVI_CATCH()
  SVI_DONE(status)
#endif

  if (pkey) EVP_PKEY_free(pkey);

  return status;
}

/* Joins a |key_filename| to |path_to_key| to create a full path. */
static char *
get_path_to_key(const char *path_to_key, const char *key_filename)
{
  size_t path_len = strlen(path_to_key);
  const size_t str_len = path_len + strlen(key_filename) + 2;  // For '\0' and '/'
  char *str = calloc(1, str_len);
  if (!str) return NULL;

  strcpy(str, path_to_key);
  // Add '/' if not exists
  if (path_to_key[path_len - 1] != '/') strcat(str, "/");
  strcat(str, key_filename);

  return str;
}

/* Creates a path string to private key PEM file. */
static svi_rc
create_full_path(sign_algo_t algo, const char *path_to_key, key_paths_t *key_paths)
{
  assert(key_paths);
  // Return directly if |path_to_key| is NULL or already exist
  if (!path_to_key) return SVI_OK;
  if (key_paths->path_to_key && (strcmp(key_paths->path_to_key, path_to_key) == 0)) return SVI_OK;

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    // Sanity check signing algorithm.
    bool is_rsa = (algo == SIGN_ALGO_RSA);
    SVI_THROW_IF(!is_rsa && (algo != SIGN_ALGO_ECDSA), SVI_NOT_SUPPORTED);

    // Store path to folder with keys.
    char *str = malloc(strlen(path_to_key) + 1);  // Including '\0'
    SVI_THROW_IF(!str, SVI_MEMORY);
    strcpy(str, path_to_key);
    free(key_paths->path_to_key);
    key_paths->path_to_key = str;

    // Store full path to private key.
    char *filename = is_rsa ? PRIVATE_RSA_KEY_FILE : PRIVATE_ECDSA_KEY_FILE;
    char *full_path_to_private_key = get_path_to_key(key_paths->path_to_key, filename);
    SVI_THROW_IF(!full_path_to_private_key, SVI_MEMORY);
    free(key_paths->full_path_to_private_key);
    key_paths->full_path_to_private_key = full_path_to_private_key;

  SVI_CATCH()
  {
    free(key_paths->path_to_key);
    key_paths->path_to_key = NULL;
    free(key_paths->full_path_to_private_key);
    key_paths->full_path_to_private_key = NULL;
  }
  SVI_DONE(status)

  return status;
}

/* Hashes the data using |hash_algo.type|. */
svi_rc
openssl_hash_data(void *handle, const uint8_t *data, size_t data_size, uint8_t *hash)
{
  openssl_crypto_t *self = (openssl_crypto_t *)handle;

  if (!data || data_size == 0 || !hash) return SVI_INVALID_PARAMETER;
  if (!self->hash_algo.type) return SVI_INVALID_PARAMETER;

  unsigned int hash_size = 0;
  int ret = EVP_Digest(data, data_size, hash, &hash_size, self->hash_algo.type, NULL);
  svi_rc status = hash_size == SHA256_HASH_SIZE ? SVI_OK : SVI_EXTERNAL_FAILURE;
  return ret == 1 ? status : SVI_EXTERNAL_FAILURE;
}

/* Initializes EVP_MD_CTX in |handle| with |hash_algo.type|. */
svi_rc
openssl_init_hash(void *handle)
{
  if (!handle) return SVI_INVALID_PARAMETER;
  openssl_crypto_t *self = (openssl_crypto_t *)handle;
  int ret = 0;

  if (self->ctx) {
    // Message digest type already set in context. Initialize the hashing function.
    ret = EVP_DigestInit_ex(self->ctx, NULL, NULL);
  } else {
    if (!self->hash_algo.type) return SVI_INVALID_PARAMETER;
    // Create a new context and set message digest type.
    self->ctx = EVP_MD_CTX_new();
    if (!self->ctx) return SVI_EXTERNAL_FAILURE;
    // Set a message digest type and initialize the hashing function.
    ret = EVP_DigestInit_ex(self->ctx, self->hash_algo.type, NULL);
  }

  return ret == 1 ? SVI_OK : SVI_EXTERNAL_FAILURE;
}

/* Updates EVP_MD_CTX in |handle| with |data|. */
svi_rc
openssl_update_hash(void *handle, const uint8_t *data, size_t data_size)
{
  if (!data || data_size == 0 || !handle) return SVI_INVALID_PARAMETER;
  openssl_crypto_t *self = (openssl_crypto_t *)handle;
  // Update the "ongoing" hash with new data.
  if (!self->ctx) return SVI_EXTERNAL_FAILURE;
  return EVP_DigestUpdate(self->ctx, data, data_size) == 1 ? SVI_OK : SVI_EXTERNAL_FAILURE;
}

/* Finalizes EVP_MD_CTX in |handle| and writes result to |hash|. */
svi_rc
openssl_finalize_hash(void *handle, uint8_t *hash)
{
  if (!hash || !handle) return SVI_INVALID_PARAMETER;
  openssl_crypto_t *self = (openssl_crypto_t *)handle;
  // Finalize and write the |hash| to output.
  if (!self->ctx) return SVI_EXTERNAL_FAILURE;
  unsigned int hash_size = 0;
  if (EVP_DigestFinal_ex(self->ctx, hash, &hash_size) == 1) {
    return hash_size <= MAX_HASH_SIZE ? SVI_OK : SVI_EXTERNAL_FAILURE;
  } else {
    return SVI_EXTERNAL_FAILURE;
  }
}

/* Given an message_digest_t object, this function reads the serialized data in |oid| and
 * sets its |type|. */
static svi_rc
oid_to_type(message_digest_t *self)
{
  ASN1_OBJECT *obj = NULL;
  const unsigned char *encoded_oid_ptr = NULL;

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    // Point to the first byte of the OID. The |oid_ptr| will increment while decoding.
    encoded_oid_ptr = self->encoded_oid;
    SVI_THROW_IF(
        !d2i_ASN1_OBJECT(&obj, &encoded_oid_ptr, self->encoded_oid_size), SVI_EXTERNAL_FAILURE);
    self->type = EVP_get_digestbyobj(obj);
  SVI_CATCH()
  SVI_DONE(status)

  ASN1_OBJECT_free(obj);

  return status;
}

/* Given an ASN1_OBJECT |obj|, this function writes the serialized data |oid| and |type|
 * of an message_digest_t struct. */
static svi_rc
obj_to_oid_and_type(message_digest_t *self, const ASN1_OBJECT *obj)
{
  const EVP_MD *type = NULL;
  unsigned char *encoded_oid_ptr = NULL;
  size_t encoded_oid_size = 0;

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    SVI_THROW_IF(!obj, SVI_INVALID_PARAMETER);
    type = EVP_get_digestbyobj(obj);
    SVI_THROW_IF(!type, SVI_EXTERNAL_FAILURE);
    // Encode the OID into ASN1/DER format. Memory is allocated and transferred.
    encoded_oid_size = i2d_ASN1_OBJECT(obj, &encoded_oid_ptr);
    SVI_THROW_IF(encoded_oid_size == 0 || !encoded_oid_ptr, SVI_EXTERNAL_FAILURE);

    self->type = type;
    free(self->encoded_oid);
    self->encoded_oid = encoded_oid_ptr;
    self->encoded_oid_size = encoded_oid_size;
  SVI_CATCH()
  SVI_DONE(status)

  return status;
}

/* Creates a |handle| with a EVP_MD_CTX and hash algo. */
void *
openssl_create_handle(void)
{
  openssl_crypto_t *self = (openssl_crypto_t *)calloc(1, sizeof(openssl_crypto_t));
  if (!self) return NULL;

  if (openssl_set_hash_algo(self, DEFAULT_HASH_ALGO) != SVI_OK) {
    openssl_free_handle(self);
    self = NULL;
  }

  return (void *)self;
}

/* Frees the |handle|. */
void
openssl_free_handle(void *handle)
{
  openssl_crypto_t *self = (openssl_crypto_t *)handle;
  if (!self) return;
  EVP_MD_CTX_free(self->ctx);
  free(self->hash_algo.encoded_oid);
  free(self);
}

svi_rc
openssl_set_hash_algo(void *handle, const char *name_or_oid)
{
  openssl_crypto_t *self = (openssl_crypto_t *)handle;
  if (!self) return SVI_INVALID_PARAMETER;
  // NULL pointer as input means default setting.
  if (!name_or_oid) {
    name_or_oid = DEFAULT_HASH_ALGO;
  }

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    ASN1_OBJECT *hash_algo_obj = OBJ_txt2obj(name_or_oid, 0 /* Accept both name and OID */);
    SVI_THROW_IF_WITH_MSG(!hash_algo_obj, SVI_INVALID_PARAMETER,
        "Could not identify hashing algorithm: %s", name_or_oid);
    SVI_THROW(obj_to_oid_and_type(&self->hash_algo, hash_algo_obj));
    // Free the context to be able to assign a new message digest type to it.
    EVP_MD_CTX_free(self->ctx);
    self->ctx = NULL;

    SVI_THROW(openssl_init_hash(self));
    DEBUG_LOG("Setting hash algo %s that has ASN.1/DER coded OID length %zu", name_or_oid,
        self->hash_algo.encoded_oid_size);
  SVI_CATCH()
  SVI_DONE(status)

  return status;
}

svi_rc
openssl_set_hash_algo_by_encoded_oid(void *handle,
    const unsigned char *encoded_oid,
    size_t encoded_oid_size)
{
  openssl_crypto_t *self = (openssl_crypto_t *)handle;
  if (!self || !encoded_oid || encoded_oid_size == 0) return SVI_INVALID_PARAMETER;

  // If the |encoded_oid| has not changed do nothing.
  if (encoded_oid_size == self->hash_algo.encoded_oid_size &&
      memcmp(encoded_oid, self->hash_algo.encoded_oid, encoded_oid_size) == 0) {
    return SVI_OK;
  }

  // A new hash algorithm to set. Reset existing one.
  free(self->hash_algo.encoded_oid);
  self->hash_algo.encoded_oid = NULL;
  self->hash_algo.encoded_oid_size = 0;

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    self->hash_algo.encoded_oid = malloc(encoded_oid_size);
    SVI_THROW_IF(!self->hash_algo.encoded_oid, SVI_MEMORY);
    memcpy(self->hash_algo.encoded_oid, encoded_oid, encoded_oid_size);
    self->hash_algo.encoded_oid_size = encoded_oid_size;

    SVI_THROW(oid_to_type(&self->hash_algo));
  SVI_CATCH()
  SVI_DONE(status)

  return status;
}

const unsigned char *
openssl_get_hash_algo_encoded_oid(void *handle, size_t *encoded_oid_size)
{
  openssl_crypto_t *self = (openssl_crypto_t *)handle;
  if (!self || encoded_oid_size == 0) return NULL;

  *encoded_oid_size = self->hash_algo.encoded_oid_size;
  return (const unsigned char *)self->hash_algo.encoded_oid;
}

/*
 * Creates a private key in a specified location
 *
 * A private key PEM-file is created. Use openssl_read_pubkey_from_private_key() to read the
 * public_key from the private_key.
 */
static svi_rc
openssl_create_private_key(sign_algo_t algo, const char *path_to_key, key_paths_t *key_paths)
{
  if (path_to_key && strlen(path_to_key) == 0) return SVI_INVALID_PARAMETER;

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    // Create paths if needed.
    SVI_THROW(create_full_path(algo, path_to_key, key_paths));
    // Generate keys
    if (algo == SIGN_ALGO_RSA) {
      SVI_THROW(create_rsa_private_key(key_paths));
    } else if (algo == SIGN_ALGO_ECDSA) {
      SVI_THROW(create_ecdsa_private_key(key_paths));
    } else {
      SVI_THROW(SVI_NOT_SUPPORTED);
    }
  SVI_CATCH()
  SVI_DONE(status)

  return status;
}

/* Reads the public key from the private key. */
svi_rc
openssl_read_pubkey_from_private_key(signature_info_t *signature_info, pem_pkey_t *pem_pkey)
{
  EVP_PKEY_CTX *ctx = NULL;
  EVP_PKEY *pkey = NULL;
  BIO *pub_bio = NULL;
  char *public_key = NULL;
  long public_key_size = 0;

  if (!signature_info) return SVI_INVALID_PARAMETER;

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    ctx = (EVP_PKEY_CTX *)signature_info->private_key;
    SVI_THROW_IF(!ctx, SVI_INVALID_PARAMETER);
    // Borrow the EVP_PKEY |pkey| from |ctx|.
    pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    SVI_THROW_IF(!pkey, SVI_EXTERNAL_FAILURE);
    // Write public key to BIO.
    pub_bio = BIO_new(BIO_s_mem());
    SVI_THROW_IF(!pub_bio, SVI_EXTERNAL_FAILURE);
    SVI_THROW_IF(!PEM_write_bio_PUBKEY(pub_bio, pkey), SVI_EXTERNAL_FAILURE);

    // Copy public key from BIO to |public_key|.
    char *buf_pos = NULL;
    public_key_size = BIO_get_mem_data(pub_bio, &buf_pos);
    SVI_THROW_IF(public_key_size <= 0, SVI_EXTERNAL_FAILURE);
    public_key = malloc(public_key_size);
    SVI_THROW_IF(!public_key, SVI_MEMORY);
    memcpy(public_key, buf_pos, public_key_size);

  SVI_CATCH()
  SVI_DONE(status)

  BIO_free(pub_bio);

  // Transfer ownership to |pem_pkey|.
  free(pem_pkey->pkey);
  pem_pkey->pkey = public_key;
  pem_pkey->pkey_size = public_key_size;

  return status;
}

/* Helper function to generate a private key. Only applicable on Linux platforms. */
SignedVideoReturnCode
signed_video_generate_private_key(sign_algo_t algo,
    const char *path_to_key,
    char **private_key,
    size_t *private_key_size)
{
  if (!path_to_key && (!private_key || !private_key_size)) return SV_INVALID_PARAMETER;

  key_paths_t key_paths = {.path_to_key = NULL,
      .full_path_to_private_key = NULL,
      .private_key = private_key,
      .private_key_size = private_key_size};
  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    SVI_THROW_IF_WITH_MSG(
        algo < 0 || algo >= SIGN_ALGO_NUM, SVI_NOT_SUPPORTED, "Algo is not supported");
    SVI_THROW(openssl_create_private_key(algo, path_to_key, &key_paths));

  SVI_CATCH()
  SVI_DONE(status)

  free(key_paths.path_to_key);
  free(key_paths.full_path_to_private_key);

  return svi_rc_to_signed_video_rc(status);
}
