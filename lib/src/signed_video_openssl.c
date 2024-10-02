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
#include <openssl/ec.h>  // EC_*
#include <openssl/evp.h>  // EVP_*
#include <openssl/objects.h>  // OBJ_*
#include <openssl/pem.h>  // PEM_*
#include <openssl/rsa.h>  // RSA_*
#include <stdio.h>  // FILE, fopen, fclose
#include <stdlib.h>  // malloc, free, calloc

// Creating keys on Windows is currently not supported. Add dummy defines for Linux specific
// functions.
#if defined(_WIN32) || defined(_WIN64)
#define unlink(p) ((void)0)
#else
#include <unistd.h>  // unlink
#endif

#include "includes/signed_video_openssl.h"  // pem_pkey_t, sign_or_verify_data_t
#include "signed_video_defines.h"
#include "signed_video_internal.h"  // MAX_HASH_SIZE
#include "signed_video_openssl_internal.h"

/**
 * Object to keep a message digest as both an EVP_MD type and on serialized OID form. This
 * holds for both the hash algorithm used to hash NAL Units and the message digest used in
 * signing with RSA.
 */
typedef struct {
  unsigned char *encoded_oid;  // Serialized OID form
  size_t encoded_oid_size;  // Size of serialized OID form
  size_t size;  // The size of the produced message digest
  // Ownership NOT transferred to this struct
  const EVP_MD *type;
} message_digest_t;

/**
 * OpenSSL cryptographic object.
 */
typedef struct {
  EVP_MD_CTX *primary_ctx;  // Hashing context for computing the GOP hash.
  EVP_MD_CTX *secondary_ctx;  // Hashing context for NALUs split in parts.
  message_digest_t hash_algo;
} openssl_crypto_t;

static svrc_t
write_private_key_to_file(EVP_PKEY *pkey, const char *path_to_key);
static svrc_t
write_private_key_to_buffer(EVP_PKEY *pkey, pem_pkey_t *pem_key);
static svrc_t
create_rsa_private_key(const char *path_to_key, pem_pkey_t *pem_key);
static svrc_t
create_ecdsa_private_key(const char *path_to_key, pem_pkey_t *pem_key);
static char *
get_path_to_key(const char *dir_to_key, const char *key_filename);

#define PRIVATE_RSA_KEY_FILE "private_rsa_key.pem"
#define PRIVATE_ECDSA_KEY_FILE "private_ecdsa_key.pem"

#define DEFAULT_HASH_ALGO "sha256"

/* Frees a key represented by an EVP_PKEY_CTX object. */
void
openssl_free_key(void *key)
{
  EVP_PKEY_CTX_free((EVP_PKEY_CTX *)key);
}

/* Reads the |private_key| which is expected to be on PEM form and creates an EVP_PKEY
 * object out of it and sets it in |sign_data|. Further, enough memory for the signature
 * is allocated. */
SignedVideoReturnCode
openssl_private_key_malloc(sign_or_verify_data_t *sign_data,
    const char *private_key,
    size_t private_key_size)
{
  // Sanity check input
  if (!sign_data || !private_key || private_key_size == 0) return SV_INVALID_PARAMETER;

  EVP_PKEY_CTX *ctx = NULL;
  EVP_PKEY *signing_key = NULL;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    // Read private key
    BIO *bp = BIO_new_mem_buf(private_key, private_key_size);
    signing_key = PEM_read_bio_PrivateKey(bp, NULL, NULL, NULL);
    BIO_free(bp);
    SV_THROW_IF(!signing_key, SV_EXTERNAL_ERROR);

    // Read the maximum size of the signature that the |private_key| can generate
    size_t max_signature_size = EVP_PKEY_size(signing_key);
    SV_THROW_IF(max_signature_size == 0, SV_EXTERNAL_ERROR);
    sign_data->signature = malloc(max_signature_size);
    SV_THROW_IF(!sign_data->signature, SV_MEMORY);
    // Create a context from the |signing_key|
    ctx = EVP_PKEY_CTX_new(signing_key, NULL /* no engine */);
    SV_THROW_IF(!ctx, SV_EXTERNAL_ERROR);
    // Initialize key
    SV_THROW_IF(EVP_PKEY_sign_init(ctx) <= 0, SV_EXTERNAL_ERROR);

    if (EVP_PKEY_base_id(signing_key) == EVP_PKEY_RSA) {
      SV_THROW_IF(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0, SV_EXTERNAL_ERROR);
      // Set message digest type to sha256
      SV_THROW_IF(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0, SV_EXTERNAL_ERROR);
    }

    // Set the content in |sign_data|
    sign_data->max_signature_size = max_signature_size;
    sign_data->key = ctx;
  SV_CATCH()
  {
    free(sign_data->signature);
    sign_data->signature = NULL;
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;
  }
  SV_DONE(status)

  EVP_PKEY_free(signing_key);

  return status;
}

/* Reads the |pem_public_key| which is expected to be on PEM form and creates an EVP_PKEY
 * object out of it and sets it in |verify_data|. */
svrc_t
openssl_public_key_malloc(sign_or_verify_data_t *verify_data, pem_pkey_t *pem_public_key)
{
  // Sanity check input
  if (!verify_data || !pem_public_key) return SV_INVALID_PARAMETER;

  EVP_PKEY_CTX *ctx = NULL;
  EVP_PKEY *verification_key = NULL;
  const void *buf = pem_public_key->key;
  int buf_size = (int)(pem_public_key->key_size);

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    // Read public key
    SV_THROW_IF(!buf, SV_INVALID_PARAMETER);
    SV_THROW_IF(buf_size == 0, SV_INVALID_PARAMETER);

    BIO *bp = BIO_new_mem_buf(buf, buf_size);
    verification_key = PEM_read_bio_PUBKEY(bp, NULL, NULL, NULL);
    BIO_free(bp);
    SV_THROW_IF(!verification_key, SV_EXTERNAL_ERROR);

    // Create an EVP context
    ctx = EVP_PKEY_CTX_new(verification_key, NULL /* No engine */);
    SV_THROW_IF(!ctx, SV_EXTERNAL_ERROR);
    SV_THROW_IF(EVP_PKEY_verify_init(ctx) <= 0, SV_EXTERNAL_ERROR);
    if (EVP_PKEY_base_id(verification_key) == EVP_PKEY_RSA) {
      SV_THROW_IF(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0, SV_EXTERNAL_ERROR);
      SV_THROW_IF(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0, SV_EXTERNAL_ERROR);
    }

    // Free any existing key
    EVP_PKEY_CTX_free(verify_data->key);
    // Set the content in |verify_data|
    verify_data->key = ctx;
  SV_CATCH()
  {
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;
  }
  SV_DONE(status)

  EVP_PKEY_free(verification_key);

  return status;
}

/* Reads the public key from the private key. */
svrc_t
openssl_read_pubkey_from_private_key(sign_or_verify_data_t *sign_data, pem_pkey_t *pem_pkey)
{
  EVP_PKEY_CTX *ctx = NULL;
  EVP_PKEY *pkey = NULL;
  BIO *pub_bio = NULL;
  char *public_key = NULL;
  long public_key_size = 0;

  if (!sign_data) return SV_INVALID_PARAMETER;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    ctx = (EVP_PKEY_CTX *)sign_data->key;
    SV_THROW_IF(!ctx, SV_INVALID_PARAMETER);
    // Borrow the EVP_PKEY |pkey| from |ctx|.
    pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    SV_THROW_IF(!pkey, SV_EXTERNAL_ERROR);
    // Write public key to BIO.
    pub_bio = BIO_new(BIO_s_mem());
    SV_THROW_IF(!pub_bio, SV_EXTERNAL_ERROR);
    SV_THROW_IF(!PEM_write_bio_PUBKEY(pub_bio, pkey), SV_EXTERNAL_ERROR);

    // Copy public key from BIO to |public_key|.
    char *buf_pos = NULL;
    public_key_size = BIO_get_mem_data(pub_bio, &buf_pos);
    SV_THROW_IF(public_key_size <= 0, SV_EXTERNAL_ERROR);
    public_key = malloc(public_key_size);
    SV_THROW_IF(!public_key, SV_MEMORY);
    memcpy(public_key, buf_pos, public_key_size);

  SV_CATCH()
  SV_DONE(status)

  BIO_free(pub_bio);

  // Transfer ownership to |pem_pkey|.
  free(pem_pkey->key);
  pem_pkey->key = public_key;
  pem_pkey->key_size = public_key_size;

  return status;
}

/* Signs a hash. */
SignedVideoReturnCode
openssl_sign_hash(sign_or_verify_data_t *sign_data)
{
  // Sanity check input
  if (!sign_data) return SV_INVALID_PARAMETER;

  unsigned char *signature = sign_data->signature;
  const size_t max_signature_size = sign_data->max_signature_size;
  // Return if no memory has been allocated for the signature.
  if (!signature || max_signature_size == 0) return SV_INVALID_PARAMETER;

  EVP_PKEY_CTX *ctx = (EVP_PKEY_CTX *)sign_data->key;
  size_t siglen = 0;
  const uint8_t *hash_to_sign = sign_data->hash;
  size_t hash_size = sign_data->hash_size;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW_IF(!ctx, SV_INVALID_PARAMETER);
    // Determine required buffer length of the signature
    SV_THROW_IF(EVP_PKEY_sign(ctx, NULL, &siglen, hash_to_sign, hash_size) <= 0, SV_EXTERNAL_ERROR);
    // Check allocated space for signature
    SV_THROW_IF(siglen > max_signature_size, SV_MEMORY);
    // Finally sign hash with context
    SV_THROW_IF(
        EVP_PKEY_sign(ctx, signature, &siglen, hash_to_sign, hash_size) <= 0, SV_EXTERNAL_ERROR);
    // Set the actually written size of the signature. Depending on signing algorithm a shorter
    // signature may have been written.
    sign_data->signature_size = siglen;
  SV_CATCH()
  SV_DONE(status)

  return status;
}

/* Verifies the |signature|. */
svrc_t
openssl_verify_hash(const sign_or_verify_data_t *verify_data, int *verified_result)
{
  if (!verify_data || !verified_result) return SV_INVALID_PARAMETER;

  int verified_hash = -1;  // Initialize to 'error'.

  const unsigned char *signature = verify_data->signature;
  const size_t signature_size = verify_data->signature_size;
  const uint8_t *hash_to_verify = verify_data->hash;
  size_t hash_size = verify_data->hash_size;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW_IF(!signature || signature_size == 0 || !hash_to_verify, SV_INVALID_PARAMETER);
    EVP_PKEY_CTX *ctx = (EVP_PKEY_CTX *)verify_data->key;
    SV_THROW_IF(!ctx, SV_INVALID_PARAMETER);
    // EVP_PKEY_verify returns 1 upon success, 0 upon failure and < 0 upon error.
    verified_hash = EVP_PKEY_verify(ctx, signature, signature_size, hash_to_verify, hash_size);
  SV_CATCH()
  SV_DONE(status)

  *verified_result = verified_hash;

  return status;
}

/* Hashes the data using |hash_algo.type|. */
svrc_t
openssl_hash_data(void *handle, const uint8_t *data, size_t data_size, uint8_t *hash)
{
  openssl_crypto_t *self = (openssl_crypto_t *)handle;

  if (!data || data_size == 0 || !hash) return SV_INVALID_PARAMETER;
  if (!self->hash_algo.type) return SV_INVALID_PARAMETER;

  unsigned int hash_size = 0;
  int ret = EVP_Digest(data, data_size, hash, &hash_size, self->hash_algo.type, NULL);
  svrc_t status = hash_size == self->hash_algo.size ? SV_OK : SV_EXTERNAL_ERROR;
  return ret == 1 ? status : SV_EXTERNAL_ERROR;
}

/* Initializes a EVP_MD_CTX in |handle| with |hash_algo.type|. */
svrc_t
openssl_init_hash(void *handle, bool use_primary_ctx)
{
  if (!handle) return SV_INVALID_PARAMETER;
  openssl_crypto_t *self = (openssl_crypto_t *)handle;
  int ret = 0;
  EVP_MD_CTX **ctx = use_primary_ctx ? &self->primary_ctx : &self->secondary_ctx;
  if (*ctx) {
    // Message digest type already set in context. Initialize the hashing function.
    ret = EVP_DigestInit_ex(*ctx, NULL, NULL);
  } else {
    if (!self->hash_algo.type) return SV_INVALID_PARAMETER;
    // Create a new context and set message digest type.
    *ctx = EVP_MD_CTX_new();
    if (!(*ctx)) return SV_EXTERNAL_ERROR;
    // Set a message digest type and initialize the hashing function.
    ret = EVP_DigestInit_ex(*ctx, self->hash_algo.type, NULL);
  }
  return ret == 1 ? SV_OK : SV_EXTERNAL_ERROR;
}

/* Updates a EVP_MD_CTX in |handle| with |data|. */
svrc_t
openssl_update_hash(void *handle, const uint8_t *data, size_t data_size, bool use_primary_ctx)
{
  if (!data || data_size == 0 || !handle) return SV_INVALID_PARAMETER;

  openssl_crypto_t *self = (openssl_crypto_t *)handle;
  EVP_MD_CTX **ctx = use_primary_ctx ? &self->primary_ctx : &self->secondary_ctx;

  // Check if the context is valid.
  if (!(*ctx)) return SV_EXTERNAL_ERROR;

  // Update the "ongoing" hash with new data.
  return EVP_DigestUpdate(*ctx, data, data_size) == 1 ? SV_OK : SV_EXTERNAL_ERROR;
}

/* Finalizes a EVP_MD_CTX in |handle| and writes result to |hash|. */
svrc_t
openssl_finalize_hash(void *handle, uint8_t *hash, bool use_primary_ctx)
{
  if (!hash || !handle) return SV_INVALID_PARAMETER;

  openssl_crypto_t *self = (openssl_crypto_t *)handle;
  EVP_MD_CTX **ctx = use_primary_ctx ? &self->primary_ctx : &self->secondary_ctx;

  // Check if the context is valid.
  if (!(*ctx)) return SV_EXTERNAL_ERROR;

  unsigned int hash_size = 0;

  // Finalize the digest and write the |hash| to output.
  if (EVP_DigestFinal_ex(*ctx, hash, &hash_size) == 1) {
    return hash_size <= MAX_HASH_SIZE ? SV_OK : SV_EXTERNAL_ERROR;
  } else {
    return SV_EXTERNAL_ERROR;
  }
}

/* Given an message_digest_t object, this function reads the serialized data in |oid| and
 * sets its |type|. */
static svrc_t
oid_to_type(message_digest_t *self)
{
  ASN1_OBJECT *obj = NULL;
  const unsigned char *encoded_oid_ptr = NULL;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    // Point to the first byte of the OID. The |oid_ptr| will increment while decoding.
    encoded_oid_ptr = self->encoded_oid;
    SV_THROW_IF(
        !d2i_ASN1_OBJECT(&obj, &encoded_oid_ptr, self->encoded_oid_size), SV_EXTERNAL_ERROR);
    self->type = EVP_get_digestbyobj(obj);
    self->size = EVP_MD_size(self->type);
  SV_CATCH()
  SV_DONE(status)

  ASN1_OBJECT_free(obj);

  return status;
}

/* Given an ASN1_OBJECT |obj|, this function writes the serialized data |oid| and |type|
 * of an message_digest_t struct. */
static svrc_t
obj_to_oid_and_type(message_digest_t *self, const ASN1_OBJECT *obj)
{
  const EVP_MD *type = NULL;
  unsigned char *encoded_oid_ptr = NULL;
  size_t encoded_oid_size = 0;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW_IF(!obj, SV_INVALID_PARAMETER);
    type = EVP_get_digestbyobj(obj);
    SV_THROW_IF(!type, SV_EXTERNAL_ERROR);
    // Encode the OID into ASN1/DER format. Memory is allocated and transferred.
    encoded_oid_size = i2d_ASN1_OBJECT(obj, &encoded_oid_ptr);
    SV_THROW_IF(encoded_oid_size == 0 || !encoded_oid_ptr, SV_EXTERNAL_ERROR);

    self->type = type;
    free(self->encoded_oid);
    self->encoded_oid = encoded_oid_ptr;
    self->encoded_oid_size = encoded_oid_size;
    self->size = EVP_MD_size(type);
  SV_CATCH()
  SV_DONE(status)

  return status;
}

svrc_t
openssl_set_hash_algo(void *handle, const char *name_or_oid)
{
  openssl_crypto_t *self = (openssl_crypto_t *)handle;
  if (!self) return SV_INVALID_PARAMETER;
  // NULL pointer as input means default setting.
  if (!name_or_oid) {
    name_or_oid = DEFAULT_HASH_ALGO;
  }

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    ASN1_OBJECT *hash_algo_obj = OBJ_txt2obj(name_or_oid, 0 /* Accept both name and OID */);
    SV_THROW_IF_WITH_MSG(!hash_algo_obj, SV_INVALID_PARAMETER,
        "Could not identify hashing algorithm: %s", name_or_oid);
    SV_THROW(obj_to_oid_and_type(&self->hash_algo, hash_algo_obj));
    // Free the context to be able to assign a new message digest type to it.
    EVP_MD_CTX_free(self->primary_ctx);
    self->primary_ctx = NULL;
    EVP_MD_CTX_free(self->secondary_ctx);
    self->secondary_ctx = NULL;

    SV_THROW(openssl_init_hash(self, false));
    DEBUG_LOG("Setting hash algo %s that has ASN.1/DER coded OID length %zu", name_or_oid,
        self->hash_algo.encoded_oid_size);
  SV_CATCH()
  SV_DONE(status)

  return status;
}

svrc_t
openssl_set_hash_algo_by_encoded_oid(void *handle,
    const unsigned char *encoded_oid,
    size_t encoded_oid_size)
{
  openssl_crypto_t *self = (openssl_crypto_t *)handle;
  if (!self || !encoded_oid || encoded_oid_size == 0) return SV_INVALID_PARAMETER;

  // If the |encoded_oid| has not changed do nothing.
  if (encoded_oid_size == self->hash_algo.encoded_oid_size &&
      memcmp(encoded_oid, self->hash_algo.encoded_oid, encoded_oid_size) == 0) {
    return SV_OK;
  }

  // A new hash algorithm to set. Reset existing one.
  free(self->hash_algo.encoded_oid);
  self->hash_algo.encoded_oid = NULL;
  self->hash_algo.encoded_oid_size = 0;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    self->hash_algo.encoded_oid = malloc(encoded_oid_size);
    SV_THROW_IF(!self->hash_algo.encoded_oid, SV_MEMORY);
    memcpy(self->hash_algo.encoded_oid, encoded_oid, encoded_oid_size);
    self->hash_algo.encoded_oid_size = encoded_oid_size;

    SV_THROW(oid_to_type(&self->hash_algo));
  SV_CATCH()
  SV_DONE(status)

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

char *
openssl_encoded_oid_to_str(const unsigned char *encoded_oid, size_t encoded_oid_size)
{
  ASN1_OBJECT *obj = NULL;
  char *algo_name = calloc(1, 50);

  if (!encoded_oid || encoded_oid_size == 0) {
    goto done;
  }

  // Point to the first byte of the OID. The |oid_ptr| will increment while decoding.
  if (!d2i_ASN1_OBJECT(&obj, &encoded_oid, encoded_oid_size)) {
    goto done;
  }
  OBJ_obj2txt(algo_name, 50, obj, 1);

done:
  ASN1_OBJECT_free(obj);

  return algo_name;
}

size_t
openssl_get_hash_size(void *handle)
{
  if (!handle) return 0;

  return ((openssl_crypto_t *)handle)->hash_algo.size;
}

/* Creates a |handle| with a EVP_MD_CTX and hash algo. */
void *
openssl_create_handle(void)
{
  openssl_crypto_t *self = (openssl_crypto_t *)calloc(1, sizeof(openssl_crypto_t));
  if (!self) return NULL;

  if (openssl_set_hash_algo(self, DEFAULT_HASH_ALGO) != SV_OK) {
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
  EVP_MD_CTX_free(self->primary_ctx);
  EVP_MD_CTX_free(self->secondary_ctx);
  free(self->hash_algo.encoded_oid);
  free(self);
}

/* Helper functions to generate a private key. Only applicable on Linux platforms. */

/* Writes the content of |pkey| to a file in PEM format. */
static svrc_t
write_private_key_to_file(EVP_PKEY *pkey, const char *path_to_key)
{
  FILE *f_private = NULL;

  assert(pkey);
  if (!path_to_key) return SV_OK;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    f_private = fopen(path_to_key, "wb");
    SV_THROW_IF(!f_private, SV_EXTERNAL_ERROR);
    SV_THROW_IF(!PEM_write_PrivateKey(f_private, pkey, NULL, 0, 0, NULL, NULL), SV_EXTERNAL_ERROR);
  SV_CATCH()
  {
    if (f_private) unlink(path_to_key);
  }
  SV_DONE(status)

  if (f_private) fclose(f_private);

  return status;
}

/* Writes the content of |pkey| to a buffer in PEM format. */
static svrc_t
write_private_key_to_buffer(EVP_PKEY *pkey, pem_pkey_t *pem_key)
{
  BIO *pkey_bio = NULL;
  char *private_key = NULL;
  long private_key_size = 0;

  assert(pkey);
  if (!pem_key) return SV_OK;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    pkey_bio = BIO_new(BIO_s_mem());
    SV_THROW_IF(!pkey_bio, SV_EXTERNAL_ERROR);
    SV_THROW_IF(
        !PEM_write_bio_PrivateKey(pkey_bio, pkey, NULL, 0, 0, NULL, NULL), SV_EXTERNAL_ERROR);

    private_key_size = BIO_get_mem_data(pkey_bio, &private_key);
    SV_THROW_IF(private_key_size == 0 || !private_key, SV_EXTERNAL_ERROR);

    pem_key->key = malloc(private_key_size);
    SV_THROW_IF(!pem_key->key, SV_MEMORY);
    memcpy(pem_key->key, private_key, private_key_size);
    pem_key->key_size = private_key_size;

  SV_CATCH()
  SV_DONE(status)

  if (pkey_bio) BIO_free(pkey_bio);

  return status;
}

/* Creates a RSA private key and stores it as a PEM file in the designated location. Existing key
 * will be overwritten. */
static svrc_t
create_rsa_private_key(const char *path_to_key, pem_pkey_t *pem_key)
{
  EVP_PKEY *pkey = NULL;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    pkey = EVP_RSA_gen(2048);
    SV_THROW_IF(!pkey, SV_EXTERNAL_ERROR);

    SV_THROW(write_private_key_to_file(pkey, path_to_key));
    SV_THROW(write_private_key_to_buffer(pkey, pem_key));
  SV_CATCH()
  SV_DONE(status)

  EVP_PKEY_free(pkey);  // Free |pkey|, |rsa| struct will be freed automatically as well

  return status;
}

/* Creates a ECDSA private key and stores it as a PEM file in the designated location. Existing key
 * will be overwritten. */
static svrc_t
create_ecdsa_private_key(const char *path_to_key, pem_pkey_t *pem_key)
{
  EVP_PKEY *pkey = NULL;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    pkey = EVP_EC_gen(OSSL_EC_curve_nid2name(NID_X9_62_prime256v1));
    SV_THROW_IF(!pkey, SV_EXTERNAL_ERROR);

    SV_THROW(write_private_key_to_file(pkey, path_to_key));
    SV_THROW(write_private_key_to_buffer(pkey, pem_key));
  SV_CATCH()
  SV_DONE(status)

  if (pkey) EVP_PKEY_free(pkey);

  return status;
}

/* Joins a |key_filename| to |dir_to_key| to create a full path. */
static char *
get_path_to_key(const char *dir_to_key, const char *key_filename)
{
  size_t path_len = strlen(dir_to_key);
  const size_t str_len = path_len + strlen(key_filename) + 2;  // For '\0' and '/'
  char *str = calloc(1, str_len);
  if (!str) return NULL;

  strcpy(str, dir_to_key);
  // Add '/' if not exists
  if (dir_to_key[path_len - 1] != '/') strcat(str, "/");
  strcat(str, key_filename);

  return str;
}

SignedVideoReturnCode
signed_video_generate_ecdsa_private_key(const char *dir_to_key,
    char **private_key,
    size_t *private_key_size)
{
  if (!dir_to_key && (!private_key || !private_key_size)) return SV_INVALID_PARAMETER;

  pem_pkey_t pem_key = {0};
  char *full_path_to_private_key = NULL;
  if (dir_to_key) {
    full_path_to_private_key = get_path_to_key(dir_to_key, PRIVATE_ECDSA_KEY_FILE);
  }

  svrc_t status = create_ecdsa_private_key(full_path_to_private_key, &pem_key);
  free(full_path_to_private_key);
  if (private_key && private_key_size) {
    *private_key = pem_key.key;
    *private_key_size = pem_key.key_size;
  } else {
    // Free the key if it is not transferred to the user.
    free(pem_key.key);
  }

  return status;
}

SignedVideoReturnCode
signed_video_generate_rsa_private_key(const char *dir_to_key,
    char **private_key,
    size_t *private_key_size)
{
  if (!dir_to_key && (!private_key || !private_key_size)) return SV_INVALID_PARAMETER;

  pem_pkey_t pem_key = {0};
  char *full_path_to_private_key = NULL;
  if (dir_to_key) {
    full_path_to_private_key = get_path_to_key(dir_to_key, PRIVATE_RSA_KEY_FILE);
  }

  svrc_t status = create_rsa_private_key(full_path_to_private_key, &pem_key);
  free(full_path_to_private_key);
  if (private_key && private_key_size) {
    *private_key = pem_key.key;
    *private_key_size = pem_key.key_size;
  } else {
    // Free the key if it is not transferred to the user.
    free(pem_key.key);
  }

  return status;
}

/* TO BE DEPRECATED */
SignedVideoReturnCode
signed_video_generate_private_key(sign_algo_t algo,
    const char *dir_to_key,
    char **private_key,
    size_t *private_key_size)
{
  if (!dir_to_key && (!private_key || !private_key_size)) return SV_INVALID_PARAMETER;

  switch (algo) {
    case SIGN_ALGO_RSA:
      return signed_video_generate_rsa_private_key(dir_to_key, private_key, private_key_size);
    case SIGN_ALGO_ECDSA:
      return signed_video_generate_ecdsa_private_key(dir_to_key, private_key, private_key_size);
    default:
      return SV_NOT_SUPPORTED;
  }
}
