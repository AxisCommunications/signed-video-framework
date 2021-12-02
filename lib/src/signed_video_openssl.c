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
#include <openssl/bio.h>  // BIO_*
#include <openssl/bn.h>  // BN_*
#include <openssl/crypto.h>  // OPENSSL_malloc, OPENSSL_free
#include <openssl/ec.h>  // EC_*
#include <openssl/evp.h>  // EVP_*
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

static svi_rc
create_rsa_private_key(const key_paths_t *key_paths);
static svi_rc
create_ecdsa_private_key(const key_paths_t *key_paths);
static char *
get_path_to_key(const char *path_to_keys, const char *key_filename);
static svi_rc
create_full_path(sign_algo_t algo, const char *path_to_keys, key_paths_t *key_paths);
static svi_rc
copy_key_from_file(const char *path_to_file, void **key, size_t *key_size);
static svi_rc
openssl_create_private_key(sign_algo_t algo, const char *path_to_keys, key_paths_t *key_paths);

#define PRIVATE_RSA_KEY_FILE "private_rsa_key.pem"
#define PRIVATE_ECDSA_KEY_FILE "private_ecdsa_key.pem"

/* Allocate data using OpenSSL API. */
uint8_t *
openssl_malloc(size_t size)
{
  return OPENSSL_malloc(size);
}

/* Free the data allocated by OpenSSL. */
void
openssl_free(uint8_t *data)
{
  OPENSSL_free(data);
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

  EVP_PKEY_CTX *ctx = NULL;
  EVP_PKEY *signing_key = NULL;
  size_t siglen = 0;
  sign_algo_t algo = signature_info->algo;
  const uint8_t *hash_to_sign = signature_info->hash;

  const void *private_key = signature_info->private_key;
  int private_key_size = (int)signature_info->private_key_size;
  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    SVI_THROW_IF(!private_key || private_key_size == 0, SVI_NOT_SUPPORTED);

    // Read private key, let it allocate signing_key
    BIO *bp = BIO_new_mem_buf(private_key, private_key_size);
    signing_key = PEM_read_bio_PrivateKey(bp, NULL, NULL, NULL);
    BIO_free(bp);

    SVI_THROW_IF(!signing_key, SVI_EXTERNAL_FAILURE);
    ctx = EVP_PKEY_CTX_new(signing_key, NULL /* no engine */);
    SVI_THROW_IF(!ctx, SVI_EXTERNAL_FAILURE);
    // Initialize key
    SVI_THROW_IF(EVP_PKEY_sign_init(ctx) <= 0, SVI_EXTERNAL_FAILURE);

    if (algo == SIGN_ALGO_RSA) {
      SVI_THROW_IF(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0, SVI_EXTERNAL_FAILURE);
    }
    // Set message digest type to sha256
    SVI_THROW_IF(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0, SVI_EXTERNAL_FAILURE);
    // Determine required buffer length
    SVI_THROW_IF(EVP_PKEY_sign(ctx, NULL, &siglen, hash_to_sign, HASH_DIGEST_SIZE) <= 0,
        SVI_EXTERNAL_FAILURE);
    // Check allocated space for signature
    SVI_THROW_IF(siglen > max_signature_size, SVI_MEMORY);
    // Finally sign hash with context
    SVI_THROW_IF(EVP_PKEY_sign(ctx, signature, &siglen, hash_to_sign, HASH_DIGEST_SIZE) <= 0,
        SVI_EXTERNAL_FAILURE);
    // Set the actually written size of the signature. Depending on signing algorithm a shorter
    // signature may have been written.
    signature_info->signature_size = siglen;
  SVI_CATCH()
  SVI_DONE(status)

  EVP_PKEY_free(signing_key);
  EVP_PKEY_CTX_free(ctx);

  return svi_rc_to_signed_video_rc(status);
}

/* Verifies the |signature|. */
SignedVideoReturnCode
openssl_verify_hash(const signature_info_t *signature_info, int *verified_result)
{
  if (!signature_info || !verified_result) return SV_INVALID_PARAMETER;

  int verified_hash = -1;  // Initialize to 'error'.

  const unsigned char *signature = signature_info->signature;
  const size_t signature_size = signature_info->signature_size;
  const uint8_t *hash_to_verify = signature_info->hash;

  if (!signature || (signature_size == 0) || !hash_to_verify) return SV_INVALID_PARAMETER;

  EVP_PKEY_CTX *ctx = NULL;
  EVP_PKEY *verify_key = NULL;

  const void *buf = signature_info->public_key;
  int buf_size = (int)(signature_info->public_key_size);

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    SVI_THROW_IF(!buf, SVI_NULL_PTR);
    SVI_THROW_IF(buf_size == 0, SVI_MEMORY);

    BIO *bp = BIO_new_mem_buf(buf, buf_size);
    verify_key = PEM_read_bio_PUBKEY(bp, NULL, NULL, NULL);
    BIO_free(bp);

    SVI_THROW_IF(!verify_key, SVI_EXTERNAL_FAILURE);

    // Create EVP context
    ctx = EVP_PKEY_CTX_new(verify_key, NULL /* No engine */);
    SVI_THROW_IF(!ctx, SVI_EXTERNAL_FAILURE);
    SVI_THROW_IF(EVP_PKEY_verify_init(ctx) <= 0, SVI_EXTERNAL_FAILURE);
    if (signature_info->algo == SIGN_ALGO_RSA) {
      SVI_THROW_IF(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0, SVI_EXTERNAL_FAILURE);
    }
    SVI_THROW_IF(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0, SVI_EXTERNAL_FAILURE);

    // EVP_PKEY_verify returns 1 indicates success, 0 verify failure and < 0 for some other error.
    verified_hash =
        EVP_PKEY_verify(ctx, signature, signature_size, hash_to_verify, HASH_DIGEST_SIZE);
  SVI_CATCH()
  SVI_DONE(status)

  EVP_PKEY_free(verify_key);
  EVP_PKEY_CTX_free(ctx);

  *verified_result = verified_hash;

  return svi_rc_to_signed_video_rc(status);
}

/* Creates a RSA private key and stores it as a PEM file in the designated location. */
static svi_rc
create_rsa_private_key(const key_paths_t *key_paths)
{
  if (!key_paths) return SVI_INVALID_PARAMETER;

  // Return directly if private key file already exists
  if (access(key_paths->full_path_to_private_key, F_OK | R_OK) == 0) return SVI_OK;

  EVP_PKEY *pkey = NULL;
  BIGNUM *bn = NULL;
  RSA *rsa = NULL;
  FILE *f_private = NULL;

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

    f_private = fopen(key_paths->full_path_to_private_key, "wb");
    SVI_THROW_IF(!f_private, SVI_FILE);

    SVI_THROW_IF(
        !PEM_write_PrivateKey(f_private, pkey, NULL, 0, 0, NULL, NULL), SVI_EXTERNAL_FAILURE);
  SVI_CATCH()
  {
    if (f_private) unlink(key_paths->full_path_to_private_key);
    if (rsa && !pkey) RSA_free(rsa);
  }
  SVI_DONE(status)

  if (f_private) fclose(f_private);

  BN_free(bn);
  EVP_PKEY_free(pkey);  // Free |pkey|, |rsa| struct will be freed automatically as well

  return status;
}

/* Creates a ECDSA private key and stores it as a PEM file in the designated location. */
static svi_rc
create_ecdsa_private_key(const key_paths_t *key_paths)
{
  if (!key_paths) return SVI_INVALID_PARAMETER;

  // Return directly if private key file already exists
  if (access(key_paths->full_path_to_private_key, F_OK | R_OK) == 0) return SVI_OK;

  EC_KEY *ec_key = NULL;
  EVP_PKEY *pkey = NULL;
  FILE *f_private = NULL;

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    SVI_THROW_IF(!ec_key, SVI_EXTERNAL_FAILURE);
    SVI_THROW_IF(EC_KEY_generate_key(ec_key) != 1, SVI_EXTERNAL_FAILURE);

    pkey = EVP_PKEY_new();
    SVI_THROW_IF(!pkey, SVI_EXTERNAL_FAILURE);
    SVI_THROW_IF(EVP_PKEY_assign_EC_KEY(pkey, ec_key) != 1, SVI_EXTERNAL_FAILURE);

    f_private = fopen(key_paths->full_path_to_private_key, "wb");
    SVI_THROW_IF(!f_private, SVI_FILE);
    SVI_THROW_IF(
        !PEM_write_PrivateKey(f_private, pkey, NULL, 0, 0, NULL, NULL), SVI_EXTERNAL_FAILURE);

  SVI_CATCH()
  {
    if (f_private) unlink(key_paths->full_path_to_private_key);
    if (ec_key && !pkey) EC_KEY_free(ec_key);
  }
  SVI_DONE(status)

  if (f_private) fclose(f_private);
  if (pkey) EVP_PKEY_free(pkey);

  return status;
}

/* Joins a |key_filename| to |path_to_keys| to create a full path. */
static char *
get_path_to_key(const char *path_to_keys, const char *key_filename)
{
  size_t path_len = strlen(path_to_keys);
  const size_t str_len = path_len + strlen(key_filename) + 2;  // For '\0' and '/'
  char *str = calloc(1, str_len);
  if (!str) return NULL;

  strcpy(str, path_to_keys);
  // Add '/' if not exists
  if (path_to_keys[path_len - 1] != '/') strcat(str, "/");
  strcat(str, key_filename);

  return str;
}

/* Creates a path string to private key PEM file. */
static svi_rc
create_full_path(sign_algo_t algo, const char *path_to_keys, key_paths_t *key_paths)
{
  assert(path_to_keys && key_paths);
  // Return directly if |path_to_keys| already exist
  if (key_paths->path_to_keys && (strcmp(key_paths->path_to_keys, path_to_keys) == 0))
    return SVI_OK;

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    // Sanity check signing algorithm.
    bool is_rsa = (algo == SIGN_ALGO_RSA);
    SVI_THROW_IF(!is_rsa && (algo != SIGN_ALGO_ECDSA), SVI_NOT_SUPPORTED);

    // Store path to folder with keys.
    char *str = malloc(strlen(path_to_keys) + 1);  // Including '\0'
    SVI_THROW_IF(!str, SVI_MEMORY);
    strcpy(str, path_to_keys);
    free(key_paths->path_to_keys);
    key_paths->path_to_keys = str;

    // Store full path to private key.
    char *filename = is_rsa ? PRIVATE_RSA_KEY_FILE : PRIVATE_ECDSA_KEY_FILE;
    char *full_path_to_private_key = get_path_to_key(key_paths->path_to_keys, filename);
    SVI_THROW_IF(!full_path_to_private_key, SVI_MEMORY);
    free(key_paths->full_path_to_private_key);
    key_paths->full_path_to_private_key = full_path_to_private_key;

  SVI_CATCH()
  {
    free(key_paths->path_to_keys);
    key_paths->path_to_keys = NULL;
    free(key_paths->full_path_to_private_key);
    key_paths->full_path_to_private_key = NULL;
  }
  SVI_DONE(status)

  return status;
}

/* Hashes the data using SHA256. */
SignedVideoReturnCode
openssl_hash_data(const uint8_t *data, size_t data_size, uint8_t *hash)
{
  if (!data || data_size == 0 || !hash) return SV_INVALID_PARAMETER;
  // If there is a mismatch between where the hash has been stored (return value of SHA256()) and
  // where we want it stored (|hash|), we return failure.
  return SHA256(data, data_size, hash) == hash ? SV_OK : SV_EXTERNAL_ERROR;
}

/* Reads the content of a key file, allocates memory and writes it to the key. */
static svi_rc
copy_key_from_file(const char *path_to_file, void **key, size_t *key_size)
{
  if (!path_to_file || !key || !key_size) return SVI_INVALID_PARAMETER;

  // TODO: Consider using OpenSSL functions instead, that is read EVP_PKEY from file, etc.
  FILE *f = NULL;
  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    f = fopen(path_to_file, "rb");
    SVI_THROW_IF(!f, SVI_FILE);
    SVI_THROW_IF(fseek(f, 0, SEEK_END), SVI_FILE);

    long int file_key_size_check = ftell(f);
    SVI_THROW_IF(file_key_size_check <= 0, SVI_FILE);
    uint16_t file_key_size = (uint16_t)file_key_size_check;

    // Rewind the file pointer.
    SVI_THROW_IF(fseek(f, 0, SEEK_SET), SVI_FILE);

    SVI_THROW(sv_rc_to_svi_rc(openssl_key_memory_allocated(key, key_size, file_key_size)));

    // Copy the |key|.
    SVI_THROW_IF(fread(*key, sizeof(uint8_t), file_key_size, f) != file_key_size, SVI_FILE);
  SVI_CATCH()
  {
    // Free the |key| and set |key_size| to zero, since the data is corrupt.
    free(*key);
    *key = NULL;
    *key_size = 0;
  }
  SVI_DONE(status)

  if (f) fclose(f);

  return status;
}

/*
 * Creates a private key in a specified location
 *
 * A private key PEM-file is created. Use openssl_read_pubkey_from_private_key() to read the
 * public_key from the private_key.
 */
static svi_rc
openssl_create_private_key(sign_algo_t algo, const char *path_to_keys, key_paths_t *key_paths)
{
  if (!path_to_keys || !key_paths || strlen(path_to_keys) == 0) return SVI_INVALID_PARAMETER;

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    // Create paths if needed.
    SVI_THROW(create_full_path(algo, path_to_keys, key_paths));
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

/* Allocates memory for a key. */
SignedVideoReturnCode
openssl_key_memory_allocated(void **key, size_t *key_size, size_t new_key_size)
{
  if (!key || !key_size) return SV_INVALID_PARAMETER;
  // Allocating zero size is not allowed.
  if (new_key_size == 0) return SV_NOT_SUPPORTED;
  // Return if memory size match.
  if (*key_size == new_key_size) return SV_OK;

  void *new_key = NULL;
  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    // Re-allocate memory.
    new_key = realloc(*key, new_key_size);
    SVI_THROW_IF(!new_key, SVI_MEMORY);
  SVI_CATCH()
  {
    free(*key);
    new_key_size = 0;
  }
  SVI_DONE(status)

  // Set key also upon failure, for which it will be a null pointer.
  *key_size = new_key_size;
  *key = new_key;

  return svi_rc_to_signed_video_rc(status);
}

/* Reads the public key from the private key. */
SignedVideoReturnCode
openssl_read_pubkey_from_private_key(signature_info_t *signature_info)
{
  EVP_PKEY *pkey = NULL;
  BIO *pub_bio = NULL;
  const void *private_key = NULL;
  int private_key_size = 0;
  char *public_key = NULL;
  long public_key_size = 0;

  if (!signature_info) return SV_INVALID_PARAMETER;

  private_key = signature_info->private_key;
  private_key_size = (int)signature_info->private_key_size;
  if (!private_key || private_key_size == 0) return SV_INVALID_PARAMETER;

  // Read private key, let it allocate signing_key.
  BIO *bp = BIO_new_mem_buf(private_key, private_key_size);
  pkey = PEM_read_bio_PrivateKey(bp, NULL, NULL, NULL);
  BIO_free(bp);

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
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
  EVP_PKEY_free(pkey);

  // Transfer ownership to |signature_info|.
  free(signature_info->public_key);
  signature_info->public_key = public_key;
  signature_info->public_key_size = public_key_size;

  return svi_rc_to_signed_video_rc(status);
}

/* Helper function to generate a private key. Only applicable on Linux platforms. */
SignedVideoReturnCode
signed_video_generate_private_key(sign_algo_t algo,
    const char *path_to_key,
    char **private_key,
    size_t *private_key_size)
{
  if (!path_to_key) return SV_INVALID_PARAMETER;

  key_paths_t key_paths = {0};
  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    SVI_THROW_IF_WITH_MSG(
        algo < 0 || algo >= SIGN_ALGO_NUM, SVI_NOT_SUPPORTED, "Algo is not supported");
    SVI_THROW(openssl_create_private_key(algo, path_to_key, &key_paths));
    // Output the content of the PEM-file if the user asks for it.
    if (private_key && private_key_size) {
      SVI_THROW(copy_key_from_file(
          key_paths.full_path_to_private_key, (void **)private_key, private_key_size));
    }

  SVI_CATCH()
  SVI_DONE(status)

  return svi_rc_to_signed_video_rc(status);
}
