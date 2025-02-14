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

#ifndef __SIGNED_VIDEO_OPENSSL__
#define __SIGNED_VIDEO_OPENSSL__

#include <stdint.h>  // uint8_t
#include <string.h>  // size_t

#include "signed_video_common.h"  // SignedVideoReturnCode

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Struct for storing necessary information to sign a hash and generate a signature.
 * It is used primarily by the signing plugins.
 */
typedef struct _sign_or_verify_data {
  uint8_t *hash;  // The hash to be signed or to use when verifying the signature.
  size_t hash_size;  // The size of the |hash|.
  void *key;  // The private key used for signing or public key used for verifying.
  uint8_t *signature;  // The signature of the |hash|.
  size_t signature_size;  // The size of the |signature|.
  size_t max_signature_size;  // The allocated size of the |signature|.
} sign_or_verify_data_t;

/**
 * Struct to store a private key in PEM format. Useful to bundle the data in a single object.
 */
typedef struct _pem_pkey_t {
  void *key;  // The private/public key used for signing/verification in a pem file format.
  size_t key_size;  // The size of the |key|.
} pem_pkey_t;

/**
 * @brief Signs a hash
 *
 * The function generates a signature of the |hash| in |sign_data| and stores the result in
 * |signature| of |sign_data|.
 *
 * @param sign_data A pointer to the struct that holds all necessary information for signing.
 *
 * @return SV_OK Successfully generated |signature|,
 *         SV_INVALID_PARAMETER Errors in |sign_data|,
 *         SV_NOT_SUPPORTED No private key present,
 *         SV_MEMORY Not enough memory allocated for the |signature|,
 *         SV_EXTERNAL_ERROR Failure in OpenSSL.
 */
SignedVideoReturnCode
openssl_sign_hash(sign_or_verify_data_t *sign_data);

/**
 * @brief Turns a private key on PEM form to EVP_PKEY form
 *
 * and allocates memory for a signature
 *
 * The function allocates enough memory for a signature given the |private_key|.
 * Use openssl_free_key() to free the key context.
 *
 * @param sign_data A pointer to the struct that holds all necessary information for signing.
 * @param private_key The content of the private key PEM file.
 * @param private_key_size The size of the |private_key|.
 *
 * @return SV_OK Successfully generated |signature|,
 *         SV_INVALID_PARAMETER Missing inputs,
 *         SV_MEMORY Failed allocating memory for the |signature|,
 *         SV_EXTERNAL_ERROR Failure in OpenSSL.
 */
SignedVideoReturnCode
openssl_private_key_malloc(sign_or_verify_data_t *sign_data,
    const char *private_key,
    size_t private_key_size);

/**
 * @brief Frees the memory of a private/public key context
 *
 * The |key| is assumed to be a key on context form.
 *
 * @param key A pointer to the key context which memory to free
 */
void
openssl_free_key(void *key);

/**
 * @brief Helper function to generate a private key
 *
 * Two different APIs for RSA and ECDSA. By specifying a location a PEM file is generated
 * and stored as private_rsa_key.pem or private_ecdsa_key.pem. The user can then read this
 * file and pass the content to Signed Video through signed_video_set_private_key().
 * In addition to storing as file the content can be written to buffers at once. Memory is
 * allocated for |private_key| and the content of |private_key_size| Bytes is written.
 * Note that the ownership is transferred.
 *
 * Writing to file currently only works on Linux.
 *
 * @param dir_to_key If not NULL, the location where the PEM file will be written. Null-terminated
 *   string.
 * @param private_key If not NULL the content of the private key PEM file is copied to this output.
 *   Ownership is transferred.
 * @param private_key_size If not NULL outputs the size of the |private_key|.
 *
 * @return SV_OK Valid algorithm and successfully written PEM-file,
 *         SV_NOT_SUPPORTED Algorithm is not supported,
 *         SV_INVALID_PARAMETER Invalid input parameter,
 *         SV_EXTERNAL_ERROR PEM-file could not be written.
 */
SignedVideoReturnCode
signed_video_generate_ecdsa_private_key(const char *dir_to_key,
    char **private_key,
    size_t *private_key_size);
SignedVideoReturnCode
signed_video_generate_rsa_private_key(const char *dir_to_key,
    char **private_key,
    size_t *private_key_size);

#ifdef __cplusplus
}
#endif

#endif  // __SIGNED_VIDEO_OPENSSL__
