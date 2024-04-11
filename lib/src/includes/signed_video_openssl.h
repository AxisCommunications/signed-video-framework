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
#include <string.h>  // size_t, strcmp, strlen, strcpy, strcat

#include "signed_video_common.h"  // SignedVideoReturnCode

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Signing algorithm
 *
 * The following signing algorithms are supported and has to be set when creating the signed video
 * session on the signing side.
 *
 * NOTE: The algorithms are currently fixed to SHA-256, which needs to be addressed when
 * implementing the interfaces.
 */
typedef enum { SIGN_ALGO_RSA = 0, SIGN_ALGO_ECDSA = 1, SIGN_ALGO_NUM } sign_algo_t;

/* NOTE: This struct is in a refactoring state, hence subject to changes. */
/**
 * Struct for storing necessary information to generate and verify a signature
 *
 * It is used by the signing plugins and also to validated the authenticity.
 */
typedef struct _signature_info_t {
  uint8_t *hash;  // The hash to be signed, or to verify the signature.
  size_t hash_size;  // The size of the |hash|. For now with a fixed size of HASH_DIGEST_SIZE.
  sign_algo_t algo;  // The algorithm used to sign the |hash|. NOT USED ANYMORE
  void *private_key;  // The private key used for signing in a pem file format.
  // Internally used as EVP_PKEY_CTX.
  size_t private_key_size;  // The size of the |private_key| if pem file format.
  void *public_key;  // The public key used for validation in a pem file format.
  // Internally used as EVP_PKEY_CTX.
  size_t public_key_size;  // The size of the |public_key| if pem file format.
  uint8_t *signature;  // The signature of the |hash|.
  size_t signature_size;  // The size of the |signature|.
  size_t max_signature_size;  // The allocated size of the |signature|.
} signature_info_t;

/**
 * Struct to store a private key in PEM format. Useful to bundle the data in a single object.
 */
typedef struct _pem_pkey_t {
  void *pkey;  // The private/public key used for signing/verification in a pem file format.
  size_t pkey_size;  // The size of the |pkey|.
} pem_pkey_t;

/**
 * @brief Create cryptographic handle
 *
 * Allocates the memory for a crypthographic |handle| holding specific OpenSSL information. This
 * handle should be created when starting the session and freed at teardown with
 * openssl_free_handle().
 *
 * @returns Pointer to the OpenSSL cryptographic handle.
 */
void *
openssl_create_handle(void);

/**
 * @brief Free cryptographic handle
 *
 * Frees a crypthographic |handle| created with openssl_create_handle().
 *
 * @param handle Pointer to the OpenSSL cryptographic handle.
 */
void
openssl_free_handle(void *handle);

/**
 * @brief Hashes data into a 256 bit hash
 *
 * Uses the OpenSSL SHA256() API to hash data. The hashed data has 256 bits, which needs to be
 * allocated in advance by the user.
 *
 * This is a simplification for calling openssl_init_hash(), openssl_update_hash() and
 * openssl_finalize_hash() done in one go.
 *
 * @param data Pointer to the data to hash.
 * @param data_size Size of the |data| to hash.
 * @param hash A pointer to the hashed output. This memory has to be pre-allocated.
 *
 * @returns SV_OK Successfully hashed |data|,
 *          SV_INVALID_PARAMETER Null pointer inputs, or invalid |data_size|,
 *          SV_EXTERNAL_ERROR Failed to hash.
 */
SignedVideoReturnCode
openssl_hash_data(const uint8_t *data, size_t data_size, uint8_t *hash);

/**
 * @brief Initiates the cryptographic handle for hashing data
 *
 * Uses the OpenSSL SHA256_Init() API to initiate an SHA256_CTX object in |handle|.
 *
 * @param handle Pointer to the OpenSSL cryptographic handle.
 *
 * @returns SV_OK Successfully initialized SHA256_CTX object in |handle|,
 *          SV_INVALID_PARAMETER Null pointer input,
 *          SV_EXTERNAL_ERROR Failed to initialize.
 */
SignedVideoReturnCode
openssl_init_hash(void *handle);

/**
 * @brief Updates the cryptographic handle with |data| for hashing
 *
 * Uses the OpenSSL SHA256_Update() API to update the SHA256_CTX object in |handle| with |data|.
 *
 * @param handle Pointer to the OpenSSL cryptographic handle.
 * @param data Pointer to the data to update an ongoing hash.
 * @param data_size Size of the |data|.
 *
 * @returns SV_OK Successfully updated SHA256_CTX object in |handle|,
 *          SV_INVALID_PARAMETER Null pointer inputs, or invalid |data_size|,
 *          SV_EXTERNAL_ERROR Failed to update.
 */
SignedVideoReturnCode
openssl_update_hash(void *handle, const uint8_t *data, size_t data_size);

/**
 * @brief Finalizes the cryptographic handle and outputs the hash
 *
 * Uses the OpenSSL SHA256_Final() API to finalize the SHA256_CTX object in |handle| and get the
 * |hash|. The SHA256_CTX object in |handle| is reset afterwards.
 *
 * @param handle Pointer to the OpenSSL cryptographic handle.
 * @param hash A pointer to the hashed output. This memory has to be pre-allocated.
 *
 * @returns SV_OK Successfully wrote the final result of SHA256_CTX object in |handle| to |hash|,
 *          SV_INVALID_PARAMETER Null pointer inputs,
 *          SV_EXTERNAL_ERROR Failed to finalize.
 */
SignedVideoReturnCode
openssl_finalize_hash(void *handle, uint8_t *hash);

/**
 * @brief Verifies a signature against a hash
 *
 * The |hash| is verified against the |signature| using the |public_key|, all located in the input
 * parameter |signature_info|.
 *
 * @param signature_info Pointer to the signature_info_t object in use.
 * @param verified_result Poiniter to the place where the verification result is written. The
 *   |verified_result| can either be 1 (success), 0 (failure), or < 0 (error).
 *
 * @returns SV_OK Successfully generated |signature|,
 *          SV_INVALID_PARAMETER Errors in |signature_info|, or null pointer inputs,
 *          SV_EXTERNAL_ERROR Failure in OpenSSL.
 */
SignedVideoReturnCode
openssl_verify_hash(const signature_info_t *signature_info, int *verified_result);

/**
 * @brief Reads the public key from the private key
 *
 * This function extracts the public key from the |private_key| and writes it to |pem_pkey|. The
 * |private_key| is assumed to be on EVP_PKEY form.
 *
 * @param signature_info A pointer to the object holding the |private_key|.
 * @param pem_pkey A pointer to the object where the public key, on PEM format, will be written.
 *
 * @returns SV_OK Successfully written |pkey| to |pem_pkey|,
 *          SV_INVALID_PARAMETER Errors in |signature_info|, or no private key present,
 *          SV_MEMORY Could not allocate memory for |pkey|,
 *          SV_EXTERNAL_ERROR Failure in OpenSSL.
 */
SignedVideoReturnCode
openssl_read_pubkey_from_private_key(signature_info_t *signature_info, pem_pkey_t *pem_pkey);

/**
 * @brief Signs a hash
 *
 * The function generates a signature of the |hash| in |singature_info| and stores the result in
 * |signature| of |signature_info|.
 *
 * @param signature_info A pointer to the struct that holds all necessary information for signing.
 *
 * @returns SV_OK Successfully generated |signature|,
 *          SV_INVALID_PARAMETER Errors in |signature_info|,
 *          SV_NOT_SUPPORTED No private key present,
 *          SV_MEMORY Not enough memory allocated for the |signature|,
 *          SV_EXTERNAL_ERROR Failure in OpenSSL.
 */
SignedVideoReturnCode
openssl_sign_hash(signature_info_t *signature_info);

/**
 * @brief Turns a private key on PEM form to EVP_PKEY form
 *
 * and allocates memory for a signature
 *
 * The function allocates enough memory for a signature given the |private_key|.
 * Use openssl_free_key() to free the key.
 *
 * @param signature_info A pointer to the struct that holds all necessary information for signing.
 * @param private_key The content of the private key PEM file.
 * @param private_key_size The size of the |private_key|.
 *
 * @returns SV_OK Successfully generated |signature|,
 *          SV_INVALID_PARAMETER Missing inputs,
 *          SV_MEMORY Failed allocating memory for the |signature|,
 *          SV_EXTERNAL_ERROR Failure in OpenSSL.
 */
SignedVideoReturnCode
openssl_private_key_malloc(signature_info_t *signature_info,
    const char *private_key,
    size_t private_key_size);

/**
 * @brief Turns a public key on PEM form to EVP_PKEY form
 *
 * The function takes the public key as a pem_pkey_t and stores it as |public_key| in
 * |signature_info| on the EVP_PKEY form.
 * Use openssl_free_key() to free the key.
 *
 * @param signature_info A pointer to the struct that holds all necessary information for signing.
 * @param pem_public_key A pointer to the PEM format struct.
 *
 * @returns SV_OK Successfully stored |public_key|,
 *          SV_INVALID_PARAMETER Missing inputs,
 *          SV_EXTERNAL_ERROR Failure in OpenSSL.
 */
SignedVideoReturnCode
openssl_public_key_malloc(signature_info_t *signature_info, pem_pkey_t *pem_public_key);

/**
 * @brief Frees the memory of a private/public key
 *
 * The |pkey| is assumed to be on EVP_PKEY form.
 *
 * @param pkey A pointer to the key which memory to free
 */
void
openssl_free_key(void *pkey);

/**
 * @brief Helper function to generate a private key
 *
 * By specifying a location and a signing algorithm (RSA, or ECDSA) a PEM file is generated and
 * stored as private_rsa_key.pem or private_ecdsa_key.pem. The user can then read this file and
 * pass the content to Signed Video through signed_video_set_private_key_new().
 * If no |path_to_key| is passed in, memory is allocated for |private_key| and the content of
 * |private_key_size| is written. Note that the ownership is transferred.
 *
 * Writing to file only works on Linux.
 *
 * @param algo The signing algorithm SIGN_ALGO_RSA or SIGN_ALGO_ECDSA.
 * @param path_to_key If not NULL, the location where the PEM file will be written. Null-terminated
 *   string.
 * @param private_key If not NULL the content of the private key PEM file is copied to this output.
 *   Ownership is transferred.
 * @param private_key_size If not NULL outputs the size of the |private_key|.
 *
 * @returns SV_OK Valid algorithm and successfully written PEM-file,
 *          SV_NOT_SUPPORTED Algorithm is not supported,
 *          SV_INVALID_PARAMETER Invalid input parameter,
 *          SV_EXTERNAL_ERROR PEM-file could not be written.
 */
SignedVideoReturnCode
signed_video_generate_private_key(sign_algo_t algo,
    const char *path_to_key,
    char **private_key,
    size_t *private_key_size);

#ifdef __cplusplus
}
#endif

#endif  // __SIGNED_VIDEO_OPENSSL__
