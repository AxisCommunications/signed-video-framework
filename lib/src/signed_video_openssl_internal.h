/**
 * MIT License
 *
 * Copyright (c) 2022 Axis Communications AB
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

#ifndef __SIGNED_VIDEO_OPENSSL_INTERNAL_H__
#define __SIGNED_VIDEO_OPENSSL_INTERNAL_H__

#include <stdint.h>  // uint8_t
#include <string.h>  // size_t

#include "includes/signed_video_common.h"  // SignedVideoReturnCode
#include "includes/signed_video_openssl.h"  // pem_pkey_t, signature_info_t

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

#endif  // __SIGNED_VIDEO_OPENSSL_INTERNAL__
