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

#include "includes/signed_video_openssl.h"  // pem_pkey_t, sign_or_verify_data_t
#include "signed_video_defines.h"  // svi_rc

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
 * @brief Sets hashing algorithm
 *
 * Assigns a hashing algorithm to the |handle|, identified by its |name_or_oid|.
 * If a nullptr is passed in as |name_or_oid|, the default SHA256 is used.
 *
 * @param handle Pointer to the OpenSSL cryptographic handle.
 * @param name_or_oid A null-terminated string defining the hashing algorithm.
 *
 * @returns SV_OK Successfully set hash algorithm,
 *          SV_INVALID_PARAMETER Null pointer |handle| or invalid |name_or_oid|.
 */
svi_rc
openssl_set_hash_algo(void *handle, const char *name_or_oid);

/**
 * @brief Sets the hashing algorithm given by its OID on ASN.1/DER form
 *
 * Stores the OID of the hashing algorithm on serialized form and determines its type.
 *
 * @param handle Pointer to the OpenSSL cryptographic handle.
 * @param encoded_oid A pointer to the encoded OID of the hashing algorithm.
 * @param encoded_oid_size The size of the encoded OID data.
 *
 * @returns SV_OK Successfully set hash algorithm,
 *          Other appropriate error.
 */
svi_rc
openssl_set_hash_algo_by_encoded_oid(void *handle,
    const unsigned char *encoded_oid,
    size_t encoded_oid_size);

/**
 * @brief Gets hashing algorithm on ASN.1/DER form
 *
 * Returns the hashing algorithm OID on serialized form, that is encoded as ASN.1/DER.
 *
 * @param handle Pointer to the OpenSSL cryptographic handle.
 * @param encoded_oid_size A Pointer to where the size of the encoded OID is written.
 *
 * @returns A pointer to the encoded OID of the hashing algorithm,
 *          and a NULL pointer upon failure.
 */
const unsigned char *
openssl_get_hash_algo_encoded_oid(void *handle, size_t *encoded_oid_size);

/**
 * @brief Gets the hash size of the hashing algorithm
 *
 * Returns the hash size of the hashing algorithm and 0 upon failure.
 *
 * @param handle Pointer to the OpenSSL cryptographic handle.
 *
 * @returns The size of the hash.
 */
size_t
openssl_get_hash_size(void *handle);

/**
 * @brief Hashes data
 *
 * Uses the hash algorithm set through openssl_set_hash_algo() to hash data. The memory
 * for the |hash| has to be pre-allocated by the user. Use openssl_get_hash_size() to get
 * the hash size.
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
svi_rc
openssl_hash_data(void *handle, const uint8_t *data, size_t data_size, uint8_t *hash);

/**
 * @brief Initiates the cryptographic handle for hashing data
 *
 * Uses the OpenSSL API EVP_DigestInit_ex() to initiate an EVP_MD_CTX object in |handle|.
 *
 * @param handle Pointer to the OpenSSL cryptographic handle.
 *
 * @returns SV_OK Successfully initialized EVP_MD_CTX object in |handle|,
 *          SV_INVALID_PARAMETER Null pointer input,
 *          SV_EXTERNAL_ERROR Failed to initialize.
 */
svi_rc
openssl_init_hash(void *handle);

/**
 * @brief Updates the cryptographic handle with |data| for hashing
 *
 * Uses the OpenSSL API EVP_DigestUpdate() to update the EVP_MD_CTX object in |handle|
 * with |data|.
 *
 * @param handle Pointer to the OpenSSL cryptographic handle.
 * @param data Pointer to the data to update an ongoing hash.
 * @param data_size Size of the |data|.
 *
 * @returns SV_OK Successfully updated EVP_MD_CTX object in |handle|,
 *          SV_INVALID_PARAMETER Null pointer inputs, or invalid |data_size|,
 *          SV_EXTERNAL_ERROR Failed to update.
 */
svi_rc
openssl_update_hash(void *handle, const uint8_t *data, size_t data_size);

/**
 * @brief Finalizes the cryptographic handle and outputs the hash
 *
 * Uses the OpenSSL API EVP_DigestFinal_ex() to finalize the EVP_MD_CTX object in |handle|
 * and get the |hash|. The EVP_MD_CTX object in |handle| is reset afterwards.
 *
 * @param handle Pointer to the OpenSSL cryptographic handle.
 * @param hash A pointer to the hashed output. This memory has to be pre-allocated.
 *
 * @returns SV_OK Successfully wrote the final result of EVP_MD_CTX object in |handle| to |hash|,
 *          SV_INVALID_PARAMETER Null pointer inputs,
 *          SV_EXTERNAL_ERROR Failed to finalize.
 */
svi_rc
openssl_finalize_hash(void *handle, uint8_t *hash);

/**
 * @brief Verifies a signature against a hash
 *
 * The |hash| is verified against the |signature| using the public |key|, all being
 * members of the input parameter |verify_data|.
 *
 * @param verify_data Pointer to the sign_or_verify_data_t object in use.
 * @param verified_result Poiniter to the place where the verification result is written. The
 *   |verified_result| can either be 1 (success), 0 (failure), or < 0 (error).
 *
 * @returns SV_OK Successfully generated |signature|,
 *          SV_INVALID_PARAMETER Errors in |verify_data|, or null pointer inputs,
 */
svi_rc
openssl_verify_hash(const sign_or_verify_data_t *verify_data, int *verified_result);

/**
 * @brief Reads the public key from the private key
 *
 * This function extracts the public key from the |private_key| and writes it to |pem_pkey|. The
 * |private_key| is assumed to be on EVP_PKEY form.
 *
 * @param sign_data A pointer to the object holding the |private_key|.
 * @param pem_pkey A pointer to the object where the public key, on PEM format, will be written.
 *
 * @returns SV_OK Successfully written |key| to |pem_pkey|,
 *          SV_INVALID_PARAMETER Errors in |sign_data|, or no private key present,
 *          SV_MEMORY Could not allocate memory for |key|,
 *          SV_EXTERNAL_ERROR Failure in OpenSSL.
 */
svi_rc
openssl_read_pubkey_from_private_key(sign_or_verify_data_t *sign_data, pem_pkey_t *pem_pkey);

/**
 * @brief Turns a public key on PEM form to EVP_PKEY form
 *
 * The function takes the public key as a pem_pkey_t and stores it as |public_key| in
 * |verify_data| on the EVP_PKEY form.
 * Use openssl_free_key() to free the key context.
 *
 * @param verify_data A pointer to the struct that holds all necessary information for signing.
 * @param pem_public_key A pointer to the PEM format struct.
 *
 * @returns SV_OK Successfully stored |public_key|,
 *          SV_INVALID_PARAMETER Missing inputs,
 *          SV_EXTERNAL_ERROR Failure in OpenSSL.
 */
svi_rc
openssl_public_key_malloc(sign_or_verify_data_t *verify_data, pem_pkey_t *pem_public_key);

#endif  // __SIGNED_VIDEO_OPENSSL_INTERNAL__
