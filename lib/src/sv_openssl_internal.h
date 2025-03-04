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

#ifndef __SV_OPENSSL_INTERNAL_H__
#define __SV_OPENSSL_INTERNAL_H__

#include <stdint.h>  // uint8_t
#include <string.h>  // size_t

#include "includes/signed_video_openssl.h"  // pem_pkey_t, sign_or_verify_data_t
#include "sv_defines.h"  // svrc_t

/**
 * @brief Create cryptographic handle
 *
 * Allocates the memory for a crypthographic |handle| holding specific OpenSSL information. This
 * handle should be created when starting the session and freed at teardown with
 * sv_openssl_free_handle().
 *
 * @return Pointer to the OpenSSL cryptographic handle.
 */
void *
sv_openssl_create_handle(void);

/**
 * @brief Free cryptographic handle
 *
 * Frees a crypthographic |handle| created with sv_openssl_create_handle().
 *
 * @param handle Pointer to the OpenSSL cryptographic handle.
 */
void
sv_openssl_free_handle(void *handle);

/**
 * @brief Sets hashing algorithm
 *
 * Assigns a hashing algorithm to the |handle|, identified by its |name_or_oid|.
 * If a nullptr is passed in as |name_or_oid|, the default SHA256 is used.
 *
 * @param handle Pointer to the OpenSSL cryptographic handle.
 * @param name_or_oid A null-terminated string defining the hashing algorithm.
 *
 * @return SV_OK Successfully set hash algorithm,
 *         SV_INVALID_PARAMETER Null pointer |handle| or invalid |name_or_oid|.
 */
svrc_t
sv_openssl_set_hash_algo(void *handle, const char *name_or_oid);

/**
 * @brief Sets the hashing algorithm given by its OID on ASN.1/DER form
 *
 * Stores the OID of the hashing algorithm on serialized form and determines its type.
 *
 * @param handle Pointer to the OpenSSL cryptographic handle.
 * @param encoded_oid A pointer to the encoded OID of the hashing algorithm.
 * @param encoded_oid_size The size of the encoded OID data.
 *
 * @return SV_OK Successfully set hash algorithm,
 *         Other appropriate error.
 */
svrc_t
sv_openssl_set_hash_algo_by_encoded_oid(void *handle,
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
 * @return A pointer to the encoded OID of the hashing algorithm,
 *         and a NULL pointer upon failure.
 */
const unsigned char *
sv_openssl_get_hash_algo_encoded_oid(void *handle, size_t *encoded_oid_size);

/**
 * @brief Converts hashing algorithm from OID form to readable string
 *
 * The ownership of the allocated string is transferred.
 *
 * @param encoded_oid Pointer to the OID on serialized form.
 * @param encoded_oid_size The size of the encoded OID.
 *
 * @return A string.
 */
char *
sv_openssl_encoded_oid_to_str(const unsigned char *encoded_oid, size_t encoded_oid_size);

/**
 * @brief Gets the hash algorithm
 *
 * Returns a null-terminated string defining the hashing algorithm and NULL upon failure.
 *
 * @param handle Pointer to the OpenSSL cryptographic handle.
 *
 * @return The hashing algorithm as a null-terminated string.
 */
char *
openssl_get_hash_algo(const void *handle);

/**
 * @brief Gets the hash size of the hashing algorithm
 *
 * Returns the hash size of the hashing algorithm and 0 upon failure.
 *
 * @param handle Pointer to the OpenSSL cryptographic handle.
 *
 * @return The size of the hash.
 */
size_t
sv_openssl_get_hash_size(void *handle);

/**
 * @brief Hashes data
 *
 * Uses the hash algorithm set through sv_openssl_set_hash_algo() to hash data. The memory
 * for the |hash| has to be pre-allocated by the user. Use sv_openssl_get_hash_size() to get
 * the hash size.
 *
 * This is a simplification for calling sv_openssl_init_hash(), sv_openssl_update_hash() and
 * sv_openssl_finalize_hash() done in one go.
 *
 * @param data Pointer to the data to hash.
 * @param data_size Size of the |data| to hash.
 * @param hash A pointer to the hashed output. This memory has to be pre-allocated.
 *
 * @return SV_OK Successfully hashed |data|,
 *         SV_INVALID_PARAMETER Null pointer inputs, or invalid |data_size|,
 *         SV_EXTERNAL_ERROR Failed to hash.
 */
svrc_t
sv_openssl_hash_data(void *handle, const uint8_t *data, size_t data_size, uint8_t *hash);

/**
 * @brief Initiates the cryptographic handle for hashing data
 *
 * Uses the OpenSSL API EVP_DigestInit_ex() to initiate an EVP_MD_CTX object in |handle|.
 *
 * @param handle Pointer to the OpenSSL cryptographic handle.
 * @param use_primary_ctx Flag that indicates which hash context to use.
 *
 * @return SV_OK Successfully initialized EVP_MD_CTX object in |handle|,
 *         SV_INVALID_PARAMETER Null pointer input,
 *         SV_EXTERNAL_ERROR Failed to initialize.
 */
svrc_t
sv_openssl_init_hash(void *handle, bool use_primary_ctx);

/**
 * @brief Updates the cryptographic handle with |data| for hashing
 *
 * Uses the OpenSSL API EVP_DigestUpdate() to update the EVP_MD_CTX object in |handle|
 * with |data|.
 *
 * @param handle Pointer to the OpenSSL cryptographic handle.
 * @param data Pointer to the data to update an ongoing hash.
 * @param data_size Size of the |data|.
 * @param use_primary_ctx Flag that indicates which hash context to use.
 *
 * @return SV_OK Successfully updated EVP_MD_CTX object in |handle|,
 *         SV_INVALID_PARAMETER Null pointer inputs, or invalid |data_size|,
 *         SV_EXTERNAL_ERROR Failed to update.
 */
svrc_t
sv_openssl_update_hash(void *handle, const uint8_t *data, size_t data_size, bool use_primary_ctx);

/**
 * @brief Finalizes the cryptographic handle and outputs the hash
 *
 * Uses the OpenSSL API EVP_DigestFinal_ex() to finalize the EVP_MD_CTX object in |handle|
 * and get the |hash|. The EVP_MD_CTX object in |handle| is reset afterwards.
 *
 * @param handle Pointer to the OpenSSL cryptographic handle.
 * @param hash A pointer to the hashed output. This memory has to be pre-allocated.
 * @param use_primary_ctx Flag that indicates which hash context to use.
 *
 * @return SV_OK Successfully wrote the final result of EVP_MD_CTX object in |handle| to |hash|,
 *         SV_INVALID_PARAMETER Null pointer inputs,
 *         SV_EXTERNAL_ERROR Failed to finalize.
 */
svrc_t
sv_openssl_finalize_hash(void *handle, uint8_t *hash, bool use_primary_ctx);

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
 * @return SV_OK Successfully generated |signature|,
 *         SV_INVALID_PARAMETER Errors in |verify_data|, or null pointer inputs,
 */
svrc_t
sv_openssl_verify_hash(const sign_or_verify_data_t *verify_data, int *verified_result);

/**
 * @brief Reads the public key from the private key
 *
 * This function extracts the public key from the |private_key| and writes it to |pem_pkey|. The
 * |private_key| is assumed to be on EVP_PKEY form.
 *
 * @param sign_data A pointer to the object holding the |private_key|.
 * @param pem_pkey A pointer to the object where the public key, on PEM format, will be written.
 *
 * @return SV_OK Successfully written |key| to |pem_pkey|,
 *         SV_INVALID_PARAMETER Errors in |sign_data|, or no private key present,
 *         SV_MEMORY Could not allocate memory for |key|,
 *         SV_EXTERNAL_ERROR Failure in OpenSSL.
 */
svrc_t
openssl_read_pubkey_from_private_key(sign_or_verify_data_t *sign_data, pem_pkey_t *pem_pkey);

/**
 * @brief Turns a public key on PEM form to EVP_PKEY form
 *
 * The function takes the public key as a pem_pkey_t and stores it as |public_key| in
 * |verify_data| on the EVP_PKEY form.
 * Use sv_openssl_free_key() to free the key context.
 *
 * @param verify_data A pointer to the struct that holds all necessary information for signing.
 * @param pem_public_key A pointer to the PEM format struct.
 *
 * @return SV_OK Successfully stored |public_key|,
 *         SV_INVALID_PARAMETER Missing inputs,
 *         SV_EXTERNAL_ERROR Failure in OpenSSL.
 */
svrc_t
openssl_public_key_malloc(sign_or_verify_data_t *verify_data, pem_pkey_t *pem_public_key);

/**
 * @brief Extracts the private key from the signing data structure.
 *
 * This function retrieves the private key stored within the `sign_data` structure
 * and returns it as a dynamically allocated null-terminated string in PEM format.
 *
 * @param sign_data A pointer to the `sign_or_verify_data_t` structure containing the key.
 * @return A dynamically allocated string containing the private key in PEM format,
 *         or NULL if an error occurs. The caller is responsible for freeing the memory.
 */
char *
get_private_key_from_sign_data(sign_or_verify_data_t *sign_data);

#endif  // __SV_OPENSSL_INTERNAL__
