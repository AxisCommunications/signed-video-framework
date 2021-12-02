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

/***** INCLUDE FILES SECTION **********************************************************************/
#include <stdint.h>  // uint8_t
#include <string.h>  // size_t, strcmp, strlen, strcpy, strcat

#include "signed_video_common.h"  // SignedVideoReturnCode
#include "signed_video_interfaces.h"  // signature_info_t, sign_algo_t

/**
 * Object to keep the path structure used to create and read pem-files.
 */
typedef struct {
  char *path_to_keys;
  // Null-terminated character string specifying the location of keys.
  char *full_path_to_private_key;
  // Null-terminated character string specifying the full path location to the private-key pem-file.
} key_paths_t;

/**
 * @brief Malloc data
 *
 * Allocates the memory for data.
 *
 * @param size Data size.
 *
 * @returns Pointer to allocated memory.
 */
uint8_t *
openssl_malloc(size_t size);

/**
 * @brief Frees data
 *
 * Free the allocated data memory.
 *
 * @param data Pointer to the data.
 */
void
openssl_free(uint8_t *data);

/**
 * @brief Hashes data into a 256 bit hash
 *
 * Uses the OpenSSL SHA256() API to hash data. The hashed data has 256 bits, which needs to be
 * allocated in advance by the user.
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
 * @brief Verifies a signature against a hash
 *
 * The |hash| is verified against the |signature| using the |public_key|, all located in the input
 * parameter |signature_info|. For information on signature_info_t see signed_video_interfaces.h.
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
 * This function extracts the public key from the |private_key| and writes it to |public_key|. The
 * |private_key| is assumed to follow PEM file format.
 *
 * @param signature_info A pointer to the object holding all information of the keys.
 *
 * @returns SV_OK Successfully written |public_key| to |signature_info|,
 *          SV_INVALID_PARAMETER Errors in |signature_info|, or no private key present,
 *          SV_MEMORY Could not allocate memory for |public_key|,
 *          SV_EXTERNAL_ERROR Failure in OpenSSL.
 */
SignedVideoReturnCode
openssl_read_pubkey_from_private_key(signature_info_t *signature_info);

/**
 * @brief Signs a hash
 *
 * The function generates a signature of the |hash| in |singature_info| and stores the result in
 * |signature| of |signature_info|. For more information on signature_info_t see
 * signed_video_interfaces.h.
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
 * @brief Allocates memory for a key
 *
 * This is a helper function to allocate memory for a key. If a new key size is detected memory is
 * re-allocated. The API applies to both public and private keys.
 *
 * @param key A pointer to the memory which should be (re-)allocated.
 * @param key_size A pointer to which the size of the allocated memory is written. If a key already
 *   exists, the pointer should hold the current size of the key.
 * @param new_key_size The desired size of the key.
 *
 * @returns SV_OK Successfully allocated memory for the |key|,
 *          SV_INVALID_PARAMETER Null pointers,
 *          SV_NOT_SUPPORTED Invalid |new_key_size|,
 *          SV_MEMORY Could not allocate memory for the |key|,
 */
SignedVideoReturnCode
openssl_key_memory_allocated(void **key, size_t *key_size, size_t new_key_size);

/**
 * @brief Helper function to generate a private key
 *
 * By specifying a location and a signing algorithm (RSA, or ECDSA) a PEM file is generated and
 * stored as private_rsa_key.pem or private_ecdsa_key.pem. The user can then read this file and
 * pass the content to Signed Video through signed_video_set_private_key().
 *
 * This helper function only works on Linux.
 *
 * @param algo The signing algorithm SIGN_ALGO_RSA or SIGN_ALGO_ECDSA.
 * @param path_to_key The location where the PEM file will be written. Null-terminated string.
 * @param private_key If not NULL the content of the private key PEM file is copied to this output.
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

#endif  // __SIGNED_VIDEO_OPENSSL__
