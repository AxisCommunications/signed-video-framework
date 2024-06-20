/**
 * MIT License
 *
 * Copyright (c) 2021 Axis Communications AB
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 * and associated documentation files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next paragraph) shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
 * BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * This signing plugin calls openssl_sign_hash() and stores the generated signature before return.
 * This signature is then copied to the user when sv_signing_plugin_get_signature().
 */
#include <assert.h>  // assert
#include <stdlib.h>  // calloc, memcpy

#include "includes/signed_video_openssl.h"
#include "includes/signed_video_signing_plugin.h"

#define MAX_BUFFER_LENGTH 60  // Maximum length of the signature buffer

#ifndef ATTR_UNUSED
#if defined(_WIN32) || defined(_WIN64)
#define ATTR_UNUSED
#else
#define ATTR_UNUSED __attribute__((unused))
#endif
#endif

/**
 * Structure to store the signature information.
 */
typedef struct _signature_data_t {
  uint8_t *signature;  // The signature of the |hash|.
  size_t signature_size;  // The size of the |signature|.
} signature_data_t;

// Plugin handle to store the signature, etc.
typedef struct _sv_unthreaded_plugin_t {
  sign_or_verify_data_t sign_data;
  int out_buffer_idx;
  signature_data_t out_buffer[MAX_BUFFER_LENGTH];  // Buffer to store signature information
} sv_unthreaded_plugin_t;

/**
 * Shifts the elements in the signature data buffer to the left.
 */
static void
shift_out_buffer(sv_unthreaded_plugin_t *self)
{
  const int idx = self->out_buffer_idx;
  assert(idx <= MAX_BUFFER_LENGTH);

  // Store the address of the oldest signature.
  uint8_t *oldest_signature = self->out_buffer[0].signature;

  for (int j = 0; j < idx - 1; j++) {
    self->out_buffer[j] = self->out_buffer[j + 1];
  }

  self->out_buffer[idx - 1].signature = oldest_signature;
  self->out_buffer[idx - 1].signature_size = 0;
  self->out_buffer_idx -= 1;
}

/**
 * Signs the given hash and stores the signature in the buffer.
 */
static SignedVideoReturnCode
unthreaded_openssl_sign_hash(sv_unthreaded_plugin_t *self, const uint8_t *hash, size_t hash_size)
{
  SignedVideoReturnCode status = SV_UNKNOWN_FAILURE;
  // Borrow the |hash| by passing the pointer to |sign_data| for signing.
  self->sign_data.hash = (uint8_t *)hash;
  self->sign_data.hash_size = hash_size;
  int idx = self->out_buffer_idx;
  if (idx < MAX_BUFFER_LENGTH) {
    status = openssl_sign_hash(&self->sign_data);
  } else {
    return SV_NOT_SUPPORTED;
  }
  if (status != SV_OK) return status;
  if (self->sign_data.signature_size > 0) {
    if (!self->out_buffer[idx].signature) {
      self->out_buffer[idx].signature = calloc(1, self->sign_data.max_signature_size);
      if (!self->out_buffer[idx].signature) {
        // Handle allocation failure
        sv_signing_plugin_session_teardown((void *)self);
        return SV_MEMORY;
      }
    }
    memcpy(
        self->out_buffer[idx].signature, self->sign_data.signature, self->sign_data.signature_size);
    self->out_buffer[idx].signature_size = self->sign_data.signature_size;
    self->out_buffer_idx++;
  } else {
    return SV_NOT_SUPPORTED;
  }

  return status;
}

/**
 * Definitions of declared interfaces according to signed_video_signing_plugin.h.
 */

SignedVideoReturnCode
sv_signing_plugin_sign(void *handle, const uint8_t *hash, size_t hash_size)
{
  sv_unthreaded_plugin_t *self = (sv_unthreaded_plugin_t *)handle;
  if (!self || !hash || hash_size == 0) return SV_INVALID_PARAMETER;
  return unthreaded_openssl_sign_hash(self, hash, hash_size);
}

/* The |signature| is copied from the local |sign_data| if the |signature_generated|
 * flag is set. */
bool
sv_signing_plugin_get_signature(void *handle,
    uint8_t *signature,
    size_t max_signature_size,
    size_t *written_signature_size,
    SignedVideoReturnCode *error)
{
  sv_unthreaded_plugin_t *self = (sv_unthreaded_plugin_t *)handle;

  if (!self || !signature || !written_signature_size) return false;

  bool has_signature = self->out_buffer_idx > 0;
  if (has_signature) {
    // Copy signature if there is room for it.
    if (max_signature_size < self->out_buffer[0].signature_size) {
      *written_signature_size = 0;
      has_signature = false;
    } else {
      memcpy(signature, self->out_buffer[0].signature, self->out_buffer[0].signature_size);
      *written_signature_size = self->out_buffer[0].signature_size;
    }
    shift_out_buffer(self);
  }
  if (error) *error = SV_OK;

  return has_signature;
}

void *
sv_signing_plugin_session_setup(const void *private_key, size_t private_key_size)
{
  if (!private_key || private_key_size == 0) return NULL;

  sv_unthreaded_plugin_t *self = calloc(1, sizeof(sv_unthreaded_plugin_t));
  if (!self) return NULL;

  // Turn the PEM |private_key| into an EVP_PKEY and allocate memory for signatures.
  if (openssl_private_key_malloc(&self->sign_data, private_key, private_key_size) != SV_OK) {
    sv_signing_plugin_session_teardown((void *)self);
    self = NULL;
  }
  return self;
}

static void
out_buffer_teardown(sv_unthreaded_plugin_t *self)
{
  for (int i = 0; i < MAX_BUFFER_LENGTH; i++) {
    free(self->out_buffer[i].signature);
  }
}

void
sv_signing_plugin_session_teardown(void *handle)
{
  sv_unthreaded_plugin_t *self = (sv_unthreaded_plugin_t *)handle;
  if (!self) return;

  out_buffer_teardown(self);
  openssl_free_key(self->sign_data.key);
  free(self->sign_data.signature);
  free(self);
}

int
sv_signing_plugin_init(void ATTR_UNUSED *user_data)
{
  return 0;
}

void
sv_signing_plugin_exit(void ATTR_UNUSED *user_data)
{
}
