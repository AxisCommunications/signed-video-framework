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
 * This signature is then copied to the user when sv_interface_get_signature().
 */
#include <stdlib.h>  // calloc

#include "includes/signed_video_interfaces.h"
#include "includes/signed_video_openssl.h"

#ifndef ATTR_UNUSED
#if defined(_WIN32) || defined(_WIN64)
#define ATTR_UNUSED
#else
#define ATTR_UNUSED __attribute__((unused))
#endif
#endif

// Plugin handle to store the signature, etc.
typedef struct _sv_unthreaded_plugin_t {
  bool signature_generated;
  signature_info_t signature_info;
} sv_unthreaded_plugin_t;

static SignedVideoReturnCode
unthreaded_openssl_sign_hash(sv_unthreaded_plugin_t *self, const uint8_t *hash, size_t hash_size)
{
  // If the generated signature has not been pulled a new signature cannot be generated without
  // being overwritten.
  if (self->signature_generated) return SV_NOT_SUPPORTED;

  SignedVideoReturnCode status = SV_UNKNOWN_FAILURE;
  // First time signing. Allocate local memory for storing the signature.
  if (!self->signature_info.signature) {
    status = openssl_signature_malloc(&self->signature_info);
    if (status != SV_OK) return status;
  }
  // Pass the |hash| pointer to |signature_info| for signing.
  self->signature_info.hash = (uint8_t *)hash;
  self->signature_info.hash_size = hash_size;

  status = openssl_sign_hash(&self->signature_info);
  self->signature_generated = (status == SV_OK) && (self->signature_info.signature_size > 0);

  return status;
}

static bool
unthreaded_openssl_has_signature(sv_unthreaded_plugin_t *self)
{
  if (self->signature_generated) {
    self->signature_generated = false;
    return true;
  }
  return false;
}

/**
 * Definitions of declared interfaces according to signed_video_interfaces.h.
 */

SignedVideoReturnCode
sv_signing_plugin_sign(void *handle, const uint8_t *hash, size_t hash_size)
{
  sv_unthreaded_plugin_t *self = (sv_unthreaded_plugin_t *)handle;
  if (!self || !hash || hash_size == 0) return SV_INVALID_PARAMETER;

  return unthreaded_openssl_sign_hash(self, hash, hash_size);
}

/* TO BE DEPRECATED */
SignedVideoReturnCode
sv_interface_sign_hash(void *plugin_handle, signature_info_t *signature_info)
{
  sv_unthreaded_plugin_t *self = (sv_unthreaded_plugin_t *)plugin_handle;
  if (!self || !signature_info) return SV_INVALID_PARAMETER;
  if (!signature_info->hash || signature_info->hash_size == 0) return SV_INVALID_PARAMETER;

  // Copy |private_key| since the new behavior is to set it through
  // sv_signing_plugin_session_setup().
  if (!self->signature_info.private_key) {
    self->signature_info.private_key = malloc(signature_info->private_key_size);
    if (!self->signature_info.private_key) return SV_MEMORY;
    memcpy(self->signature_info.private_key, signature_info->private_key,
        signature_info->private_key_size);
    self->signature_info.private_key_size = signature_info->private_key_size;
  }

  // Pass in the hash to sign using the new API.
  return unthreaded_openssl_sign_hash(self, signature_info->hash, signature_info->hash_size);
}

/* The |signature| is copied from the local |signature_info| if the |signature_generated|
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

  bool has_signature = unthreaded_openssl_has_signature(self);
  if (has_signature) {
    // Copy signature if there is room for it.
    if (max_signature_size < self->signature_info.signature_size) {
      *written_signature_size = 0;
    } else {
      memcpy(signature, self->signature_info.signature, self->signature_info.signature_size);
      *written_signature_size = self->signature_info.signature_size;
    }
  }
  if (error) *error = SV_OK;

  return has_signature;
}

/* TO BE DEPRECATED */
bool
sv_interface_get_signature(void *plugin_handle,
    uint8_t *signature,
    size_t max_signature_size,
    size_t *written_signature_size,
    SignedVideoReturnCode *error)
{
  return sv_signing_plugin_get_signature(
      plugin_handle, signature, max_signature_size, written_signature_size, error);
}

void *
sv_signing_plugin_session_setup(const void *private_key, size_t private_key_size)
{
  if (!private_key || private_key_size == 0) return NULL;

  sv_unthreaded_plugin_t *self = calloc(1, sizeof(sv_unthreaded_plugin_t));
  if (!self) return NULL;

  // Allocate memory and copy |private_key|.
  self->signature_info.private_key = malloc(private_key_size);
  if (!self->signature_info.private_key) {
    free(self);
    return NULL;
  }
  memcpy(self->signature_info.private_key, private_key, private_key_size);
  self->signature_info.private_key_size = private_key_size;

  return self;
}

/* TO BE DEPRECATED */
void *
sv_interface_setup()
{
  return calloc(1, sizeof(sv_unthreaded_plugin_t));
}

void
sv_signing_plugin_session_teardown(void *handle)
{
  sv_unthreaded_plugin_t *self = (sv_unthreaded_plugin_t *)handle;
  if (!self) return;

  free(self->signature_info.private_key);
  if (self->signature_info.signature) openssl_free(self->signature_info.signature);
  free(self);
}

/* TO BE DEPRECATED */
void
sv_interface_teardown(void *plugin_handle)
{
  sv_signing_plugin_session_teardown(plugin_handle);
}

uint8_t *
sv_interface_malloc(size_t data_size)
{
  return openssl_malloc(data_size);
}

void
sv_interface_free(uint8_t *data)
{
  openssl_free(data);
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
