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

// Plugin handle to store the signature, etc.
typedef struct _sv_unthreaded_plugin_t {
  bool signature_generated;
  uint8_t *signature;  // The signature of the |hash|.
  size_t signature_size;  // The size of the |signature|.
  size_t max_signature_size;  // The allocated size of the |signature|.
} sv_unthreaded_plugin_t;

static SignedVideoReturnCode
unthreaded_openssl_sign_hash(sv_unthreaded_plugin_t *self, signature_info_t *signature_info)
{
  if (!signature_info) return SV_INVALID_PARAMETER;
  // If the generated signature has not been pulled a new signature cannot be generated without
  // replacing it.
  if (self->signature_generated) return SV_NOT_SUPPORTED;

  // First time signing. Allocate local memory for storing the signature.
  if (!self->signature) {
    self->signature = openssl_malloc(signature_info->max_signature_size);
    if (!self->signature) return SV_MEMORY;
    self->max_signature_size = signature_info->max_signature_size;
  }

  self->signature_generated = true;

  SignedVideoReturnCode status = openssl_sign_hash(signature_info);
  self->signature_size = (status == SV_OK) ? signature_info->signature_size : 0;

  if (self->signature_size > 0) {
    memcpy(self->signature, signature_info->signature, self->signature_size);
  }

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
 * Definitions of declared interfaces.
 */

SignedVideoReturnCode
sv_interface_sign_hash(void *plugin_handle, signature_info_t *signature_info)
{
  sv_unthreaded_plugin_t *self = (sv_unthreaded_plugin_t *)plugin_handle;

  return unthreaded_openssl_sign_hash(self, signature_info);
}

/* The |signature| is not copied.
 * This implementation is blocking the thread while signing and the signature is written to the
 * memory at once. Therefore, only the handle is passed to unthreaded_openssl_has_signature() for
 * sanity checks on state etc. */
bool
sv_interface_get_signature(void *plugin_handle,
    uint8_t *signature,
    size_t max_signature_size,
    size_t *written_signature_size)
{
  sv_unthreaded_plugin_t *self = (sv_unthreaded_plugin_t *)plugin_handle;

  if (!self || !signature || !written_signature_size) return false;

  bool has_signature = unthreaded_openssl_has_signature(self);
  if (has_signature) {
    // Copy signature if there is room for it.
    if (max_signature_size < self->signature_size) {
      *written_signature_size = 0;
    } else {
      memcpy(signature, self->signature, self->signature_size);
      *written_signature_size = self->signature_size;
    }
  }
  return has_signature;
}

void *
sv_interface_setup()
{
  return calloc(1, sizeof(sv_unthreaded_plugin_t));
}

void
sv_interface_teardown(void *plugin_handle)
{
  sv_unthreaded_plugin_t *self = (sv_unthreaded_plugin_t *)plugin_handle;
  if (self->signature) openssl_free(self->signature);
  free(self);
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
