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
#include <stdlib.h>  // calloc

#include "includes/signed_video_interfaces.h"
#include "includes/signed_video_openssl.h"

#if defined(_WIN32) || defined(_WIN64)
#define ATTR_UNUSED
#else
#define ATTR_UNUSED __attribute__((unused))
#endif

static bool signature_generated = false;
static key_paths_t *key_paths = NULL;

static SignedVideoReturnCode
unthreaded_openssl_sign_hash(signature_info_t *signature_info)
{
  if (!signature_info) return SV_INVALID_PARAMETER;
  // If we have not pulled the generated signature we cannot sign a new hash.
  if (signature_generated) return SV_NOT_SUPPORTED;

  signature_generated = true;

  return openssl_sign_hash(signature_info);
}

/* The |signature_data| is not copied since this implementation is blocking the thread and the
 * signature is written to the memory at once. */
static bool
unthreaded_openssl_has_signature(uint8_t ATTR_UNUSED *signature_data)
{
  if (signature_generated) {
    signature_generated = false;
    return true;
  }
  return false;
}

static SignedVideoReturnCode
unthreaded_setup(void)
{
  key_paths = calloc(1, sizeof(key_paths_t));
  return key_paths ? SV_OK : SV_MEMORY;
}

static void
unthreaded_teardown(void)
{
  free(key_paths);
  key_paths = NULL;
}

/**
 * Definitions of declared interfaces.
 */

SignedVideoReturnCode
sv_interface_sign_hash(signature_info_t *signature_info)
{
  return unthreaded_openssl_sign_hash(signature_info);
}

bool
sv_interface_get_signature(uint8_t *signature)
{
  return unthreaded_openssl_has_signature(signature);
}

SignedVideoReturnCode
sv_interface_setup()
{
  return unthreaded_setup();
}

void
sv_interface_teardown()
{
  unthreaded_teardown();
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
