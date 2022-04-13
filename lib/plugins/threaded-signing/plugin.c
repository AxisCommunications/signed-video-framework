/**
 * MIT License
 *
 * Copyright (c) 2022 Axis Communications AB
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
 * This signing plugin sets up a worker thread and calls openssl_sign_hash(), from the worker
 * thread, when there is a new hash to sign. The plugin can only handle one signature at a time,
 * that is, there is no queue of hashes to sign. If the latest signature is not completed by the
 * time of a new request, that new hash is not signed.
 */

#include <assert.h>
#include <glib.h>
#include <stdlib.h>  // calloc, malloc, free
#include <string.h>  // memcpy

#include "includes/signed_video_interfaces.h"
#include "includes/signed_video_openssl.h"

typedef enum {
  THREADED_SIGNING_WAITS_FOR_HASH_TO_SIGN,
  THREADED_SIGNING_HAS_HASH_TO_SIGN,
  THREADED_SIGNING_SIGNS_HASH,
  THREADED_SIGNING_HAS_SIGNATURE,
  THREADED_SIGNING_ERROR,
} threaded_signing_plugin_state;

/* Threaded plugin handle maintaining the thread and locks. Further, stores the hash to sign and the
 * written signature (part of |signature_info|): */
typedef struct _sv_threaded_plugin {
  GThread *thread;
  GMutex mutex;
  GCond cond;

  // Variables that has to be r/w under mutex lock.
  bool is_running;
  threaded_signing_plugin_state plugin_state;
  uint8_t *hash_to_sign;
  size_t hash_size;
  int nbr_of_unsigned_hashes;  // Tracks hashes that could not be signed.

  // Variables that can operate without mutex lock.
  // A local copy of the signature_info is used for signing. The hash to be signed is copied to it
  // when it is time to sign.
  signature_info_t *signature_info;
} sv_threaded_plugin_t;

/* Frees the memory of |signature_info|. */
static void
local_signature_info_free(signature_info_t *signature_info)
{
  if (!signature_info) return;

  free(signature_info->private_key);
  openssl_free(signature_info->signature);
  free(signature_info->hash);
  free(signature_info);
}

/* Allocate memory and copy data for the local |signature_info|.
 *
 * This is only done once and the necessary |private_key| as well as the |algo| is copied. Memory
 * for the |signature| and the |hash| is allocated. */
static signature_info_t *
local_signature_info_create(const signature_info_t *signature_info)
{
  signature_info_t *local_signature_info = calloc(1, sizeof(signature_info_t));
  if (!local_signature_info) goto catch_error;

  // Allocate memory and copy |private_key|.
  local_signature_info->private_key = malloc(signature_info->private_key_size);
  if (!local_signature_info->private_key) goto catch_error;
  memcpy(local_signature_info->private_key, signature_info->private_key,
      signature_info->private_key_size);
  local_signature_info->private_key_size = signature_info->private_key_size;

  // Allocate memory for the |signature|.
  local_signature_info->signature = openssl_malloc(signature_info->max_signature_size);
  if (!local_signature_info->signature) goto catch_error;
  local_signature_info->max_signature_size = signature_info->max_signature_size;

  // Allocate memory for the |hash|.
  local_signature_info->hash = calloc(1, signature_info->hash_size);
  if (!local_signature_info->hash) goto catch_error;
  local_signature_info->hash_size = signature_info->hash_size;
  // Copy the |algo|.
  local_signature_info->algo = signature_info->algo;

  return local_signature_info;

catch_error:
  local_signature_info_free(local_signature_info);
  return NULL;
}

/* Frees all allocated memory and resets members. Excluded are the worker thread members |thread|,
 * |mutex|, |cond| and |is_running|, but also the counter |nbr_of_unsigned_hashes|. */
static void
sv_threaded_plugin_reset(sv_threaded_plugin_t *self)
{
  local_signature_info_free(self->signature_info);
  self->signature_info = NULL;
  free(self->hash_to_sign);
  self->hash_to_sign = NULL;
  self->hash_size = 0;
  self->plugin_state = THREADED_SIGNING_WAITS_FOR_HASH_TO_SIGN;
}

/* The worker thread waits for a condition signal, triggered when there is a hash to sign. */
static void *
signing_worker_thread(void *user_data)
{
  sv_threaded_plugin_t *self = (sv_threaded_plugin_t *)user_data;

  g_mutex_lock(&self->mutex);
  if (self->is_running) goto done;

  self->is_running = true;
  // Send a signal that thread has started.
  g_cond_signal(&self->cond);

  while (self->is_running) {
    // Wait for a signal, triggered when it is time to sign a hash.
    g_cond_wait(&self->cond, &self->mutex);

    if (self->plugin_state == THREADED_SIGNING_HAS_HASH_TO_SIGN) {
      // Copy the |hash_to_sign| to |signature_info| and start signing. In principle, it is now
      // possible to prepare for a new |hash_to_sign|.
      assert(self->hash_size == self->signature_info->hash_size);
      memcpy(self->signature_info->hash, self->hash_to_sign, self->hash_size);
      self->plugin_state = THREADED_SIGNING_SIGNS_HASH;

      // Let the signing operate outside a lock. Otherwise sv_interface_get_signature() is blocked,
      // since variables need to be read under a lock.
      g_mutex_unlock(&self->mutex);
      SignedVideoReturnCode status = openssl_sign_hash(self->signature_info);

      g_mutex_lock(&self->mutex);
      // When successfully done with signing, move |plugin_state| to THREADED_SIGNING_HAS_SIGNATURE,
      // otherwise move to THREADED_SIGNING_ERROR to report the error when getting the signature.
      if (status == SV_OK) {
        self->plugin_state = THREADED_SIGNING_HAS_SIGNATURE;
      } else {
        self->plugin_state = THREADED_SIGNING_ERROR;
      }
    }
  };

done:
  g_mutex_unlock(&self->mutex);

  return NULL;
}

/* This function is called from the library upon signing and the input |signature_info| includes
 * all necessary information to do so.
 *
 * The |hash| is copied to |hash_to_sign| and the |plugin_state| is moved to
 * THREADED_SIGNING_HAS_HASH_TO_SIGN. If this is the first time of signing, memory for
 * |self->signature_info| and |hash_to_sign| is allocated and the |private_key| is copied from
 * |signature_info|.
 *
 * Further, if there is no worker thread running or if the latest signing has not yet finished an
 * SV_NOT_SUPPORTED is returned. */
static SignedVideoReturnCode
threaded_openssl_sign_hash(sv_threaded_plugin_t *self, const signature_info_t *signature_info)
{
  assert(self && signature_info);
  if (!signature_info->private_key || !signature_info->hash) return SV_INVALID_PARAMETER;

  SignedVideoReturnCode status = SV_UNKNOWN_FAILURE;
  g_mutex_lock(&self->mutex);

  // If the signature has not yet been pulled, or even generated, a new signature cannot be
  // generated without replacing it. Log in |nbr_of_unsigned_hashes| and move to done.
  if (self->plugin_state != THREADED_SIGNING_WAITS_FOR_HASH_TO_SIGN) {
    self->nbr_of_unsigned_hashes++;
    status = SV_OK;
    goto done;
  }

  // If no |self->signature_info| exists. Allocate necessary memory for it and copy the
  // |private_key| and |algo|.
  if (!self->signature_info) {
    self->signature_info = local_signature_info_create(signature_info);
    if (!self->signature_info) goto catch_error;
  }

  // Allocate memory for the |hash_to_sign| if necessary.
  if (!self->hash_to_sign) {
    self->hash_to_sign = calloc(1, signature_info->hash_size);
    if (!self->hash_to_sign) goto catch_error;
    self->hash_size = signature_info->hash_size;
  }

  // Currently a fixed |hash_size| throughout the session is assumed.
  // TODO: Should we allow to change the hash_size in runtime?
  if (signature_info->hash_size != self->hash_size) goto catch_error;

  // Copy the |hash| ready for signing.
  memcpy(self->hash_to_sign, signature_info->hash, signature_info->hash_size);

  status = SV_OK;
  self->plugin_state = THREADED_SIGNING_HAS_HASH_TO_SIGN;

catch_error:
  if (status == SV_UNKNOWN_FAILURE) {
    // Failed in memory allocation. Free all memory and set status to SV_MEMORY.
    sv_threaded_plugin_reset(self);
    status = SV_MEMORY;
  }

  g_cond_signal(&self->cond);
done:
  g_mutex_unlock(&self->mutex);

  return status;
}

/* If |plugin_state| = THREADED_SIGNING_HAS_SIGNATURE a new |signature| has been written to
 * |signature_info|. The new |signature| is then copied to the output and the |plugin_state|
 * is set to THREADED_SIGNING_WAITS_FOR_HASH_TO_SIGN.
 *
 * Returns true if a new |signature| has been copied to output, otherwise false.
 * If the hash could not be signed due to a blocked openssl_sign_hash(), |signature_size| is set to
 * zero, but still returning true. */
static bool
threaded_openssl_get_signature(sv_threaded_plugin_t *self,
    uint8_t *signature,
    size_t max_signature_size,
    size_t *written_signature_size,
    SignedVideoReturnCode *error)
{
  assert(self && signature && written_signature_size);

  bool has_copied_signature = false;
  SignedVideoReturnCode status = SV_OK;

  g_mutex_lock(&self->mutex);
  if (self->plugin_state == THREADED_SIGNING_HAS_SIGNATURE && self->signature_info) {
    if (self->signature_info->signature_size > max_signature_size) {
      // If there is no room to copy the signature, report zero size.
      *written_signature_size = 0;
    } else {
      memcpy(signature, self->signature_info->signature, self->signature_info->signature_size);
      *written_signature_size = self->signature_info->signature_size;
    }
    // Change state and mark as copied.
    self->plugin_state = THREADED_SIGNING_WAITS_FOR_HASH_TO_SIGN;
    has_copied_signature = true;
  } else if (self->plugin_state == THREADED_SIGNING_ERROR) {
    *written_signature_size = 0;
    // Change state and mark as copied.
    self->plugin_state = THREADED_SIGNING_WAITS_FOR_HASH_TO_SIGN;
    has_copied_signature = true;
    // Propagate SV_EXTERNAL_ERROR when signing failed.
    status = SV_EXTERNAL_ERROR;
  } else if (self->plugin_state == THREADED_SIGNING_WAITS_FOR_HASH_TO_SIGN &&
      self->nbr_of_unsigned_hashes > 0) {
    // There are unsigned hashes in the pipe. Report them with zero size, since no signature exists.
    *written_signature_size = 0;
    self->nbr_of_unsigned_hashes--;
    has_copied_signature = true;
  }
  g_mutex_unlock(&self->mutex);

  if (error) *error = status;

  return has_copied_signature;
}

/**
 * Definitions of declared interfaces. For declarations see signed_video_interfaces.h.
 */

SignedVideoReturnCode
sv_interface_sign_hash(void *plugin_handle, signature_info_t *signature_info)
{
  sv_threaded_plugin_t *self = (sv_threaded_plugin_t *)plugin_handle;

  if (!self || !signature_info) return SV_INVALID_PARAMETER;

  return threaded_openssl_sign_hash(self, signature_info);
}

bool
sv_interface_get_signature(void *plugin_handle,
    uint8_t *signature,
    size_t max_signature_size,
    size_t *written_signature_size,
    SignedVideoReturnCode *error)
{
  sv_threaded_plugin_t *self = (sv_threaded_plugin_t *)plugin_handle;

  if (!self || !signature || !written_signature_size) return false;

  return threaded_openssl_get_signature(
      self, signature, max_signature_size, written_signature_size, error);
}

/* This function is called when a Signed Video session is created.
 * Here, a worker thread for signing is started.
 *
 * returns sv_threaded_plugin_t if the thread was successfully started, and NULL upon failure. */
void *
sv_interface_setup()
{
  GError *error = NULL;
  sv_threaded_plugin_t *self = calloc(1, sizeof(sv_threaded_plugin_t));

  if (!self) return NULL;

  // Initialize |self|.
  self->plugin_state = THREADED_SIGNING_WAITS_FOR_HASH_TO_SIGN;
  g_mutex_init(&(self->mutex));
  g_cond_init(&(self->cond));

  self->thread =
      g_thread_try_new("signing-worker-thread", signing_worker_thread, (void *)self, &error);

  if (!self->thread) goto catch_error;

  // Wait for the thread to start before returning.
  g_mutex_lock(&self->mutex);
  // TODO: Consider using g_cond_wait_until() instead, to avoid deadlock.
  while (!self->is_running) g_cond_wait(&self->cond, &self->mutex);

  g_mutex_unlock(&self->mutex);

  return (void *)self;

catch_error:
  g_error_free(error);
  free(self);
  return NULL;
}

void
sv_interface_teardown(void *plugin_handle)
{
  sv_threaded_plugin_t *self = (sv_threaded_plugin_t *)plugin_handle;

  g_mutex_lock(&self->mutex);

  if (!self->thread) {
    g_mutex_unlock(&self->mutex);
    goto done;
  }

  GThread *thread = self->thread;

  self->is_running = false;
  self->thread = NULL;
  g_cond_signal(&self->cond);
  g_mutex_unlock(&self->mutex);

  g_thread_join(thread);

done:
  sv_threaded_plugin_reset(self);
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
