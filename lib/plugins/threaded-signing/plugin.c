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
 * thread, when there is a new hash to sign. The plugin can only handle one signature at a time.
 * To handle delays, there are therefore two buffers. One for incomming hashes and another for
 * outgoing signatures.
 */

#include <assert.h>
#include <glib.h>
#include <stdlib.h>  // calloc, malloc, free
#include <string.h>  // memcpy
#include <unistd.h>

#include "includes/signed_video_interfaces.h"
#include "includes/signed_video_openssl.h"

// This means that the signing plugin can handle a blocked signing hardware up to, for example, 60
// seconds if the GOP length is 1 second
#define MAX_BUFFER_LENGTH 60

typedef struct _output_data_t {
  uint8_t *signature;
  size_t size;
  bool signing_error;
} output_data_t;

/* Threaded plugin handle maintaining the thread and locks. Further, stores the hashes to sign and
 * the written signatures in two buffers */
typedef struct _sv_threaded_plugin {
  GThread *thread;
  GMutex mutex;
  GCond cond;

  // Variables that has to be r/w under mutex lock.
  bool is_running;
  // Buffer of hashes to sign
  uint8_t *input_buffer[MAX_BUFFER_LENGTH];
  int input_buffer_idx;
  size_t hash_size;
  // Buffer of written signatures
  output_data_t output_buffer[MAX_BUFFER_LENGTH];
  int output_buffer_idx;
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
 * |mutex|, |cond| and |is_running|. */
static void
sv_threaded_plugin_reset(sv_threaded_plugin_t *self)
{
  local_signature_info_free(self->signature_info);
  self->signature_info = NULL;

  for (int i = 0; i < MAX_BUFFER_LENGTH; i++) {
    free(self->output_buffer[i].signature);
    self->output_buffer[i].signature = NULL;
    self->output_buffer[i].size = 0;
    self->output_buffer[i].signing_error = false;
  }

  for (int j = 0; j < MAX_BUFFER_LENGTH; j++) {
    free(self->input_buffer[j]);
    self->input_buffer[j] = NULL;
  }
  self->hash_size = 0;
}

static int a = 0;
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
    if (self->input_buffer_idx > 0) {
      // Get the oldest hash from the input buffer
      // Copy the hash to |signature_info| and start signing. In principle, it is now possible to
      // prepare for a new hash.
      assert(self->hash_size == self->signature_info->hash_size);
      assert(self->signature_info->hash);
      memcpy(self->signature_info->hash, self->input_buffer[0], self->hash_size);

      uint8_t *tmp = self->input_buffer[0];
      int j = 0;
      while (self->input_buffer[j] != NULL && j < MAX_BUFFER_LENGTH) {
        self->input_buffer[j] = self->input_buffer[j + 1];
        j++;
      }
      self->input_buffer[j - 1] = tmp;
      self->input_buffer_idx -= 1;

      // Let the signing operate outside a lock. Otherwise sv_interface_get_signature() is blocked,
      // since variables need to be read under a lock.
      g_mutex_unlock(&self->mutex);
      SignedVideoReturnCode status = openssl_sign_hash(self->signature_info);
      // TODO: Remove sleeps
      a++;
      if (a > 3) {
        sleep(0);
      } else {
        sleep(5);
      }
      g_mutex_lock(&self->mutex);

      // If not successfully done with signing, set |signing_error| to true to
      // report the error when getting the signature.
      self->output_buffer[self->output_buffer_idx].signing_error = (status != SV_OK);

      if (status == SV_OK) {
        // Allocate memory for the |signature| if necessary.
        if (!self->output_buffer[self->output_buffer_idx].signature) {
          self->output_buffer[self->output_buffer_idx].signature =
              calloc(1, self->signature_info->max_signature_size);
        }
        if (!self->output_buffer[self->output_buffer_idx].signature) {
          // Failed in memory allocation. Free all memory and set status to SV_MEMORY.
          sv_threaded_plugin_reset(self);
          status = SV_MEMORY;
        }

        // Copy the |signature| to the output buffer
        memcpy(self->output_buffer[self->output_buffer_idx].signature,
            self->signature_info->signature, self->output_buffer[self->output_buffer_idx].size);
        self->output_buffer[self->output_buffer_idx].size = self->signature_info->signature_size;
        self->output_buffer_idx++;
      }
    } else {
      // Wait for a signal, triggered when it is time to sign a hash.
      g_cond_wait(&self->cond, &self->mutex);
    }
  };

done:
  g_mutex_unlock(&self->mutex);

  return NULL;
}

/* This function is called from the library upon signing and the input |signature_info| includes
 * all necessary information to do so.
 *
 * The |hash| is copied to |input_buffer|. If this is the first time of signing, memory for
 * |input_buffer| is allocated and the |private_key| is copied from |signature_info|. */
static SignedVideoReturnCode
threaded_openssl_sign_hash(sv_threaded_plugin_t *self, const signature_info_t *signature_info)
{
  assert(self && signature_info);
  if (!signature_info->private_key || !signature_info->hash) return SV_INVALID_PARAMETER;

  SignedVideoReturnCode status = SV_UNKNOWN_FAILURE;
  g_mutex_lock(&self->mutex);

  // If no |self->signature_info| exists. Allocate necessary memory for it and copy the
  // |private_key| and |algo|.
  if (!self->signature_info) {
    self->signature_info = local_signature_info_create(signature_info);
    if (!self->signature_info) goto catch_error;
  }

  if (!self->input_buffer[self->input_buffer_idx]) {
    self->input_buffer[self->input_buffer_idx] = calloc(1, signature_info->hash_size);
    if (!self->input_buffer[self->input_buffer_idx]) goto catch_error;
    self->hash_size = signature_info->hash_size;
  }

  // Currently a fixed |hash_size| throughout the session is assumed.
  // TODO: Should we allow to change the hash_size in runtime?
  if (signature_info->hash_size != self->hash_size) goto catch_error;

  // Copy the |hash| ready for signing.
  memcpy(
      self->input_buffer[self->input_buffer_idx], signature_info->hash, signature_info->hash_size);
  self->input_buffer_idx++;

  status = SV_OK;

catch_error:
  if (status == SV_UNKNOWN_FAILURE) {
    // Failed in memory allocation. Free all memory and set status to SV_MEMORY.
    sv_threaded_plugin_reset(self);
    status = SV_MEMORY;
  }

  g_cond_signal(&self->cond);
  g_mutex_unlock(&self->mutex);

  return status;
}

/* Returns true if a new |signature| has been copied to output, otherwise false.
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
  if (self->output_buffer[0].signing_error) {
    *written_signature_size = 0;
    // Propagate SV_EXTERNAL_ERROR when signing failed.
    status = SV_EXTERNAL_ERROR;
  } else if (self->output_buffer_idx > 0) {
    if (self->output_buffer[0].size > max_signature_size) {
      // If there is no room to copy the signature, report zero size.
      *written_signature_size = 0;
    } else {
      // Get the oldest signature
      memcpy(signature, self->output_buffer[0].signature, self->output_buffer[0].size);
      *written_signature_size = self->output_buffer[0].size;
      // Change state and mark as copied.
      has_copied_signature = true;
    }
  }
  if (self->output_buffer_idx > 0) {
    // Move buffer
    output_data_t tmp = self->output_buffer[0];
    int i = 0;
    while (self->output_buffer[i].signature != NULL) {
      self->output_buffer[i] = self->output_buffer[i + 1];
      i++;
    }
    self->output_buffer[i - 1] = tmp;
    self->output_buffer_idx -= 1;
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
