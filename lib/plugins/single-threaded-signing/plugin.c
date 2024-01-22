/**
 * MIT License
 *
 * Copyright (c) 2024 Axis Communications AB
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
 * This signing plugin sets up a single worker thread upon initialization and calls
 * openssl_sign_hash(), from the worker thread, when there is a new hash to sign. To handle several
 * signatures at the same time, the plugin has two buffers. One for incomming hashes and another for
 * outgoing signatures. The thread is stopped if |output_buffer| is full, if there was a failure in
 * the memory allocation for a new signature or if sv_interface_exit() is called.
 * sv_interface_setup() assigns an id to the session, necessary to track hashes and signatures in
 * the input/output buffers.
 */

#include <assert.h>
#include <glib.h>
#include <stdlib.h>  // calloc, malloc, free
#include <string.h>  // memcpy

#include "includes/signed_video_interfaces.h"
#include "includes/signed_video_openssl.h"

// This means that the signing plugin can handle a blocked signing hardware up to, for example, 60
// seconds if the GOP length is 1 second
#define MAX_BUFFER_LENGTH 60

// Structure for the input buffer
typedef struct _hash_input_data_t {
  uint8_t *hash;
  size_t size;
  unsigned id;
} hash_input_data_t;

// Structure for the output buffer
typedef struct _signature_output_data_t {
  uint8_t *signature;
  size_t size;
  bool signing_error;
  unsigned id;
} signature_output_data_t;

/* Threaded plugin handle currently only stores the session id associated with it. */
typedef struct _sv_single_threaded_plugin {
  unsigned id;
} sv_single_threaded_plugin_t;

// The single thread and mutex
static GThread *thread = NULL;
static GMutex mutex;  // No need to init since statically allocated
static GCond cond;  // No need to init since statically allocated

// Variables that have to be r/w under mutex lock.
static bool is_running = false;
// Buffer of hashes to sign
static hash_input_data_t input_buffer[MAX_BUFFER_LENGTH];
static int input_buffer_idx = 0;
// Buffer of written signatures
static signature_output_data_t output_buffer[MAX_BUFFER_LENGTH];
static int output_buffer_idx = 0;
// Session id related variables
static unsigned id_in_signing = 0;
static unsigned next_id = 1;
static int num_attached_streams = 0;

// Variables that can operate without mutex lock.
// A local copy of the signature_info_t is used for signing. The hash to be signed is copied to it
// when it is time to sign.
static signature_info_t *local_signature_info = NULL;

/* Resets a hash_input_data_t element. */
static void
reset_hash_buffer(hash_input_data_t *buf)
{
  free(buf->hash);
  buf->hash = NULL;
  buf->size = 0;
  buf->id = 0;
}

/* Resets a signature_output_data_t element. */
static void
reset_signature_buffer(signature_output_data_t *buf)
{
  free(buf->signature);
  buf->signature = NULL;
  buf->size = 0;
  buf->id = 0;
  buf->signing_error = false;
}

/* Frees the memory of |local_signature_info|. */
static void
local_signature_info_free()
{
  if (!local_signature_info) return;

  free(local_signature_info->private_key);
  openssl_free(local_signature_info->signature);
  free(local_signature_info->hash);
  free(local_signature_info);
  local_signature_info = NULL;
}

/* Allocate memory and copy data for the local |signature_info|.
 *
 * This is only done once and the necessary |private_key| as well as the |algo| is copied. Memory
 * for the |signature| and the |hash| is allocated. */
static bool
local_signature_info_create(const signature_info_t *signature_info)
{
  if (local_signature_info) return true;

  local_signature_info = calloc(1, sizeof(signature_info_t));
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

  return true;

catch_error:
  local_signature_info_free();
  return false;
}

/* Flushes the input and output buffers. Need to be called under lock. */
static void
sv_threaded_plugin_reset(void)
{
  for (int i = 0; i < MAX_BUFFER_LENGTH; i++) {
    reset_signature_buffer(&output_buffer[i]);
    reset_hash_buffer(&input_buffer[i]);
  }

  input_buffer_idx = 0;
  output_buffer_idx = 0;
}

static void
buffer_remove(unsigned id)
{
  for (int i = 0; i < output_buffer_idx; i++) {
    if (output_buffer[i].id == id) {
      signature_output_data_t *tmp = &output_buffer[i];
      reset_signature_buffer(tmp);

      int j = i + 1;
      while (j < MAX_BUFFER_LENGTH) {
        output_buffer[j - 1] = output_buffer[j];
        j++;
      }
      output_buffer[j - 1] = tmp;
      output_buffer_idx--;
    }
  }

  for (int i = 0; i < input_buffer_idx; i++) {
    if (input_buffer[i].id == id) {
      hash_input_data_t *tmp = &input_buffer[i];
      reset_hash_buffer(tmp);

      int j = i + 1;
      while (j < MAX_BUFFER_LENGTH) {
        input_buffer[j - 1] = input_buffer[j];
        j++;
      }
      input_buffer[j - 1] = tmp;
      input_buffer_idx--;
    }
  }
}

/* The worker thread waits for a condition signal, triggered when there is a hash to sign. */
static void *
signing_worker_thread(void *user_data)
{
  if (user_data != NULL) return NULL;

  g_mutex_lock(&mutex);
  if (is_running) goto done;

  is_running = true;
  // Send a signal that thread has started.
  g_cond_signal(&cond);

  while (is_running) {
    if (input_buffer_idx > 0) {
      // Get the oldest hash from the input buffer
      // Copy the hash to |signature_info| and start signing.
      assert(input_buffer[0].size == local_signature_info->hash_size);
      assert(local_signature_info->hash);
      memcpy(local_signature_info->hash, input_buffer[0].hash, input_buffer[0].size);
      id_in_signing = input_buffer[0].id;

      // Move the oldest input buffer to end of queue for reuse at a later stage.
      hash_input_data_t tmp = input_buffer[0];
      int j = 0;
      while (input_buffer[j + 1].hash != NULL && j < MAX_BUFFER_LENGTH - 1) {
        input_buffer[j] = input_buffer[j + 1];
        j++;
      }
      input_buffer[j] = tmp;
      input_buffer_idx--;

      // Let the signing operate outside a lock. Otherwise sv_interface_get_signature() is blocked,
      // since variables need to be read under a lock.
      g_mutex_unlock(&mutex);
      SignedVideoReturnCode status = openssl_sign_hash(local_signature_info);
      g_mutex_lock(&mutex);

      if (output_buffer_idx >= MAX_BUFFER_LENGTH) {
        // |output_buffer| is full. Buffers this long are not supported.
        // There are no means to signal an error to the signing session. Flush all buffers and stop
        // the thread.
        is_running = false;
        sv_threaded_plugin_reset();
        goto done;
      }

      // If not successfully done with signing, set |signing_error| to true to
      // report the error when getting the signature.
      output_buffer[output_buffer_idx].signing_error = (status != SV_OK);
      output_buffer[output_buffer_idx].id = id_in_signing;

      // Allocate memory for the |signature| if necessary.
      if (!output_buffer[output_buffer_idx].signature) {
        output_buffer[output_buffer_idx].signature =
            calloc(1, local_signature_info->max_signature_size);
        if (!output_buffer[output_buffer_idx].signature) {
          // Failed in memory allocation. Stop the thread and free all memory.
          is_running = false;
          sv_threaded_plugin_reset();
          goto done;
        }
      }

      if (status == SV_OK) {
        // Copy the |signature| to the output buffer
        memcpy(output_buffer[output_buffer_idx].signature, local_signature_info->signature,
            local_signature_info->signature_size);
        output_buffer[output_buffer_idx].size = local_signature_info->signature_size;
      }
      output_buffer_idx++;
    } else {
      // Wait for a signal, triggered when it is time to sign a hash.
      g_cond_wait(&cond, &mutex);
    }
  };

done:

  g_mutex_unlock(&mutex);

  return NULL;
}

/* This function is called from the library upon signing and the input |signature_info| includes
 * all necessary information to do so.
 *
 * If this is the first time of signing, memory for |local_signature_info| is allocated and
 * |private_key| and |algo| is copied.
 *
 * The hash from |signature_info| is copied to |input_buffer|. If memory for the hash has not been
 * allocated it will be allocated. */
static SignedVideoReturnCode
single_threaded_openssl_sign_hash(sv_single_threaded_plugin_t *self,
    const signature_info_t *signature_info)
{
  assert(self && signature_info);
  if (!signature_info->private_key || !signature_info->hash) return SV_INVALID_PARAMETER;

  SignedVideoReturnCode status = SV_UNKNOWN_FAILURE;
  g_mutex_lock(&mutex);

  if (!thread || !is_running) {
    // Thread is not running. Go to catch_error and return status.
    status = SV_EXTERNAL_ERROR;
    goto done;
  }

  // If no |local_signature_info| exists. Allocate necessary memory for it and copy the
  // |private_key| and |algo|.
  if (!local_signature_info_create(signature_info)) {
    // Failed in memory allocation.
    status = SV_MEMORY;
    goto done;
  }

  if (input_buffer_idx >= MAX_BUFFER_LENGTH) {
    // |input_buffer| is full. Buffers this long are not supported.
    status = SV_NOT_SUPPORTED;
    goto done;
  }

  if (!input_buffer[input_buffer_idx].hash) {
    input_buffer[input_buffer_idx].hash = calloc(1, signature_info->hash_size);
    if (!input_buffer[input_buffer_idx].hash) {
      // Failed in memory allocation.
      status = SV_MEMORY;
      goto done;
    }
    input_buffer[input_buffer_idx].size = signature_info->hash_size;
  }

  // Currently a fixed |hash_size| throughout all sessions is assumed.
  // TODO: Should we allow to change the hash_size in runtime?
  if (signature_info->hash_size != input_buffer[input_buffer_idx].size) {
    status = SV_NOT_SUPPORTED;
    goto done;
  }

  // Copy the |hash| ready for signing.
  memcpy(input_buffer[input_buffer_idx].hash, signature_info->hash, signature_info->hash_size);
  input_buffer[input_buffer_idx].id = self->id;
  input_buffer_idx++;

  status = SV_OK;

done:

  g_cond_signal(&cond);
  g_mutex_unlock(&mutex);

  return status;
}

/* Returns true if the oldest signature in |output_buffer| has been copied to |signature|, otherwise
 * false. Moves the signatures in |output_buffer| forward when the copy is done. */
static bool
single_threaded_openssl_get_signature(sv_single_threaded_plugin_t *self,
    uint8_t *signature,
    size_t max_signature_size,
    size_t *written_signature_size,
    SignedVideoReturnCode *error)
{
  assert(self && signature && written_signature_size);

  bool has_copied_signature = false;
  SignedVideoReturnCode status = SV_OK;

  g_mutex_lock(&mutex);

  if (!thread || !is_running) {
    // Thread is not running. Go to done and return error.
    status = SV_EXTERNAL_ERROR;
    goto done;
  }

  // Return if no signature exists in the buffer.
  if (output_buffer_idx == 0) goto done;

  // Return if next signature belongs to a different stream.
  if (output_buffer[0].id != self->id) goto done;

  *written_signature_size = 0;
  if (output_buffer[0].signing_error) {
    // Propagate SV_EXTERNAL_ERROR when signing failed.
    status = SV_EXTERNAL_ERROR;
  } else if (output_buffer[0].size > max_signature_size) {
    // There is no room to copy the signature, set status to invalid parameter.
    status = SV_INVALID_PARAMETER;
  } else {
    // Copy the oldest signature
    memcpy(signature, output_buffer[0].signature, output_buffer[0].size);
    *written_signature_size = output_buffer[0].size;
    // Change state and mark as copied.
    has_copied_signature = true;
  }
  // Move buffer
  signature_output_data_t tmp = output_buffer[0];
  int i = 0;
  while (output_buffer[i + 1].signature != NULL && i < MAX_BUFFER_LENGTH - 1) {
    output_buffer[i] = output_buffer[i + 1];
    i++;
  }
  output_buffer[i] = tmp;
  output_buffer_idx--;
done:
  g_mutex_unlock(&mutex);

  if (error) *error = status;

  return has_copied_signature;
}

/**
 * Definitions of declared interfaces. For declarations see signed_video_interfaces.h.
 */

SignedVideoReturnCode
sv_interface_sign_hash(void *plugin_handle, signature_info_t *signature_info)
{
  sv_single_threaded_plugin_t *self = (sv_single_threaded_plugin_t *)plugin_handle;

  if (!self || !signature_info) return SV_INVALID_PARAMETER;

  return single_threaded_openssl_sign_hash(self, signature_info);
}

bool
sv_interface_get_signature(void *plugin_handle,
    uint8_t *signature,
    size_t max_signature_size,
    size_t *written_signature_size,
    SignedVideoReturnCode *error)
{
  sv_single_threaded_plugin_t *self = (sv_single_threaded_plugin_t *)plugin_handle;

  if (!self || !signature || !written_signature_size) return false;

  return single_threaded_openssl_get_signature(
      self, signature, max_signature_size, written_signature_size, error);
}

/* This function is called when a Signed Video session is created.
 * Here, a worker thread for signing is started.
 *
 * returns sv_threaded_plugin_t if the thread was successfully started, and NULL upon failure. */
void *
sv_interface_setup()
{
  sv_single_threaded_plugin_t *self = calloc(1, sizeof(sv_single_threaded_plugin_t));

  if (!self) return NULL;

  // Check if the thread is running. If no thread exists, create one.
  g_mutex_lock(&mutex);
  if (!thread) {
    if (!sv_interface_init()) {
      g_mutex_unlock(&mutex);
      goto catch_error;
    }
  }
  if (!is_running) {
    g_mutex_unlock(&mutex);
    goto catch_error;
  }

  self->id = next_id;
  next_id++;
  if (next_id == 0) next_id++;  // Handle wraparound

  num_attached_streams++;

  g_mutex_unlock(&mutex);

  return (void *)self;

catch_error:
  free(self);
  return NULL;
}

void
sv_interface_teardown(void *plugin_handle)
{
  sv_single_threaded_plugin_t *self = (sv_single_threaded_plugin_t *)plugin_handle;

  g_mutex_lock(&mutex);
  buffer_remove(self->id);
  num_attached_streams--;
  g_mutex_unlock(&mutex);

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

int
sv_interface_init()
{
  if (thread) return 0;

  thread = g_thread_try_new("signing-worker-thread", signing_worker_thread, NULL, NULL);
  if (!thread) return -1;

  // Wait for the thread to start before returning.
  g_mutex_lock(&mutex);
  // TODO: Consider using g_cond_wait_until() instead, to avoid deadlock.
  while (!is_running) g_cond_wait(&cond, &mutex);

  g_mutex_unlock(&mutex);
  return 0;
}

void
sv_interface_exit()
{
  g_mutex_lock(&mutex);

  if (num_attached_streams > 0) {
    g_warning("Terminating Signed Video signing thread when %d sessions are still attached",
        num_attached_streams);
  }

  if (!thread) {
    g_mutex_unlock(&mutex);
    goto done;
  }

  GThread *tmp_thread = thread;

  is_running = false;
  thread = NULL;
  g_cond_signal(&cond);
  g_mutex_unlock(&mutex);

  g_thread_join(tmp_thread);

done:
  sv_threaded_plugin_reset();
  local_signature_info_free();
}
