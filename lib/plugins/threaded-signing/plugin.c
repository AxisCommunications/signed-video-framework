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
 * thread, when there is a new hash to sign. To handle several signatures at the same time, the
 * plugin has two buffers. One for incomming hashes and another for outgoing signatures.
 * The thread is stopped if |output_buffer| is full, if there was a failure in the memory allocation
 * for a new signature or if sv_interface_teardown is called.
 *
 * If the plugin is initialized, sv_interface_init(), one single central thread is spawned. Signed
 * Video session will then attach to that thread and use common input and output buffers.
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

// Structure for the input buffer of hashes
typedef struct _hash_data_t {
  uint8_t *hash;
  size_t size;
  unsigned id;
} hash_data_t;

// Structure for the output buffer of signatures
typedef struct _signature_data_t {
  uint8_t *signature;
  size_t size;
  bool signing_error;
  unsigned id;
} signature_data_t;

/* Threaded plugin handle maintaining the thread and locks. Furthermore, it stores the hashes to
 * sign and the written signatures in two different buffers */
typedef struct _local_threaded_data {
  GThread *thread;
  GMutex mutex;
  GCond cond;

  // Variables that have to be r/w under mutex lock.
  bool is_running;
  // Buffer of hashes to sign
  hash_data_t input_buffer[MAX_BUFFER_LENGTH];
  int input_buffer_idx;
  // Buffer of written signatures
  signature_data_t output_buffer[MAX_BUFFER_LENGTH];
  int output_buffer_idx;
  // Variables that can operate without mutex lock.
  // A local copy of the signature_info is used for signing. The hash to be signed is copied to it
  // when it is time to sign.
  signature_info_t *signature_info;
} local_threaded_data_t;

typedef struct _central_threaded_data {
  unsigned id;
} central_threaded_data_t;

/* Threaded plugin handle containing data for either a local signing or a central signing. */
typedef struct _sv_threaded_plugin {
  central_threaded_data_t *central;
  local_threaded_data_t *local;
} sv_threaded_plugin_t;

// Static members for a central thread
local_threaded_data_t central = {0};
// Session id related variables
static unsigned id_in_signing = 0;
static unsigned next_id = 1;
static int num_active_streams = 0;

/*
 * Helper functions common to both a local and a central thread.
 */

/* Resets a hash_input_data_t element. */
static void
reset_hash_buffer(hash_data_t *buf)
{
  free(buf->hash);
  buf->hash = NULL;
  buf->size = 0;
  buf->id = 0;
}

/* Resets a signature_output_data_t element. */
static void
reset_signature_buffer(signature_data_t *buf)
{
  free(buf->signature);
  buf->signature = NULL;
  buf->size = 0;
  buf->id = 0;
  buf->signing_error = false;
}

static void
buffer_remove(unsigned id)
{
  for (int i = 0; i < central.output_buffer_idx; i++) {
    if (central.output_buffer[i].id == id) {
      signature_data_t *tmp = &(central.output_buffer[i]);
      reset_signature_buffer(tmp);

      int j = i + 1;
      while (j < MAX_BUFFER_LENGTH) {
        central.output_buffer[j - 1] = central.output_buffer[j];
        j++;
      }
      central.output_buffer[j - 1] = *tmp;
      central.output_buffer_idx--;
    }
  }

  for (int i = 0; i < central.input_buffer_idx; i++) {
    if (central.input_buffer[i].id == id) {
      hash_data_t *tmp = &(central.input_buffer[i]);
      reset_hash_buffer(tmp);

      int j = i + 1;
      while (j < MAX_BUFFER_LENGTH) {
        central.input_buffer[j - 1] = central.input_buffer[j];
        j++;
      }
      central.input_buffer[j - 1] = *tmp;
      central.input_buffer_idx--;
    }
  }
}

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
reset_plugin(local_threaded_data_t *self)
{
  local_signature_info_free(self->signature_info);
  self->signature_info = NULL;

  for (int i = 0; i < MAX_BUFFER_LENGTH; i++) {
    reset_signature_buffer(&self->output_buffer[i]);
    reset_hash_buffer(&self->input_buffer[i]);
  }
  self->input_buffer_idx = 0;
  self->output_buffer_idx = 0;
}

/* This function is called from the library upon signing and the input |signature_info| includes
 * all necessary information to do so.
 *
 * If this is the first time of signing, memory for |self->signature_info| is allocated and
 * |private_key| and |algo| is copied.
 *
 * The hash from |signature_info| is copied to |input_buffer|. If memory for the hash has not been
 * allocated it will be allocated. */
static SignedVideoReturnCode
sign_hash(local_threaded_data_t *self, unsigned id, const signature_info_t *signature_info)
{
  assert(self && signature_info);
  if (!signature_info->private_key || !signature_info->hash) return SV_INVALID_PARAMETER;

  SignedVideoReturnCode status = SV_UNKNOWN_FAILURE;
  g_mutex_lock(&self->mutex);

  if (!self->is_running) {
    // Thread is not running. Go to catch_error and return status.
    status = SV_EXTERNAL_ERROR;
    goto done;
  }

  // If no |self->signature_info| exists. Allocate necessary memory for it and copy the
  // |private_key| and |algo|.
  if (!self->signature_info) {
    self->signature_info = local_signature_info_create(signature_info);
    if (!self->signature_info) {
      // Failed in memory allocation.
      status = SV_MEMORY;
      goto done;
    }
  }

  if (self->input_buffer_idx >= MAX_BUFFER_LENGTH) {
    // |input_buffer| is full. Buffers this long are not supported.
    status = SV_NOT_SUPPORTED;
    goto done;
  }

  // The |hash_size| has to be fixed throughout the session.
  if (self->signature_info->hash_size != signature_info->hash_size) {
    status = SV_NOT_SUPPORTED;
    goto done;
  }

  if (!self->input_buffer[self->input_buffer_idx].hash) {
    self->input_buffer[self->input_buffer_idx].hash = calloc(1, signature_info->hash_size);
    if (!self->input_buffer[self->input_buffer_idx].hash) {
      // Failed in memory allocation.
      status = SV_MEMORY;
      goto done;
    }
    self->input_buffer[self->input_buffer_idx].size = signature_info->hash_size;
  }

  // Copy the |hash| ready for signing.
  memcpy(self->input_buffer[self->input_buffer_idx].hash, signature_info->hash,
      signature_info->hash_size);
  central.input_buffer[central.input_buffer_idx].id = id;
  self->input_buffer_idx++;

  status = SV_OK;

done:

  g_cond_signal(&self->cond);
  g_mutex_unlock(&self->mutex);

  return status;
}

/* If
 *   1. the |id| matches the oldest |output_buffer|, and
 *   2. the signature in |output_buffer| has been copied to |signature|
 * then returns true, otherwise false.
 * Moves the signatures in |output_buffer| forward when the copy is done. */
static bool
get_signature(local_threaded_data_t *self,
    unsigned id,
    uint8_t *signature,
    size_t max_signature_size,
    size_t *written_signature_size,
    SignedVideoReturnCode *error)
{
  assert(self && signature && written_signature_size);

  bool has_copied_signature = false;
  SignedVideoReturnCode status = SV_OK;

  g_mutex_lock(&self->mutex);

  if (!self->is_running) {
    // Thread is not running. Go to done and return error.
    status = SV_EXTERNAL_ERROR;
    goto done;
  }

  // Return if there are no signatures in the buffer
  if (self->output_buffer_idx == 0) goto done;

  // Return if next signature belongs to a different session.
  if (self->output_buffer[0].id != id) goto done;

  *written_signature_size = 0;
  if (self->output_buffer[0].signing_error) {
    // Propagate SV_EXTERNAL_ERROR when signing failed.
    status = SV_EXTERNAL_ERROR;
  } else if (self->output_buffer[0].size > max_signature_size) {
    // There is no room to copy the signature, set status to invalid parameter.
    status = SV_INVALID_PARAMETER;
  } else {
    // Copy the oldest signature
    memcpy(signature, self->output_buffer[0].signature, self->output_buffer[0].size);
    *written_signature_size = self->output_buffer[0].size;
    // Mark as copied.
    has_copied_signature = true;
  }
  // Move buffer
  signature_data_t tmp = self->output_buffer[0];
  int i = 0;
  while (self->output_buffer[i + 1].signature != NULL && i < MAX_BUFFER_LENGTH - 1) {
    self->output_buffer[i] = self->output_buffer[i + 1];
    i++;
  }
  self->output_buffer[i] = tmp;
  self->output_buffer_idx--;
done:
  g_mutex_unlock(&self->mutex);

  if (error) *error = status;

  return has_copied_signature;
}

/*
 * Helper functions for a central thread.
 */

/* The worker thread waits for a condition signal, triggered when there is a hash to sign. */
static void *
central_worker_thread(void *user_data)
{
  if (user_data != NULL) return NULL;

  g_mutex_lock(&(central.mutex));
  if (central.is_running) goto done;

  central.is_running = true;
  // Send a signal that thread has started.
  g_cond_signal(&(central.cond));

  while (central.is_running) {
    if (central.input_buffer_idx > 0) {
      // Get the oldest hash from the input buffer
      // Copy the hash to |signature_info| and start signing.
      assert(central.input_buffer[0].size == central.signature_info->hash_size);
      assert(central.signature_info->hash);
      memcpy(
          central.signature_info->hash, central.input_buffer[0].hash, central.input_buffer[0].size);
      id_in_signing = central.input_buffer[0].id;

      // Move the oldest input buffer to end of queue for reuse at a later stage.
      hash_data_t tmp = central.input_buffer[0];
      int j = 0;
      while (central.input_buffer[j + 1].hash != NULL && j < MAX_BUFFER_LENGTH - 1) {
        central.input_buffer[j] = central.input_buffer[j + 1];
        j++;
      }
      central.input_buffer[j] = tmp;
      central.input_buffer_idx--;

      // Let the signing operate outside a lock. Otherwise sv_interface_get_signature() is blocked,
      // since variables need to be read under a lock.
      g_mutex_unlock(&(central.mutex));
      SignedVideoReturnCode status = openssl_sign_hash(central.signature_info);
      g_mutex_lock(&(central.mutex));

      if (central.output_buffer_idx >= MAX_BUFFER_LENGTH) {
        // |output_buffer| is full. Buffers this long are not supported.
        // There are no means to signal an error to the signing session. Flush all buffers and stop
        // the thread.
        central.is_running = false;
        reset_plugin(&central);
        goto done;
      }

      // If not successfully done with signing, set |signing_error| to true to
      // report the error when getting the signature.
      central.output_buffer[central.output_buffer_idx].signing_error = (status != SV_OK);
      central.output_buffer[central.output_buffer_idx].id = id_in_signing;

      // Allocate memory for the |signature| if necessary.
      if (!central.output_buffer[central.output_buffer_idx].signature) {
        central.output_buffer[central.output_buffer_idx].signature =
            calloc(1, central.signature_info->max_signature_size);
        if (!central.output_buffer[central.output_buffer_idx].signature) {
          // Failed in memory allocation. Stop the thread and free all memory.
          central.is_running = false;
          reset_plugin(&central);
          goto done;
        }
      }

      if (status == SV_OK) {
        // Copy the |signature| to the output buffer
        memcpy(central.output_buffer[central.output_buffer_idx].signature,
            central.signature_info->signature, central.signature_info->signature_size);
        central.output_buffer[central.output_buffer_idx].size =
            central.signature_info->signature_size;
      }
      central.output_buffer_idx++;
    } else {
      // Wait for a signal, triggered when it is time to sign a hash.
      g_cond_wait(&(central.cond), &(central.mutex));
    }
  };

done:

  g_mutex_unlock(&(central.mutex));

  return NULL;
}

/* This function creates an id for the session to identify hashes and signatures.
 *
 * returns sv_threaded_plugin_t upon success, and NULL upon failure. */
static central_threaded_data_t *
central_setup()
{
  central_threaded_data_t *self = calloc(1, sizeof(central_threaded_data_t));

  if (!self) return NULL;

  // Make sure that the thread is running.
  g_mutex_lock(&(central.mutex));

  if (!central.is_running) {
    g_mutex_unlock(&(central.mutex));
    free(self);
    return NULL;
  }

  // TODO: Add a list of attached ids to make it possible to detect existing ids.
  self->id = next_id;
  next_id++;
  if (next_id == 0) next_id++;  // Handles wraparound

  num_active_streams++;

  g_mutex_unlock(&(central.mutex));

  return self;
}

static void
central_teardown(central_threaded_data_t *self)
{
  g_mutex_lock(&(central.mutex));
  buffer_remove(self->id);
  num_active_streams--;
  g_mutex_unlock(&(central.mutex));

  free(self);
}

/*
 * Helper functions for a local thread.
 */

/* The worker thread waits for a condition signal, triggered when there is a hash to sign. */
static void *
local_worker_thread(void *user_data)
{
  local_threaded_data_t *self = (local_threaded_data_t *)user_data;

  g_mutex_lock(&self->mutex);
  if (self->is_running) goto done;

  self->is_running = true;
  // Send a signal that thread has started.
  g_cond_signal(&self->cond);

  while (self->is_running) {
    if (self->input_buffer_idx > 0) {
      // Get the oldest hash from the input buffer
      // Copy the hash to |signature_info| and start signing.
      assert(self->input_buffer[0].size == self->signature_info->hash_size);
      assert(self->signature_info->hash);
      memcpy(self->signature_info->hash, self->input_buffer[0].hash, self->input_buffer[0].size);

      // Store the oldest hash temporarily by moving it from the first element of the buffer to the
      // end and move all other elements in the buffer forward.
      hash_data_t tmp = self->input_buffer[0];
      int j = 0;
      while (self->input_buffer[j + 1].hash != NULL && j < MAX_BUFFER_LENGTH - 1) {
        self->input_buffer[j] = self->input_buffer[j + 1];
        j++;
      }
      self->input_buffer[j] = tmp;
      self->input_buffer_idx--;

      // Let the signing operate outside a lock. Otherwise sv_interface_get_signature() is blocked,
      // since variables need to be read under a lock.
      g_mutex_unlock(&self->mutex);
      SignedVideoReturnCode status = openssl_sign_hash(self->signature_info);
      g_mutex_lock(&self->mutex);

      if (self->output_buffer_idx >= MAX_BUFFER_LENGTH) {
        // |output_buffer| is full. Buffers this long are not supported.
        self->is_running = false;
        reset_plugin(self);
        goto done;
      }

      // If not successfully done with signing, set |signing_error| to true to
      // report the error when getting the signature.
      self->output_buffer[self->output_buffer_idx].signing_error = (status != SV_OK);

      // Allocate memory for the |signature| if necessary.
      if (!self->output_buffer[self->output_buffer_idx].signature) {
        self->output_buffer[self->output_buffer_idx].signature =
            calloc(1, self->signature_info->max_signature_size);
        if (!self->output_buffer[self->output_buffer_idx].signature) {
          // Failed in memory allocation. Stop the thread and free all memory.
          self->is_running = false;
          reset_plugin(self);
          goto done;
        }
      }

      if (status == SV_OK) {
        // Copy the |signature| to the output buffer
        memcpy(self->output_buffer[self->output_buffer_idx].signature,
            self->signature_info->signature, self->signature_info->signature_size);
        self->output_buffer[self->output_buffer_idx].size = self->signature_info->signature_size;
      }
      self->output_buffer_idx++;
    } else {
      // Wait for a signal, triggered when it is time to sign a hash.
      g_cond_wait(&self->cond, &self->mutex);
    }
  };

done:

  g_mutex_unlock(&self->mutex);

  return NULL;
}

/* This function starts a local worker thread for signing.
 *
 * returns sv_threaded_plugin_t upon success, and NULL upon failure. */
static local_threaded_data_t *
local_setup()
{
  local_threaded_data_t *self = calloc(1, sizeof(local_threaded_data_t));

  if (!self) return NULL;

  // Initialize |self|.
  g_mutex_init(&(self->mutex));
  g_cond_init(&(self->cond));

  self->thread = g_thread_try_new("local-signing", local_worker_thread, (void *)self, NULL);

  if (!self->thread) goto catch_error;

  // Wait for the thread to start before returning.
  g_mutex_lock(&self->mutex);
  // TODO: Consider using g_cond_wait_until() instead, to avoid deadlock.
  while (!self->is_running) g_cond_wait(&self->cond, &self->mutex);

  g_mutex_unlock(&self->mutex);

  return self;

catch_error:
  free(self);
  return NULL;
}

static void
local_teardown(local_threaded_data_t *self)
{
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
  reset_plugin(self);
  free(self);
}

/**
 * Definitions of declared interfaces. For declarations see signed_video_interfaces.h.
 */

SignedVideoReturnCode
sv_interface_sign_hash(void *plugin_handle, signature_info_t *signature_info)
{
  sv_threaded_plugin_t *self = (sv_threaded_plugin_t *)plugin_handle;

  if (!self || !signature_info) return SV_INVALID_PARAMETER;

  if (self->local) {
    return sign_hash(self->local, 0, signature_info);
  } else if (self->central) {
    return sign_hash(&central, self->central->id, signature_info);
  } else {
    return SV_NOT_SUPPORTED;
  }
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

  if (self->local) {
    return get_signature(
        self->local, 0, signature, max_signature_size, written_signature_size, error);
  } else if (self->central) {
    return get_signature(
        &central, self->central->id, signature, max_signature_size, written_signature_size, error);
  } else {
    *error = SV_NOT_SUPPORTED;
    return false;
  }
}

void *
sv_interface_setup()
{
  sv_threaded_plugin_t *self = calloc(1, sizeof(sv_threaded_plugin_t));

  if (!self) return NULL;

  if (central.thread) {
    self->central = central_setup();
    if (!self->central) goto catch_error;
  } else {
    self->local = local_setup();
    if (!self->local) goto catch_error;
  }

  return (void *)self;

catch_error:
  free(self);
  return NULL;
}

void
sv_interface_teardown(void *plugin_handle)
{
  sv_threaded_plugin_t *self = (sv_threaded_plugin_t *)plugin_handle;

  if (self->local) {
    local_teardown(self->local);
    self->local = NULL;
  }
  if (self->central) {
    central_teardown(self->central);
    self->central = NULL;
  }
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
  if (central.thread) return 0;

  g_mutex_init(&(central.mutex));
  g_cond_init(&(central.cond));

  central.thread = g_thread_try_new("central-signing", central_worker_thread, NULL, NULL);
  if (!central.thread) return -1;

  // Wait for the thread to start before returning.
  g_mutex_lock(&(central.mutex));
  // TODO: Consider using g_cond_wait_until() instead, to avoid deadlock.
  while (!central.is_running) g_cond_wait(&(central.cond), &(central.mutex));

  g_mutex_unlock(&(central.mutex));
  return 0;
}

void
sv_interface_exit()
{
  g_mutex_lock(&(central.mutex));

  if (num_active_streams > 0) {
    g_warning("Terminating Signed Video signing thread when %d sessions are still active",
        num_active_streams);
    num_active_streams = 0;
  }

  if (!central.thread) {
    g_mutex_unlock(&(central.mutex));
    goto done;
  }

  GThread *tmp_thread = central.thread;

  central.is_running = false;
  central.thread = NULL;
  g_cond_signal(&(central.cond));
  g_mutex_unlock(&(central.mutex));

  g_thread_join(tmp_thread);

done:
  reset_plugin(&central);
}
