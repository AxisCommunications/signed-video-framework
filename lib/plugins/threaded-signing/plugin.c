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
 * The thread is stopped if |out| is full, if there was a failure in the memory allocation
 * for a new signature or if sv_interface_teardown() is called.
 *
 * If the plugin is initialized, sv_interface_init(), one single central thread is spawned. Each
 * Signed Video session will then get an id to distiguish between tehm since they use common input
 * and output buffers. The thread is stopped if |out| is full, if there was a failure in
 * the memory allocation for a new signature or if sv_interface_exit() is called.
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

/* A data handle maintaining the thread, lock and buffers. It stores the hashes to sign and the
 * written signatures in two separate buffers. This structure is used for both local and central
 * signing. */
typedef struct _threaded_data {
  GThread *thread;
  GMutex mutex;
  GCond cond;

  // Variables that have to be r/w under mutex lock.
  bool is_running;
  bool is_in_signing;
  // Buffer of hashes to sign
  hash_data_t in[MAX_BUFFER_LENGTH];
  int in_idx;
  // Buffer of written signatures
  signature_data_t out[MAX_BUFFER_LENGTH];
  int out_idx;
  // Variables that can operate without mutex lock.
  // A local copy of the signature_info is used for signing. The hash to be signed is copied to it
  // when it is time to sign.
  signature_info_t *signature_info;
} threaded_data_t;

/* A structure for keeping Signed Video session dependent data when signing is central. */
typedef struct _central_threaded_data {
  unsigned id;
} central_threaded_data_t;

/* Threaded plugin handle containing data for either a local signing or a central signing. */
typedef struct _sv_threaded_plugin {
  central_threaded_data_t *central;
  threaded_data_t *local;
} sv_threaded_plugin_t;

typedef struct _id_node id_node_t;
struct _id_node {
  unsigned id;
  id_node_t *prev;
  id_node_t *next;
};

// Static members for a central thread
threaded_data_t central = {0};
// Session related variables
static unsigned id_in_signing = 0;
static id_node_t *id_list = NULL;

/*
 * Helper functions common to both a local and a central thread.
 */

/* Frees the memory of |signature_info|. */
static void
signature_info_free(signature_info_t *signature_info)
{
  if (!signature_info) return;

  free(signature_info->private_key);
  if (signature_info->signature) openssl_free(signature_info->signature);
  free(signature_info->hash);
  free(signature_info);
}

/* Resets a hash_data_t element. */
static void
reset_hash_buffer(hash_data_t *buf)
{
  buf->id = 0;
}

/* Resets a signature_data_t element. */
static void
reset_signature_buffer(signature_data_t *buf)
{
  buf->size = 0;  // Note that the size of the allocated signature is handled by |signature_info|
  buf->id = 0;
  buf->signing_error = false;
}

/* Reset and free memory in a hash_data_t element. */
static void
free_hash_buffer(hash_data_t *buf)
{
  reset_hash_buffer(buf);
  free(buf->hash);
  buf->hash = NULL;
  buf->size = 0;
}

/* Reset and free memory in a signature_data_t element. */
static void
free_signature_buffer(signature_data_t *buf)
{
  reset_signature_buffer(buf);
  free(buf->signature);
  buf->signature = NULL;
}

/* Allocate memory and copy data from |signature_info|.
 *
 * This is only done once and the necessary |private_key| is copied. Memory
 * for the |signature| and, if known also the |hash|, is allocated. */
static signature_info_t *
signature_info_create(const signature_info_t *signature_info)
{
  signature_info_t *tmp_signature_info = calloc(1, sizeof(signature_info_t));
  if (!tmp_signature_info) goto catch_error;

  // Allocate memory and copy |private_key|.
  tmp_signature_info->private_key = malloc(signature_info->private_key_size);
  if (!tmp_signature_info->private_key) goto catch_error;
  memcpy(tmp_signature_info->private_key, signature_info->private_key,
      signature_info->private_key_size);
  tmp_signature_info->private_key_size = signature_info->private_key_size;

  if (signature_info->max_signature_size) {
    // Allocate memory for the |signature|.
    tmp_signature_info->signature = openssl_malloc(signature_info->max_signature_size);
    if (!tmp_signature_info->signature) goto catch_error;
    tmp_signature_info->max_signature_size = signature_info->max_signature_size;
  } else {
    if (openssl_signature_malloc(tmp_signature_info) != SV_OK) goto catch_error;
  }

  if (signature_info->hash_size) {
    // Allocate memory for the |hash|.
    tmp_signature_info->hash = calloc(1, signature_info->hash_size);
    if (!tmp_signature_info->hash) goto catch_error;
    tmp_signature_info->hash_size = signature_info->hash_size;
  }
  // Copy the |algo|.
  // tmp_signature_info->algo = signature_info->algo;

  return tmp_signature_info;

catch_error:
  signature_info_free(tmp_signature_info);
  return NULL;
}

/* Free all memory of input and ourput buffers. */
static void
free_buffers(threaded_data_t *self)
{
  for (int i = 0; i < MAX_BUFFER_LENGTH; i++) {
    free_signature_buffer(&self->out[i]);
    free_hash_buffer(&self->in[i]);
  }
  self->in_idx = 0;
  self->out_idx = 0;
}

/* Frees all allocated memory and resets members. Excluded are the worker thread members |thread|,
 * |mutex|, |cond| and |is_running|. */
static void
free_plugin(threaded_data_t *self)
{
  signature_info_free(self->signature_info);
  self->signature_info = NULL;

  free_buffers(self);
}

/* This function is, via sv_signing_plugin_sign(), called from the library upon signing.
 *
 * If this is the first time of signing, memory for |self->signature_info->hash| is allocated.
 * The |hash| is copied to |in|. If memory for the |in| hash has not been allocated it will be
 * allocated. */
static SignedVideoReturnCode
sign_hash(threaded_data_t *self, unsigned id, const uint8_t *hash, size_t hash_size)
{
  assert(self && hash);
  SignedVideoReturnCode status = SV_UNKNOWN_FAILURE;
  g_mutex_lock(&self->mutex);
  int idx = self->in_idx;

  if (idx >= MAX_BUFFER_LENGTH) {
    // |in| is full. Buffers this long are not supported.
    status = SV_NOT_SUPPORTED;
    goto done;
  }

  if (!self->is_running) {
    // Thread is not running. Go to catch_error and return status.
    status = SV_EXTERNAL_ERROR;
    goto done;
  }

  // Signing from a central thread. The |signature_info| should have been allocated when
  // the plugin was initialized.
  assert(self->signature_info);
  // Allocate memory for the hash slot in |signature_info| if this is the first time,
  // since it is now known to the signing plugin and cannot be changed.
  if (!self->signature_info->hash) {
    self->signature_info->hash = calloc(1, hash_size);
    if (!self->signature_info->hash) {
      // Failed in memory allocation.
      status = SV_MEMORY;
      goto done;
    }
    self->signature_info->hash_size = hash_size;
  }

  if (!self->in[idx].hash) {
    self->in[idx].hash = calloc(1, hash_size);
    if (!self->in[idx].hash) {
      // Failed in memory allocation.
      status = SV_MEMORY;
      goto done;
    }
    self->in[idx].size = hash_size;
  }

  // The |hash_size| has to be fixed throughout the session.
  if (self->in[idx].size != hash_size) {
    status = SV_NOT_SUPPORTED;
    goto done;
  }

  // Copy the |hash| ready for signing.
  memcpy(self->in[idx].hash, hash, hash_size);
  self->in[idx].id = id;
  self->in_idx++;

  status = SV_OK;

done:

  g_cond_signal(&self->cond);
  g_mutex_unlock(&self->mutex);

  return status;
}

/* If
 *   1. the |id| matches the oldest |out|, and
 *   2. the signature in |out| has been copied to |signature|
 * then returns true, otherwise false.
 * Moves the signatures in |out| forward when the copy is done. */
static bool
get_signature(threaded_data_t *self,
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
  if (self->out_idx == 0) goto done;

  // Return if next signature belongs to a different session.
  if (self->out[0].id != id) goto done;

  *written_signature_size = 0;
  if (self->out[0].signing_error) {
    // Propagate SV_EXTERNAL_ERROR when signing failed.
    status = SV_EXTERNAL_ERROR;
  } else if (self->out[0].size > max_signature_size) {
    // There is no room to copy the signature, set status to invalid parameter.
    status = SV_INVALID_PARAMETER;
  } else {
    // Copy the oldest signature
    memcpy(signature, self->out[0].signature, self->out[0].size);
    *written_signature_size = self->out[0].size;
    // Mark as copied.
    has_copied_signature = true;
  }
  // Move buffer
  signature_data_t tmp = self->out[0];
  reset_signature_buffer(&tmp);
  int i = 1;
  while (i < MAX_BUFFER_LENGTH) {
    self->out[i - 1] = self->out[i];
    i++;
  }
  self->out[MAX_BUFFER_LENGTH - 1] = tmp;
  self->out_idx--;

done:
  g_mutex_unlock(&self->mutex);

  if (error) *error = status;

  return has_copied_signature;
}

/*
 * Helper functions for a central thread.
 */

/* Goes through the list of active sessions and returns true if id exists. This function has to be
 * called under a lock. */
static bool
is_active(unsigned id)
{
  bool found_id = false;
  id_node_t *item = id_list;
  while (item && !found_id) {
    if (item->id == id) {
      found_id = true;
    }
    item = item->next;
  }
  return found_id;
}

/* Appends the |item| to the |id_list| of active sessions. This function has to be called under a
 * lock. */
static void
append_item(id_node_t *item)
{
  id_node_t *cur = id_list;
  while (cur->next) cur = cur->next;
  item->prev = cur;
  cur->next = item;
}

/* Delete the item of the |id_list| corresponding to the active session with |id|. This function has
 * to be called under a lock. */
static void
delete_item(unsigned id)
{
  id_node_t *item = id_list;
  while (item && (item->id != id)) item = item->next;
  if (item) {
    (item->prev)->next = item->next;
    if (item->next) (item->next)->prev = item->prev;
    free(item);
  }
}

/* Resets all elements of input and output buffers with correct |id|. */
static void
buffer_reset(unsigned id)
{
  int i = 0;
  while (i < MAX_BUFFER_LENGTH) {
    if (central.out[i].id == id) {
      // Found an element with correct id. Reset element and move to the back of buffer.
      signature_data_t tmp = central.out[i];
      reset_signature_buffer(&tmp);

      int j = i + 1;
      while (j < MAX_BUFFER_LENGTH) {
        central.out[j - 1] = central.out[j];
        j++;
      }
      central.out[j - 1] = tmp;
      if (i < central.out_idx) central.out_idx--;
    } else {
      i++;
    }
  }

  i = 0;
  while (i < MAX_BUFFER_LENGTH) {
    if (central.in[i].id == id) {
      // Found an element with correct id. Reset element and move to the back of buffer.
      hash_data_t tmp = central.in[i];
      reset_hash_buffer(&tmp);

      int j = i + 1;
      while (j < MAX_BUFFER_LENGTH) {
        central.in[j - 1] = central.in[j];
        j++;
      }
      central.in[j - 1] = tmp;
      if (i < central.in_idx) central.in_idx--;
    } else {
      i++;
    }
  }
}

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
    if (central.in_idx > 0) {
      SignedVideoReturnCode status = SV_UNKNOWN_FAILURE;
      // Get the oldest hash from the input buffer
      // Copy the hash to |signature_info| and start signing.
      assert(central.in[0].size == central.signature_info->hash_size);
      assert(central.signature_info->hash);
      memcpy(central.signature_info->hash, central.in[0].hash, central.in[0].size);
      id_in_signing = central.in[0].id;

      // Move the oldest input buffer to end of queue for reuse at a later stage.
      hash_data_t tmp = central.in[0];
      reset_hash_buffer(&tmp);
      int j = 1;
      while (j < MAX_BUFFER_LENGTH) {
        central.in[j - 1] = central.in[j];
        j++;
      }
      central.in[MAX_BUFFER_LENGTH - 1] = tmp;
      central.in_idx--;

      // Let the signing operate outside a lock. Otherwise sv_signing_plugin_get_signature() is
      // blocked, since variables need to be read under a lock.
      central.is_in_signing = true;
      g_mutex_unlock(&(central.mutex));
      status = openssl_sign_hash(central.signature_info);
      g_mutex_lock(&(central.mutex));
      central.is_in_signing = false;

      int idx = central.out_idx;
      if (idx >= MAX_BUFFER_LENGTH) {
        // |out| is full. Buffers this long are not supported.
        // There are no means to signal an error to the signing session. Flush all buffers for this
        // id and move on.
        status = SV_NOT_SUPPORTED;
        buffer_reset(id_in_signing);
        continue;
      }

      // If not successfully done with signing, set |signing_error| to true to
      // report the error when getting the signature.
      central.out[idx].signing_error = (status != SV_OK);
      central.out[idx].id = id_in_signing;

      // Allocate memory for the |signature| if necessary.
      if (!central.out[idx].signature) {
        central.out[idx].signature = calloc(1, central.signature_info->max_signature_size);
        if (!central.out[idx].signature) {
          // Failed in memory allocation. Stop the thread and free all memory.
          status = SV_MEMORY;
          central.is_running = false;
          free_buffers(&central);
          continue;
        }
      }

      if (status == SV_OK) {
        // Copy the |signature| to the output buffer
        memcpy(central.out[idx].signature, central.signature_info->signature,
            central.signature_info->signature_size);
        central.out[idx].size = central.signature_info->signature_size;
      }
      central.out_idx++;
    } else {
      // Wait for a signal, triggered when it is time to sign a hash.
      g_cond_wait(&(central.cond), &(central.mutex));
    }
  }

done:
  // Send a signal that thread has stopped.
  g_cond_signal(&(central.cond));
  g_mutex_unlock(&(central.mutex));

  return NULL;
}

/* This function creates an id for the session to identify hashes and signatures.
 *
 * returns central_threaded_data_t upon success, and NULL upon failure. */
static central_threaded_data_t *
central_setup()
{
  central_threaded_data_t *self = calloc(1, sizeof(central_threaded_data_t));

  if (!self) return NULL;

  g_mutex_lock(&(central.mutex));

  // Make sure that the thread is running.
  if (!central.is_running) goto catch_error;

  // Find first available id and add to list of active sessions.
  unsigned id = 1;
  while (is_active(id) && id != 0) id++;
  if (id == 0) goto catch_error;

  id_node_t *item = (id_node_t *)calloc(1, sizeof(id_node_t));
  if (!item) goto catch_error;

  item->id = id;
  append_item(item);
  self->id = id;

  g_mutex_unlock(&(central.mutex));

  return self;

catch_error:
  g_mutex_unlock(&(central.mutex));
  free(self);
  return NULL;
}

static void
central_teardown(central_threaded_data_t *self)
{
  g_mutex_lock(&(central.mutex));
  buffer_reset(self->id);
  delete_item(self->id);
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
  threaded_data_t *self = (threaded_data_t *)user_data;

  g_mutex_lock(&self->mutex);
  if (self->is_running) goto done;

  self->is_running = true;
  // Send a signal that thread has started.
  g_cond_signal(&self->cond);

  while (self->is_running) {
    if (self->in_idx > 0) {
      // Get the oldest hash from the input buffer
      // Copy the hash to |signature_info| and start signing.
      assert(self->in[0].size == self->signature_info->hash_size);
      assert(self->signature_info->hash);
      memcpy(self->signature_info->hash, self->in[0].hash, self->in[0].size);

      // Move the oldest input buffer to end of queue for reuse at a later stage.
      hash_data_t tmp = self->in[0];
      int j = 0;
      while (self->in[j + 1].hash != NULL && j < MAX_BUFFER_LENGTH - 1) {
        self->in[j] = self->in[j + 1];
        j++;
      }
      self->in[j] = tmp;
      self->in_idx--;

      // Let the signing operate outside a lock. Otherwise sv_signing_plugin_get_signature() is
      // blocked, since variables need to be read under a lock.
      self->is_in_signing = true;
      g_mutex_unlock(&self->mutex);
      SignedVideoReturnCode status = openssl_sign_hash(self->signature_info);
      g_mutex_lock(&self->mutex);
      self->is_in_signing = false;

      int idx = self->out_idx;
      if (idx >= MAX_BUFFER_LENGTH) {
        // |out| is full. Buffers this long are not supported.
        self->is_running = false;
        free_plugin(self);
        goto done;
      }

      // If not successfully done with signing, set |signing_error| to true to
      // report the error when getting the signature.
      self->out[idx].signing_error = (status != SV_OK);

      // Allocate memory for the |signature| if necessary.
      if (!self->out[idx].signature) {
        self->out[idx].signature = calloc(1, self->signature_info->max_signature_size);
        if (!self->out[idx].signature) {
          // Failed in memory allocation. Stop the thread and free all memory.
          self->is_running = false;
          free_plugin(self);
          goto done;
        }
      }

      if (status == SV_OK) {
        // Copy the |signature| to the output buffer
        memcpy(self->out[idx].signature, self->signature_info->signature,
            self->signature_info->signature_size);
        self->out[idx].size = self->signature_info->signature_size;
      }
      self->out_idx++;
    } else {
      // Wait for a signal, triggered when it is time to sign a hash.
      g_cond_wait(&self->cond, &self->mutex);
    }
  }

done:
  // Send a signal that thread has stopped.
  g_cond_signal(&self->cond);
  g_mutex_unlock(&self->mutex);

  return NULL;
}

/* This function starts a local worker thread for signing.
 *
 * returns threaded_data_t upon success, and NULL upon failure. */
static threaded_data_t *
local_setup(const void *private_key, size_t private_key_size)
{
  threaded_data_t *self = calloc(1, sizeof(threaded_data_t));

  if (!self) return NULL;

  // Setup |signature_info| with |private_key| if there is one
  if (private_key && private_key_size > 0 && !self->signature_info) {
    self->signature_info = calloc(1, sizeof(signature_info_t));
    if (!self->signature_info) goto catch_error;
    // Allocate memory and copy |private_key|.
    self->signature_info->private_key = malloc(private_key_size);
    if (!self->signature_info->private_key) goto catch_error;
    memcpy(self->signature_info->private_key, private_key, private_key_size);
    self->signature_info->private_key_size = private_key_size;

    if (openssl_signature_malloc(self->signature_info) != SV_OK) goto catch_error;
  }

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
  free_plugin(self);
  return NULL;
}

static void
local_teardown_locked(threaded_data_t *self)
{
  if (!self->thread) {
    g_mutex_unlock(&self->mutex);
    goto done;
  }

  GThread *thread = self->thread;

  self->is_running = false;
  self->thread = NULL;

  // Wait (at most 2 seconds) for an ongoing signing to complete
  int64_t end_time = g_get_monotonic_time() + 2 * G_TIME_SPAN_SECOND;
  while (self->is_in_signing) {
    if (!g_cond_wait_until(&self->cond, &self->mutex, end_time)) {
      // timeout has passed.
      break;
    }
  }
  g_cond_signal(&self->cond);
  g_mutex_unlock(&self->mutex);

  g_thread_join(thread);

done:
  free_plugin(self);
}

/**
 * Definitions of declared interfaces. For declarations see signed_video_interfaces.h.
 */

SignedVideoReturnCode
sv_signing_plugin_sign(void *handle, const uint8_t *hash, size_t hash_size)
{
  sv_threaded_plugin_t *self = (sv_threaded_plugin_t *)handle;

  if (!self || !hash || hash_size == 0) return SV_INVALID_PARAMETER;

  if (self->local) {
    return sign_hash(self->local, 0, hash, hash_size);
  } else if (self->central) {
    return sign_hash(&central, self->central->id, hash, hash_size);
  } else {
    return SV_NOT_SUPPORTED;
  }
}

/* TO BE DEPRECATED */
SignedVideoReturnCode
sv_interface_sign_hash(void *plugin_handle, signature_info_t *signature_info)
{
  sv_threaded_plugin_t *self = (sv_threaded_plugin_t *)plugin_handle;

  if (!self || !signature_info) return SV_INVALID_PARAMETER;

  if (self->local) {
    // If this is the first signing call, copy |private_key| etc. from the input.
    if (!self->local->signature_info) {
      self->local->signature_info = signature_info_create(signature_info);
    }
    return sign_hash(self->local, 0, signature_info->hash, signature_info->hash_size);
  } else if (self->central) {
    return sign_hash(&central, self->central->id, signature_info->hash, signature_info->hash_size);
  } else {
    return SV_NOT_SUPPORTED;
  }
}

bool
sv_signing_plugin_get_signature(void *handle,
    uint8_t *signature,
    size_t max_signature_size,
    size_t *written_signature_size,
    SignedVideoReturnCode *error)
{
  sv_threaded_plugin_t *self = (sv_threaded_plugin_t *)handle;

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
  sv_threaded_plugin_t *self = calloc(1, sizeof(sv_threaded_plugin_t));

  if (!self) return NULL;

  if (central.thread) {
    assert(id_list);
    self->central = central_setup();
    if (!self->central) goto catch_error;
  } else {
    // Setting a |private_key| is only necessary if setup to use separate threads for each session.
    if (!private_key || private_key_size == 0) goto catch_error;

    self->local = local_setup(private_key, private_key_size);
    if (!self->local) goto catch_error;
  }

  return (void *)self;

catch_error:
  free(self);
  return NULL;
}

/* TO BE DEPRECATED */
void *
sv_interface_setup()
{
  return sv_signing_plugin_session_setup(NULL, 0);
}

void
sv_signing_plugin_session_teardown(void *handle)
{
  sv_threaded_plugin_t *self = (sv_threaded_plugin_t *)handle;
  if (!self) return;

  if (self->local) {
    g_mutex_lock(&(self->local)->mutex);
    local_teardown_locked(self->local);
    free(self->local);
    self->local = NULL;
  }
  if (self->central) {
    central_teardown(self->central);
    self->central = NULL;
  }
  free(self);
}

/* TO BE DEPRECATED */
void
sv_interface_teardown(void *plugin_handle)
{
  sv_signing_plugin_session_teardown(plugin_handle);
}

/* TO BE DEPRECATED */
uint8_t *
sv_interface_malloc(size_t data_size)
{
  return openssl_malloc(data_size);
}

/* TO BE DEPRECATED */
void
sv_interface_free(uint8_t *data)
{
  openssl_free(data);
}

/* This plugin initializer expects the |user_data| to be a signature_info_t struct. Only the
 * |private_key| in it is copied to the static |signature_info|. The |private_key| will be
 * used throught all added sessions.
 *
 * A central thread is set up and a list, containing the IDs of the active sessions, is initialized
 * with an empty list head.
 */
int
sv_signing_plugin_init(void *user_data)
{
  signature_info_t *signature_info = (signature_info_t *)user_data;

  if (central.thread || id_list || central.signature_info) {
    // Central thread, id list or signature_info already exists
    return -1;
  }

  id_list = (id_node_t *)calloc(1, sizeof(id_node_t));
  if (!id_list) goto catch_error;

  central.signature_info = signature_info_create(signature_info);
  if (!central.signature_info) goto catch_error;

  g_mutex_init(&(central.mutex));
  g_cond_init(&(central.cond));

  central.thread = g_thread_try_new("central-signing", central_worker_thread, NULL, NULL);
  if (!central.thread) goto catch_error;

  // Wait for the thread to start before returning.
  g_mutex_lock(&(central.mutex));
  // TODO: Consider using g_cond_wait_until() instead, to avoid deadlock.
  while (!central.is_running) g_cond_wait(&(central.cond), &(central.mutex));

  g_mutex_unlock(&(central.mutex));
  return 0;

catch_error:
  signature_info_free(central.signature_info);
  central.signature_info = NULL;
  free(id_list);
  id_list = NULL;
  return -1;
}

/* This function closes down the plugin. No |user_data| is expected and aborts the action if
 * present.
 *
 * The thread is terminated and all allocated memory is freed.
 */
void
sv_signing_plugin_exit(void *user_data)
{
  // User is not expected to pass in any data. Aborting.
  if (user_data) return;

  g_mutex_lock(&(central.mutex));

  if (id_list) {
    id_node_t *item = id_list;
    while (item) {
      id_node_t *next_item = item->next;
      free(item);
      item = next_item;
    }
    id_list = NULL;
  }

  local_teardown_locked(&central);
}
