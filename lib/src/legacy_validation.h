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

#ifndef __LEGACY_VALIDATION_H__
#define __LEGACY_VALIDATION_H__

#include <stdint.h>  // uint8_t
#include <stdlib.h>  // size_t

#include "includes/signed_video_auth.h"  // signed_video_authenticity_t
#include "includes/signed_video_common.h"  // signed_video_t
#include "sv_defines.h"  // svrc_t

typedef struct _legacy_sv_t legacy_sv_t;

/**
 * @brief Creates a legacy signed video session.
 *
 * Creates a legacy_sv_t object which the user should keep across the entire streaming
 * session. The returned struct can be used for validating the authenticity of a legacy
 * video.
 *
 * @param parent The parent session, i.e., a signed_video_t object.
 *
 * @return A pointer to legacy_sv_t struct, allocated and initialized. A null pointer is
 *         returned if memory could not be allocated.
 */
legacy_sv_t *
legacy_sv_create(signed_video_t *parent);

/**
 * @brief Frees the memory of the legacy_sv_t object.
 *
 * All memory allocated to and by the legacy_sv_t object will be freed. This will
 * affectivly end the signed video session.
 *
 * @param self Pointer to the object which memory to free.
 */
void
legacy_sv_free(legacy_sv_t *self);

/**
 * @brief Resets the legacy session to allow for, e.g., scrubbing signed video
 *
 * Resets the session and puts it in a pre-stream state, that is, waiting for a new GOP.
 * Once a new GOP is found the operations start over.
 *
 * For the signing part, this means starting to produce the required SEIs needed for
 * authentication. For the authentication part, this should be used when scrubbing the
 * video. Otherwise the lib will fail authentication due to skipped Bitstream Units.
 *
 * @param self Signed Video session in use
 *
 * @return A svrc_t
 */
svrc_t
legacy_sv_reset(legacy_sv_t *self);

/**
 * @brief Add Bitstream Unit data to the session and get an authentication report
 *
 * This function should be called for each Bitstream Unit the user receives. It is assumed
 * that |nalu_data| consists of one single Bitstream Unit including Start Code and
 * Bitstream Unit, so that Bitstream Unit type can be parsed. That is, the format should
 * look like this:
 *
 * |------------|------|
 * | Start Code | NALU |
 * |------------|------|
 *  3 or 4 bytes       ^
 *                     Including stop bit
 *
 * @note: Bitstream Units sent into the API cannot be in packetized format (access units)!
 * The access unit has to be split into Bitstream Units if so.
 *
 * The input |nalu_data| is not changed by this call. Note that it is assumed that ALL
 * Bitstream Units are passed to this function. Otherwise, they will be treated as
 * missing/lost packets which may affect the validation.
 *
 * Signatures are sent on regular basis. Currently this is done at the end of each GOP
 * (Group Of Pictures). For every input |nalu_data| with a signature, or when a signature
 * is expected, validation is performed and a copy of the |authenticity| result is
 * provided. If a Bitstream Unit does not trigger a validation, |authenticity| is a NULL
 * pointer. If one NALU is lost or tampered with within a GOP, the whole GOP is marked as
 * NOT OK, even if the other NALUs are correct.
 *
 * The user should continuously check the return value for errors and upon success check
 * |authenticity| for a new report.
 * Two typical use cases are; 1) live monitoring which could be screening the video until
 * authenticity can no longer be validated OK, and 2) screening a recording and get a full
 * report at the end. In the first case further operations can simply be aborted as soon
 * as a validation fails, whereas in the latter case all the NALUs need to be screened.
 * @note: Only the live monitoring use case is currently supported.
 *
 * Example code of usage; See example code above.
 *
 * @param self Pointer to the legacy_sv_t object to update
 * @param nalu_data Pointer to the Bitstream Unit data to be added
 * @param nalu_data_size Size of the nalu_data
 * @param authenticity Pointer to the autenticity report. Passing in a NULL pointer will
 *     not provide latest validation results. The user is then responsible to get a report
 *     using signed_video_get_authenticity_report(...).
 *
 * @return A svrc_t
 */
svrc_t
legacy_sv_add_and_authenticate(legacy_sv_t *self,
    const uint8_t *nalu_data,
    size_t nalu_data_size,
    signed_video_authenticity_t **authenticity);

/**
 * @brief Gets the size of the Bitstream Unit list
 *
 * This function is necessary to update the authenticity report from the parent Signed
 * Video session.
 *
 * @param self Pointer to the legacy_sv_t object
 *
 * @return Number of Bitstream Units (items) in the nalu_list
 */
int
legacy_get_nalu_list_items(legacy_sv_t *self);

#endif  // __LEGACY_VALIDATION_H__
