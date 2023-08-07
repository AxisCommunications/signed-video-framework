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

#ifndef __SIGNED_VIDEO_SIGN_H__
#define __SIGNED_VIDEO_SIGN_H__

#include <stdint.h>  // uint8_t
#include <string.h>  // size_t

#include "signed_video_common.h"  // signed_video_t, SignedVideoReturnCode
#include "signed_video_interfaces.h"  // sign_algo_t

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Instruction on where to prepend a generated NALU.
 *
 * If an action is to prepend a NALU (SIGNED_VIDEO_PREPEND_NALU) the generated NALU should prepend
 * the input NALU + all already prepended NALUs.
 * If an action is to prepend an access unit (SIGNED_VIDEO_PREPEND_ACCESS_UNIT) the generated NALU
 * should be added to an extra access unit (AU) preceding the current one. If an extra AU has
 * already been created, this generated NALU should prepend all already added NALUs in that extra
 * AU.
 *
 * For example, assume one AU with one NALU F0, that is, the memory looks like
 *
 * | AUD | F0 |
 *
 * Further, assume four NALUs are pulled in order; F1, F2, F3 and F4. The corresponding
 * instructions are; SIGNED_VIDEO_PREPEND_NALU, SIGNED_VIDEO_PREPEND_NALU,
 * SIGNED_VIDEO_PREPEND_ACCESS_UNIT and SIGNED_VIDEO_PREPEND_ACCESS_UNIT. Then the memory afterwards
 * should look like this
 *
 * | AUD | F4 | F3 | AUD | F2 | F1 | F0 |
 * /---------------/
 *       new AU
 */
typedef enum {
  SIGNED_VIDEO_PREPEND_NOTHING,
  // Nothing more to prepend.
  SIGNED_VIDEO_PREPEND_ACCESS_UNIT,
  // Prepend the NALUs in a preceding access unit.
  SIGNED_VIDEO_PREPEND_NALU,
  // Prepend the NALUs in the same access unit as the input H26x NALU.
} SignedVideoPrependInstruction;

/**
 * A struct composed of the data of a, by Signed Video, generated NALU and instructions on how to
 * add it to the stream.
 */
typedef struct {
  SignedVideoPrependInstruction prepend_instruction;
  // Instructions on where to prepend the NALU.
  uint8_t *nalu_data;
  // Data of generated NALU.
  size_t nalu_data_size;
  // Size of generated |nalu_data|.
} signed_video_nalu_to_prepend_t;

/**
 * The authenticity level sets the granularity of the authenticity.
 */
typedef enum {
  SV_AUTHENTICITY_LEVEL_GOP = 0,
  // The entire GOP is verified as one solid chunk. Hence, if validation fails it is unknown which
  // NALUs were incorrect or missing.
  SV_AUTHENTICITY_LEVEL_FRAME = 1,
  // Individual NALUs are verified. Hence, if validation fails the incorrect or missing NALU(s) are
  // detected.
  SV_AUTHENTICITY_LEVEL_NUM
} SignedVideoAuthenticityLevel;

/**
 * @brief Updates Signed Video, with a H26x NALU, for signing
 *
 * Each NALU in a video has to be processed for signing. Sometimes the NALU data is split in parts
 * and cannot be hashed in one go. This API adds a NALU part to the signed_video_t object for
 * signing. It is very important that the video NALUs are fed to this API in the same order as they
 * are transmitted. Otherwise, the authentication will fail.
 *
 * Signed Video adds SEI-NALUs of type "user data unregistered" to communicate data for
 * authentication. These SEI-NALUs are generated by the Signed Video library and are complete NALUs
 * + 4 start code bytes. The user is responsible for pulling these generated NALUs from the object.
 * Hence, upon a successful signed_video_add_nalu_for_signing_with_timestamp(...) call the user
 * should always call signed_video_get_nalu_to_prepend(...) to get the additional NALUs.
 *
 * The timestamp parameter shall be a UNIX epoch value in UTC format. The integrator of this signed
 * video framework shall make sure this is true, so that the client side knows the expected format
 * and is able to convert the timestamp to whatever format is desired. If the timestamp is not NULL
 * and the NALU is the first in the gop (i.e. the first I-frame slice), it will be included in the
 * general SEI. All other timestamps and NULL will be disregarded.
 *
 * For sample code, see the description of signed_video_get_nalu_to_prepend(...) below.
 *
 * @param self Pointer to the signed_video_t object in use.
 * @param nalu_data A pointer to the NALU data
 * @param nalu_data_size The size of the NALU data.
 * @param timestamp Unix epoch in UTC.
 * @param is_last_part Flag to mark the last part of the NALU data.
 *
 * @returns SV_OK            - the NALU was processed successfully.
 *          SV_NOT_SUPPORTED - signed_video_set_private_key(...) has not been set
 *                             OR
 *                             there are generated NALUs waiting to be pulled. Use
 *                             signed_video_get_nalu_to_prepend(...) to fetch them. Then call this
 *                             function again to process the |nalu_data|.
 *          otherwise a different error code.
 */
SignedVideoReturnCode
signed_video_add_nalu_part_for_signing_with_timestamp(signed_video_t *self,
    const uint8_t *nalu_data,
    size_t nalu_data_size,
    const int64_t *timestamp,
    bool is_last_part);

/**
 * This API is identical to signed_video_add_nalu_part_for_signing_with_timestamp() where every call
 * has |is_last_part| = true, that is, every part is a complete NALU.
 */
SignedVideoReturnCode
signed_video_add_nalu_for_signing_with_timestamp(signed_video_t *self,
    const uint8_t *nalu_data,
    size_t nalu_data_size,
    const int64_t *timestamp);

/**
 * To be depricated.
 *
 * This API is identical to signed_video_add_nalu_for_signing_with_timestamp using NULL as
 * timestamp.
 */
SignedVideoReturnCode
signed_video_add_nalu_for_signing(signed_video_t *self,
    const uint8_t *nalu_data,
    size_t nalu_data_size);

/**
 * @brief Gets generated NALUs to prepend the latest added NALU
 *
 * This function should always be called after a successful
 * signed_video_add_nalu_for_signing_with_timestamp(...). Otherwise, the functionality of Signed
 * Video is jeopardized, since vital SEI-NALUs may not be added to the video stream. The
 * signed_video_add_nalu_for_signing_with_timestamp(...) returns SV_NOT_SUPPORTED if there are
 * available NALUs to prepend. The user should then pull these before continuing; See return values
 * in signed_video_add_nalu_for_signing_with_timestamp(...).
 *
 * These SEI-NALUs are generated by the Signed Video library and are complete NALUs + 4 start code
 * bytes. Hence, the user can simply pull and prepend existing H26x NALUs. Pull NALUs to prepend
 * from signed_video_t one by one until no further action is required. When this happens, a
 * SIGNED_VIDEO_PREPEND_NOTHING instruction is pulled. The signed_video_get_nalu_to_prepend(...)
 * API provides the user with the NALU data as well as instructions on where to prepend that data.
 *
 * NOTE that as soon as the user pulls a new NALU to prepend, the ownership of the |nalu_data|
 * memory (see members of signed_video_nalu_to_prepend_t) is transferred. Free the |nalu_data|
 * memory with signed_video_nalu_data_free(...).
 *
 * Here is an example code of usage:
 *
 *   signed_video_t *sv = signed_video_create(SV_CODEC_H264);
 *   if (!sv) {
 *     // Handle error
 *   }
 *   if (signed_video_set_private_key(sv, SIGN_ALGO_ECDSA, private_key, private_key_size)
 *       != SV_OK) {
 *     // Handle error
 *   }
 *   SignedVideoReturnCode status;
 *   status = signed_video_add_nalu_for_signing_with_timestamp(sv, nalu, nalu_size, NULL);
 *   if (status != SV_OK) {
 *     // Handle error
 *   } else {
 *     signed_video_nalu_to_prepend_t nalu_to_prepend;
 *     status = signed_video_get_nalu_to_prepend(sv, &nalu_to_prepend);
 *     while (status == SV_OK &&
 *         nalu_to_prepend.prepend_instruction != SIGNED_VIDEO_PREPEND_NOTHING) {
 *       switch (nalu_to_prepend.prepend_instruction) {
 *       case (SIGNED_VIDEO_PREPEND_ACCESS_UNIT):
 *         // Add an extra access unit (AU) before current AU, or prepend the
 *         // NALUs if an extra AU has already been created.
 *         break;
 *       case (SIGNED_VIDEO_PREPEND_NALU):
 *         // Prepend the NALUs in the current AU.
 *         break;
 *       default:
 *         break;
 *       }
 *       // Maybe free the |nalu_data| before pulling a new |nalu_to_prepend|.
 *       // signed_video_nalu_data_free(nalu_to_prepend.nalu_data);
 *       status = signed_video_get_nalu_to_prepend(sv, &nalu_to_prepend);
 *     }
 *     // Handle return code
 *     if (status != SV_OK) {
 *       // True error. Handle it properly.
 *     }
 *   }
 *
 * @param self Pointer to the signed_video_t object in use.
 * @param nalu_to_prepend A pointer to a signed_video_nalu_to_prepend_t object holding NALU data
 *   and prepend instructions.
 *
 * @returns SV_OK            - NALU was pulled successfully,
 *          SV_NOT_SUPPORTED - no available data, the action is not supported,
 *          otherwise        - an error code.
 */
SignedVideoReturnCode
signed_video_get_nalu_to_prepend(signed_video_t *self,
    signed_video_nalu_to_prepend_t *nalu_to_prepend);

/**
 * @brief Frees the |nalu_data| of signed_video_nalu_to_prepend_t
 *
 * The user takes ownership of the |nalu_data| memory after pulling a
 * signed_video_nalu_to_prepend_t. Use this function to free that memory.
 *
 * @param nalu_data Pointer to the nalu_data of a signed_video_nalu_to_prepend_t object.
 */
void
signed_video_nalu_data_free(uint8_t *nalu_data);

/**
 * @brief Tells Signed Video that the stream has ended
 *
 * When reaching the end of a stream (EOS) a final SEI-NALU needs to be transmitted to be able to
 * validate all the way to the end, thereby avoiding a dangling end.
 *
 * This API can be called when the end of a stream is reached. Afterwards, all NALUs to prepend
 * should be pulled as normal using signed_video_get_nalu_to_prepend(...) above.
 *
 * @param self Pointer to the signed_video_t object in use.
 *
 * @returns SV_OK            - EOS was successfully set,
 *          otherwise        - an error code.
 */
SignedVideoReturnCode
signed_video_set_end_of_stream(signed_video_t *self);

/**
 * @brief Sets the product information for the signed video session
 *
 * This API will set the hardware id, firmware version and serial number in the signed_video_t
 * struct for the session. Although this should only have to be set once, this can be called
 * multiple times during the signing, but it must be done in between adding NALUs synchronously.
 * NOTE: This API assumes null-terminated input strings.
 * NOTE: The length of a string has to be less than 255 characters, otherwise the string will be
 * truncated.
 *
 * @param self Signed Video session pointer
 * @param hardware_id Null-terminated string
 * @param firmware_version Null-terminated string
 * @param serial_number Null-terminated string
 * @param manufacturer Null-terminated string
 * @param address Null-terminated string
 *
 * @returns SV_OK            - Product info was successfully set,
 *          otherwise        - an error code.
 */
SignedVideoReturnCode
signed_video_set_product_info(signed_video_t *self,
    const char *hardware_id,
    const char *firmware_version,
    const char *serial_number,
    const char *manufacturer,
    const char *address);

/**
 * @brief Sets the content of the private key.
 *
 * NOTE: This call has to be called before the video session can begin.
 *
 * Signed Video requires a PEM file format of private (and public) keys. The user is responsible for
 * key handling. The content of the private key (in PEM format) is passed to Signed Video through
 * this API. For Linux there is an OpenSSL based helper function to generate a private key in a
 * given location; See signed_video_openssl.h.
 *
 * Associated with the private key is a signing algorithm, for example RSA or ECDSA. This type
 * needs to be set to know if some additional actions need to be taken when signing or validating.
 * The algorithm will be transmitted in the SEI nalu and picked up by the client side which will
 * then be able to take necessary actions on their side before verifying the signature.
 *
 * @param self Pointer to the signed_video_t object session.
 * @param algo Enum type of sign_algo_t specifying the algorithm use to generate the
 *   private key.
 * @param private_key The content of the private key pem file.
 * @param private_key_size The size of the |private_key|.
 *
 * @return SV_OK If the |algo| is supported and set,
 *         SV_INVALID_PARAMETER Invalid input parameter(s),
 *         SV_NOT_SUPPORTED If the algo is not supported,
 *         SV_MEMORY If failed allocating memory for the private key,
 *         SV_EXTERNAL_ERROR The public key could not be extracted.
 */
SignedVideoReturnCode
signed_video_set_private_key(signed_video_t *self,
    sign_algo_t algo,
    const char *private_key,
    size_t private_key_size);

/**
 * @brief Setter for adding the Public key to the SEI or not
 *
 * If the public key, used to verify the signatures, cannot be secured through a hardware
 * certificate or key attestation, it should not be added to the video stream. Without securing it,
 * anyone can sign arbitrary (tampered) videos.
 *
 * This function should be used before starting the Signed Video session. If it is not used, the
 * public key is added to the SEI.
 *
 * @param self Pointer to the current Signed Video session
 * @param add_public_key_to_sei Flag to indicate if the public key should be added to the SEI
 *   (default true)
 *
 * @return A Signed Video Return Code (SignedVideoReturnCode)
 */
SignedVideoReturnCode
signed_video_add_public_key_to_sei(signed_video_t *self, bool add_public_key_to_sei);

/**
 * @brief Sets the authenticity level to be used.
 *
 * The framework supports two levels of authenticity; GOP and Frame, where Frame is default. At GOP
 * level a verification is made for the entire GOP in one chunk, whereas at Frame level frame drops
 * can be handled.
 *
 * The signing part decides on the level and the receiving end will automatically produce an
 * appropriate report.
 *
 * NOTE: that authenticity at Frame level will have a significantly higher bitrate than at GOP
 * level.
 *
 * @param self Pointer to the signed_video_t object session.
 * @param authenticity_level The authenticity level used.
 *
 * @return SV_OK If the authenticity_level is supported and set,
 *         SV_INVALID_PARAMETER Invalid parameter,
 *         SV_NOT_SUPPORTED If the authenticity_level is not supported.
 */
SignedVideoReturnCode
signed_video_set_authenticity_level(signed_video_t *self,
    SignedVideoAuthenticityLevel authenticity_level);

/**
 * @brief Sets the average recurrence interval for the signed video session in frames
 *
 * Metadata that is only needed once when validating the authenticity can be transmitted with a
 * different recurrence interval than the signatures. This API sets that recurrence, counted in
 * frames (not NALUs). Note that this type of metadata is still bundled together in the same SEI
 * as the signature, hence the true recurrence will be correct on the average.

 * Example of metadata that is only needed once are the public key and product info.
 *
 * @param self Session struct pointer
 * @param recurrence Recurrence interval in frames
 *
 * @returns SV_OK Recurrence interval was successfully set,
 *          SV_INVALID_PARAMETER Invalid parameter,
 *          SV_NOT_SUPPORTED Recurrence interval is not supported.
 */
SignedVideoReturnCode
signed_video_set_recurrence_interval_frames(signed_video_t *self, unsigned recurrence);

/**
 * @brief Configures Signed Video to generate the SEI NAL Units with/without emulation prevention
 *
 * Emulation prevention bytes (EPB) are used to prevent the decoder from detecting the start code
 * sequence in the middle of a NAL Unit. By default, the framework generates SEI frames with EPB
 * written to the payload. With this API, the user can select to have Signed Video generate SEI
 * frames with or without EPBs.

 * If this API is not used, SEI payload is written with EPBs, hence equivalent with setting
 * |sei_epb| to True.
 *
 * @param self Session struct pointer
 * @param sei_epb SEI payload written with EPB (default True)
 *
 * @returns SV_OK SEI w/o EPB was successfully set,
 *          SV_INVALID_PARAMETER Invalid parameter.
 */
SignedVideoReturnCode
signed_video_set_sei_epb(signed_video_t *self, bool sei_epb);

/**
 * @brief Configures Signed Video to limit the payload size of the SEI NAL Units
 *
 * In many Signed Video integrations on the signing side SEIs cannot become arbitrary large due to
 * hardware constraints. This API sets an upper limit on the payload size of the generated SEI. If
 * the, to be generated, SEI exceeds the set |max_sei_payload_size| Signed Video falls back to GOP
 * level authentication.
 *
 * Note that it is a soft limit. If the payload size is still too large even for GOP level
 * authentication the SEI NAL Unit is generated. Further, note that the API sets the maximum SEI
 * payload size. The final SEI size can become larger since it includes headers, size bytes and
 * potentional emulation prevention.
 *
 * If this API is not used, an unlimited SEI payload size is used (|max_sei_payload_size| = 0).
 *
 * The behavior of this API may change in the future and replace the fallback mechanism with a
 * forced signing mechanism.
 *
 * @param self Session struct pointer
 * @param max_sei_payload_size Upper limit on SEI payload (default 0 = unlimited)
 *
 * @returns SV_OK Max SEI payload size was successfully set,
 *          SV_INVALID_PARAMETER Invalid parameter.
 */
SignedVideoReturnCode
signed_video_set_max_sei_payload_size(signed_video_t *self, size_t max_sei_payload_size);

#ifdef __cplusplus
}
#endif

#endif  // __SIGNED_VIDEO_SIGN_H__
