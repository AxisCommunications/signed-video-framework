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

#include <stdbool.h>  // bool
#include <stdint.h>  // uint8_t
#include <string.h>  // size_t

#include "signed_video_common.h"  // signed_video_t, SignedVideoReturnCode
#include "signed_video_openssl.h"  // sign_algo_t

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Instruction on where to prepend a generated Bitstream Unit (NALU or OBU).
 *
 * If an action is to prepend a Bitstream Unit (SIGNED_VIDEO_PREPEND_NALU) the generated
 * Bitstream Unit should prepend the input Bitstream Unit + all already prepended
 * Bitstream Units.
 * If an action is to prepend an access unit (SIGNED_VIDEO_PREPEND_ACCESS_UNIT) the
 * generated Bitstream Unit should be added to an extra access unit (AU) preceding the
 * current one. If an extra AU has already been created, this generated Bitstream Unit
 * should prepend all already added Bitstream Units in that extra AU.
 *
 * For example, assume one AU with one Bitstream Unit F0, that is, the memory looks like
 *
 * | AUD | F0 |
 *
 * Further, assume four Bitstream Units are pulled in order; F1, F2, F3 and F4. The
 * corresponding instructions are; SIGNED_VIDEO_PREPEND_NALU, SIGNED_VIDEO_PREPEND_NALU,
 * SIGNED_VIDEO_PREPEND_ACCESS_UNIT and SIGNED_VIDEO_PREPEND_ACCESS_UNIT. Then the memory
 * afterwards should look like this
 *
 * | AUD | F4 | F3 | AUD | F2 | F1 | F0 |
 * /---------------/
 *       new AU
 */
typedef enum {
  // Nothing more to prepend.
  SIGNED_VIDEO_PREPEND_NOTHING,
  // Prepend the Bitstream Units in a preceding access unit.
  SIGNED_VIDEO_PREPEND_ACCESS_UNIT,
  // Prepend the Bitstream Units in the same access unit as the input Bitstream Unit.
  SIGNED_VIDEO_PREPEND_NALU,
} SignedVideoPrependInstruction;

/**
 * A struct composed of the data of a, by Signed Video, generated Bitstream Unit and
 * instructions on how to add it to the stream.
 */
typedef struct {
  SignedVideoPrependInstruction prepend_instruction;
  // Instructions on where to prepend the Bitstream Unit.
  uint8_t *nalu_data;
  // Data of generated Bitstream Unit.
  size_t nalu_data_size;
  // Size of generated |nalu_data|.
} signed_video_nalu_to_prepend_t;

/**
 * The authenticity level sets the granularity of the authenticity.
 */
typedef enum {
  SV_AUTHENTICITY_LEVEL_GOP = 0,
  // The entire GOP is verified as one solid chunk. Hence, if validation fails it is unknown which
  // Bitstream Units were incorrect or missing.
  SV_AUTHENTICITY_LEVEL_FRAME = 1,
  // Individual Bitstream Units are verified. Hence, if validation fails the incorrect or missing
  // Bitstream Unit(s) are detected.
  SV_AUTHENTICITY_LEVEL_NUM
} SignedVideoAuthenticityLevel;

/**
 * @brief Updates Signed Video, with a Bitstream Unit (BU), for signing
 *
 * Each Bitstream Unit (NALU for H.26x and OBU for AV1) in a video has to be processed for
 * signing. Sometimes the BU data is split in parts and cannot be hashed in one go. This
 * API adds a BU part to the signed_video_t object for signing. It is very important that
 * the video BUs are fed to this API in the same order as they are transmitted. Otherwise,
 * the authentication will fail.
 *
 * Signed Video adds SEIs of type "user data unregistered" (OBU Metadata of type "user
 * private") to communicate data for authentication. These SEIs/OBU Metadata are generated
 * by the Signed Video library and are complete Bitstream Units (NALUs + 4 start code
 * bytes, or OBUs). The user is responsible for pulling these generated BUs from the
 * object. Hence, upon a successful signed_video_add_nalu_for_signing_with_timestamp(...)
 * call the user should always call signed_video_get_nalu_to_prepend(...) to get the
 * additional BUs.
 *
 * The timestamp parameter shall be a UNIX epoch value in UTC format. The integrator of
 * this signed video framework shall make sure this is true, so that the client side knows
 * the expected format and is able to convert the timestamp to whatever format is desired.
 * If the timestamp is not NULL and the BU is the first in the GOP (i.e. the first I-frame
 * slice), it will be included in the general SEI/OBU Metadata. All other timestamps and
 * NULL will be disregarded.
 *
 * For sample code, see the description of signed_video_get_nalu_to_prepend(...) below.
 *
 * @param self Pointer to the signed_video_t object in use.
 * @param bu_data A pointer to the Bitstream Unit data
 * @param bu_data_size The size of the Bitstream Unit data.
 * @param timestamp Unix epoch in UTC.
 * @param is_last_part Flag to mark the last part of the Bitstream Unit data.
 *
 * @return SV_OK            - the BU was processed successfully.
 *         SV_NOT_SUPPORTED - signed_video_set_private_key_new(...) has not been set
 *                            OR
 *                            there are generated BUs waiting to be pulled. Use
 *                            signed_video_get_nalu_to_prepend(...) to fetch them. Then call this
 *                            function again to process the |bu_data|.
 *         otherwise a different error code.
 */
SignedVideoReturnCode
signed_video_add_nalu_part_for_signing_with_timestamp(signed_video_t *self,
    const uint8_t *bu_data,
    size_t bu_data_size,
    const int64_t *timestamp,
    bool is_last_part);

/**
 * This API is identical to signed_video_add_nalu_part_for_signing_with_timestamp() where
 * every call has |is_last_part| = true, that is, every part is a complete Bitstream Unit.
 */
SignedVideoReturnCode
signed_video_add_nalu_for_signing_with_timestamp(signed_video_t *self,
    const uint8_t *bu_data,
    size_t bu_data_size,
    const int64_t *timestamp);

/**
 * To be depricated.
 *
 * This API is identical to signed_video_add_nalu_for_signing_with_timestamp using NULL as
 * timestamp.
 */
SignedVideoReturnCode
signed_video_add_nalu_for_signing(signed_video_t *self,
    const uint8_t *bu_data,
    size_t bu_data_size);

/**
 * @brief Gets generated Bitstream Units to prepend the latest added Bitstream Unit (BU)
 *
 * This function should always be called after a successful
 * signed_video_add_nalu_for_signing_with_timestamp(...). Otherwise, the functionality of
 * Signed Video is jeopardized, since vital SEIs may not be added to the video stream. The
 * signed_video_add_nalu_for_signing_with_timestamp(...) returns SV_NOT_SUPPORTED if there
 * are available Bitstream Units to prepend. The user should then pull these before
 * continuing; See return values in signed_video_add_nalu_for_signing_with_timestamp(...).
 *
 * These SEIs are generated by the Signed Video library and are complete BU (NALUs + 4
 * start code bytes, or OBUs). Hence, the user can simply pull and prepend existing BU.
 * Pull BUs to prepend from signed_video_t one by one until no further action is required.
 * When this happens, a SIGNED_VIDEO_PREPEND_NOTHING instruction is pulled.
 * The signed_video_get_nalu_to_prepend(...) API provides the user with the BU data as
 * well as instructions on where to prepend that data.
 *
 * @note that as soon as the user pulls a new Bitstream Unit to prepend, the ownership of
 * the |nalu_data| memory (see members of signed_video_nalu_to_prepend_t) is transferred.
 * Free the |nalu_data| memory with signed_video_nalu_data_free(...).
 *
 * Here is an example code of usage:
 *
 *   signed_video_t *sv = signed_video_create(SV_CODEC_H264);
 *   if (!sv) {
 *     // Handle error
 *   }
 *   if (signed_video_set_private_key_new(sv, private_key, private_key_size) != SV_OK) {
 *     // Handle error
 *   }
 *   SignedVideoReturnCode status;
 *   status = signed_video_add_nalu_for_signing_with_timestamp(sv, bu, bu_size, NULL);
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
 * @param nalu_to_prepend A pointer to a signed_video_nalu_to_prepend_t object holding
 *   Bitstream Unit data and prepend instructions.
 *
 * @return SV_OK            - Bitstream Unit was pulled successfully,
 *         SV_NOT_SUPPORTED - no available data, the action is not supported,
 *         otherwise        - an error code.
 */
SignedVideoReturnCode
signed_video_get_nalu_to_prepend(signed_video_t *self,
    signed_video_nalu_to_prepend_t *nalu_to_prepend);

/**
 * @brief Gets generated SEIs/OBU Metadata to add to the stream
 *
 * This function is recommended to be called before
 * signed_video_add_nalu_for_signing_with_timestamp(...). The user has an option to
 * provide this function with a |peek_bu|, which is the same Bitstream Unit (BU) that is
 * to be added for signing. A Bitstream Unit is a NALU for H.26x and OBU for AV1.
 *
 * These SEIs/OBU Metadata are generated by the Signed Video library and are complete
 * BU (NAL Units + 4 start code bytes, or OBUs). Hence, the user can simply pull and
 * prepend existing BUs. Pull BUs to prepend from signed_video_t one by one until no more
 * generated SEIs/OBU Metadata exists, that is, when |sei_size| is zero and/or |sei| is a
 * NULL pointer.
 *
 * @note: The memory is transferred and the user is responsible for freeing the memory of
 * the |sei|.
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
 *   uint8_t *sei = NULL;
 *   size_t sei_size = 0;
 *   // Get the SEI data.
 *   status = signed_video_get_sei(sv, &sei, &sei_size, NULL, NULL, 0, NULL);
 *   while (status == SV_OK && sei_size > 0) {
 *       // Add the SEI to the stream according to the standard.
 *       // The user is responsible for freeing |sei|.
 *       // Check for more SEIs.
 *       status = signed_video_get_sei(sv, &sei, &sei_size, NULL, NULL, 0, NULL);
 *   }
 *   status = signed_video_add_nalu_for_signing_with_timestamp(sv, bu, bu_size, NULL);
 *   if (status != SV_OK) {
 *     // Handle error
 *   }
 *
 * @param self Pointer to the signed_video_t object in use.
 * @param sei Pointer to the memory pointer to which a complete SEI/OBU Metadata is
 *   located.
 * @param sei_size Pointer to where the size of the SEI/OBU Metadata is written.
 * @param payload_offset Pointer to where the offset to the start of the SEI/OBU Metadata
 *   payload is written. This is useful if the SEI/OBU Metadata is added by the encoder,
 *   which would take the SEI/OBU Metadata payload only and then fill in the header,
 *   payload size and apply emulation prevention onto the data.
 * @param peek_bu Pointer to the BU of which the SEI/OBU Metadata will be prepended as a
 *   header. When peeking at the next BU, SEIs/OBU Metadata can only be fetched if the BU
 *   is a primary slice. A NULL pointer means that the user is responsible to add the
 *   SEI/OBU Metadata according to standard.
 * @param peek_bu_size The size of the peek BU.
 * @param num_pending_seis Pointer to where the number of pending SEIs/OBU Metadata is
 *   written.
 *
 * @return SV_OK            - Bitstream Unit was copied successfully,
 *         SV_NOT_SUPPORTED - no available data, the action is not supported,
 *         otherwise        - an error code.
 */
SignedVideoReturnCode
signed_video_get_sei(signed_video_t *self,
    uint8_t **sei,
    size_t *sei_size,
    unsigned *payload_offset,
    const uint8_t *peek_bu,
    size_t peek_bu_size,
    unsigned *num_pending_seis);

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
 * When reaching the end of a stream (EOS) a final SEI/OBU Metadata needs to be
 * transmitted to be able to validate all the way to the end, thereby avoiding a dangling
 * end.
 *
 * This API can be called when the end of a stream is reached. Afterwards, all Bitstream
 * Units to prepend should be pulled as normal using signed_video_get_sei(...) above.
 *
 * @param self Pointer to the signed_video_t object in use.
 *
 * @return SV_OK            - EOS was successfully set,
 *         otherwise        - an error code.
 */
SignedVideoReturnCode
signed_video_set_end_of_stream(signed_video_t *self);

/**
 * @brief Generates a golden SEI/OBU Metadata.
 *
 * A golden SEI/OBU Metadata is a self-signed SEI/OBU Metadata that includes all
 * information only needed once such as the Public key. Usually a golden SEI/OBU Metadata
 * is sent only once in the beginning of a stream.
 * With this function a golden SEI/OBU Metadata can be generated and the user can store it
 * for later use, and easily added to the stream when needed.
 *
 * Here is an example code of usage:
 *
 *   signed_video_t *sv = signed_video_create(SV_CODEC_H264);
 *   if (!sv) {
 *     // Handle error
 *   }
 *   if (signed_video_set_private_key_new(sv, private_key, private_key_size)
 *       != SV_OK) {
 *     // Handle error
 *   }
 *   // All necessary configurations need to be done prior to this call.
 *   status = signed_video_generate_golden_sei(sv);
 *   if (status != SV_OK) {
 *     // Handle error
 *   }
 *   // Before fetching the SEI user needs to wait for the SEI generated.
 *   sleep(1);
 *   // The user can get the golden SEI using signed_video_get_sei().
 *
 * @param self Pointer to the signed_video_t object in use.
 *
 * @return An appropriate return code.
 */
SignedVideoReturnCode
signed_video_generate_golden_sei(signed_video_t *self);

/**
 * @brief Sets the product information for the signed video session
 *
 * This API will set the hardware id, firmware version and serial number in the
 * signed_video_t struct for the session. Although this should only have to be set once,
 * this can be called multiple times during the signing, but it must be done in between
 * adding Bitstream Units synchronously.
 * @note: This API assumes null-terminated input strings.
 * @note: The length of a string has to be less than 255 characters, otherwise the string
 * will be truncated.
 *
 * @param self Signed Video session pointer
 * @param hardware_id Null-terminated string
 * @param firmware_version Null-terminated string
 * @param serial_number Null-terminated string
 * @param manufacturer Null-terminated string
 * @param address Null-terminated string
 *
 * @return SV_OK            - Product info was successfully set,
 *         otherwise        - an error code.
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
 * @note: This call has to be called before the video session can begin.
 *
 * Signed Video requires a PEM file format of private (and public) keys. The user is
 * responsible for key handling. The content of the private key (in PEM format) is passed
 * to Signed Video through this API. For Linux there is an OpenSSL based helper function
 * to generate a private key in a given location; See signed_video_openssl.h.
 *
 * Associated with the private key is a signing algorithm, for example RSA or ECDSA. This
 * type needs to be set to know if some additional actions need to be taken when signing
 * or validating. The algorithm will be transmitted in the SEI and picked up by the client
 * side which will then be able to take necessary actions on their side before verifying
 * the signature.
 *
 * @param self Pointer to the signed_video_t object session.
 * @param private_key The content of the private key pem file.
 * @param private_key_size The size of the |private_key|.
 *
 * @return SV_OK If the |private_key| is set,
 *         SV_INVALID_PARAMETER Invalid input parameter(s),
 *         SV_MEMORY If failed allocating memory for the private key,
 *         SV_EXTERNAL_ERROR The public key could not be extracted.
 */
SignedVideoReturnCode
signed_video_set_private_key_new(signed_video_t *self,
    const char *private_key,
    size_t private_key_size);
/* TO BE REPLACED BY signed_video_set_private_key_new(). */
SignedVideoReturnCode
signed_video_set_private_key(signed_video_t *self,
    sign_algo_t algo,
    const char *private_key,
    size_t private_key_size);

/**
 * @brief Setter for adding the Public key to the SEI/OBU Metadata or not
 *
 * If the public key, used to verify the signatures, cannot be secured through a hardware
 * certificate or key attestation, it should not be added to the video stream. Without
 * securing it, anyone can sign arbitrary (tampered) videos.
 *
 * This function should be used before starting the Signed Video session. If it is not
 * used, the public key is added to the SEI/OBU Metadata.
 *
 * @param self Pointer to the current Signed Video session
 * @param add_public_key_to_sei Flag to indicate if the public key should be added to the
 *   SEI/OBU Metadata (default true)
 *
 * @return A Signed Video Return Code (SignedVideoReturnCode)
 */
SignedVideoReturnCode
signed_video_add_public_key_to_sei(signed_video_t *self, bool add_public_key_to_sei);

/**
 * @brief Sets the authenticity level to be used.
 *
 * The framework supports two levels of authenticity; GOP and Frame, where Frame is
 * default. At GOP level a verification is made for the entire GOP in one chunk, whereas
 * at Frame level frame drops can be handled.
 *
 * The signing part decides on the level and the receiving end will automatically produce
 * an appropriate report.
 *
 * @note: that authenticity at Frame level will have a significantly higher bitrate than
 * at GOP level.
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
 * Metadata that is only needed once when validating the authenticity can be transmitted
 * with a different recurrence interval than the signatures. This API sets that
 * recurrence, counted in frames (not Bitstream Units). Note that this type of metadata is
 * still bundled together in the same SEI/OBU Metadata as the signature, hence the true
 * recurrence will be correct on the average.

 * Example of metadata that is only needed once are the public key and product info.
 *
 * @param self Session struct pointer
 * @param recurrence Recurrence interval in frames
 *
 * @return SV_OK Recurrence interval was successfully set,
 *         SV_INVALID_PARAMETER Invalid parameter,
 *         SV_NOT_SUPPORTED Recurrence interval is not supported.
 */
/* TO BE DEPRECATED */
SignedVideoReturnCode
signed_video_set_recurrence_interval_frames(signed_video_t *self, unsigned recurrence);

/**
 * @brief Configures Signed Video to generate the SEIs with/without emulation prevention
 *
 * Emulation prevention bytes (EPB) are used to prevent the decoder from detecting the
 * start code sequence in the middle of a NAL Unit. By default, the framework generates
 * SEI frames with EPB written to the payload. With this API, the user can select to have
 * Signed Video generate SEI frames with or without EPBs.

 * If this API is not used, SEI payload is written with EPBs, hence equivalent with
 * setting |sei_epb| to True.
 *
 * @note: AV1 does not have emulation prevention. Therefore, this API is not supported for
 * AV1.
 *
 * @param self Session struct pointer
 * @param sei_epb SEI payload written with EPB (default True if applicable)
 *
 * @return SV_OK SEI w/o EPB was successfully set,
 *         SV_NOT_SUPPORTED if codec is AV1,
 *         SV_INVALID_PARAMETER Invalid parameter.
 */
SignedVideoReturnCode
signed_video_set_sei_epb(signed_video_t *self, bool sei_epb);

/**
 * @brief Configures Signed Video to use golden SEI/OBU Metadata principle
 *
 * The principle of the golden SEI/OBU Metadata sends all information only needed once,
 * such as the Public key, at the start of the stream with the golden SEI/OBU Metadata.
 * After that, the rest of the SEIs/OBU Metadata in the stream only include mandatory
 * information.
 *
 * It is the user's responsibility to ensure that the first SEI/OBU Metadata in the stream
 * is a golden SEI/OBU Metadata.
 * This golden SEI/OBU Metadata does not necessarily have to be at the very beginning of
 * the stream, but it must be the first SEI/OBU Metadata included.
 *
 * @note: It is not feasible to set this on an ongoing session.
 *
 * @param self Session struct pointer
 * @param using_golden_sei Flag to enable or disable the golden SEI/OBU Metadata principle.
 *
 * @return SV_OK SEI/OBU Metadata |using_golden_sei| was successfully set,
 *         SV_INVALID_PARAMETER Invalid parameter.
 *         SV_NOT_SUPPORTED if set during an ongoing session.
 */
SignedVideoReturnCode
signed_video_set_using_golden_sei(signed_video_t *self, bool using_golden_sei);

/**
 * @brief Configures Signed Video to limit the payload size of the SEIs/OBU Metadata
 *
 * In many Signed Video integrations on the signing side SEIs/OBU Metadata cannot become
 * arbitrary large due to hardware constraints. This API sets an upper limit on the
 * payload size of the generated SEI/OBU Metadata. If the, to be generated, SEI/OBU
 * Metadata exceeds the set |max_sei_payload_size| Signed Video falls back to GOP level
 * authentication.
 *
 * Note that it is a soft limit. If the payload size is still too large even for GOP level
 * authentication the SEI/OBU Metadata is generated. Further, note that the API sets the
 * maximum SEI/OBU Metadata payload size. The final SEI/OBU Metadata size can become
 * larger since it includes headers, size bytes and potentional emulation prevention.
 *
 * If this API is not used, an unlimited SEI/OBU Metadata payload size is used
 * (|max_sei_payload_size| = 0).
 *
 * The behavior of this API may change in the future and replace the fallback mechanism
 * with a forced signing mechanism.
 *
 * @param self Session struct pointer
 * @param max_sei_payload_size Upper limit on SEI/OBU Metadata payload
 *   (default 0 = unlimited)
 *
 * @return SV_OK Max SEI/OBU Metadata payload size was successfully set,
 *         SV_INVALID_PARAMETER Invalid parameter.
 */
SignedVideoReturnCode
signed_video_set_max_sei_payload_size(signed_video_t *self, size_t max_sei_payload_size);

/**
 * @brief Configures Signed Video to use a specific hash algorithm
 *
 * Signed Video hashes Bitstream Units and, depending on configuration, sends these hashes
 * in a SEI/OBU Metadata.
 * The default hash algorithm used is SHA256. With this function, the user can change hash
 * algorithm.
 *
 * Only hash algorithms supported by OpenSSL can be used and should be specified by
 * |name_or_oid|. For example, to use SHA512 use the name "sha512", or the OID
 * "2.16.840.1.101.3.4.2.3". For a complete list of, by OpenSSL, supported algorithms see
 * the OpenSSL documentation.
 *
 * If this API is not used, or if a nullptr is passed in as |name_or_oid|, SHA256 is used.
 *
 * This function can only be used before a Signed Video stream has started, or after a
 * reset. Changing the hash algorithm on the fly is not supported.
 *
 * @note: that this is NOT the message digest hash used in signing data.
 *
 * @param self Session struct pointer
 * @param name_or_oid A null terminated string of the name or OID of the hash function to
 *   use
 *
 * @return SV_OK A hash algorithm was successfully set,
 *         SV_INVALID_PARAMETER Invalid parameter,
 *         SV_NOT_SUPPORTED If called during ongoing signing.
 */
SignedVideoReturnCode
signed_video_set_hash_algo(signed_video_t *self, const char *name_or_oid);

/**
 * @brief Sets an upper limit on number of frames before signing
 *
 * The default behavior of the Signed Video library is to sign and generate a SEI every
 * GOP (Group Of Pictures). When very long GOPs are used, the duration between signatures
 * can become impractically long, or even makes a file export on the validation side
 * infeasible to validate because the segment lacks a SEI.
 *
 * This API allows the user to set an upper limit on how many frames that can be added
 * before sending a signing request. If this limit is reached, an intermediate SEI is
 * generated. This limit will not affect the normal behavior of signing when reaching the
 * end of a GOP (or when the signing frequency set with
 * signed_video_set_signing_frequency(...) (to be implemented)).
 * If |max_signing_frames| = 0, no limit is used. This is the default behavior.
 *
 * @note the difference between 'frames' and 'Bitstream Units'. A frame can be split in
 * several slices. To avoid creating a SEI and signing it in the middle of a frame only
 * primary slices are counted.
 * @note that it is the responsibility to set a value that will not jeopardize the signing
 * functionality. For example, signing every frame (max_signing_frames = 1) can be
 * infeasible in practice since signing takes longer than the duration between frames.
 *
 * @param self Pointer to the Signed Video session.
 * @param max_signing_frames Maximum number of frames covered by a signatures.
 *
 * @return An appropriate Signed Video Return Code.
 */
SignedVideoReturnCode
signed_viedo_set_max_signing_frames(signed_video_t *self, unsigned max_signing_frames);

#ifdef __cplusplus
}
#endif

#endif  // __SIGNED_VIDEO_SIGN_H__
