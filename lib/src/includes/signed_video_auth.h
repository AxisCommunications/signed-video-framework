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

#ifndef __SIGNED_VIDEO_AUTH_H__
#define __SIGNED_VIDEO_AUTH_H__

#include <stdbool.h>  // bool
#include <stdint.h>  // uint8_t
#include <string.h>  // size_t

#include "signed_video_common.h"  // signed_video_t, SignedVideoReturnCode

/**
 * Status of authenticity validation since last result
 */
typedef enum {
  SV_AUTH_RESULT_NOT_SIGNED = 0,
  // The consumed NALUs so far contain no signature information.
  SV_AUTH_RESULT_SIGNATURE_PRESENT = 1,
  // Signed video has been detected present, but there is not enough information to complete a
  // validation. This state is shown until validation has been performed.
  SV_AUTH_RESULT_NOT_OK = 2,
  // At least one NALU failed verification.
  SV_AUTH_RESULT_OK_WITH_MISSING_INFO = 3,
  // Successfully verified all NALUs that could be verified, but missing NALUs were detected.
  // Further actions need to be taken to judge these losses and complete the authenticity
  // validation.
  SV_AUTH_RESULT_OK = 4,
  // Successfully verified all NALUs that could be verified, and all expected NALUs are present.
  SV_AUTH_RESULT_VERSION_MISMATCH = 5,
  // Video has been signed with a version newer than that used by the validation part. Correct
  // validation cannot be guaranteed. The user is encouraged to update the validation code with a
  // newer version.
  SV_AUTH_NUM_SIGNED_GOP_VALID_STATES
} SignedVideoAuthenticityResult;

/**
 * Status of public key validation
 */
typedef enum {
  SV_PUBKEY_VALIDATION_NOT_FEASIBLE = 0,
  // There are no means to verify the public key. This happens if no attestation exists or if the
  // public key was not part of the stream.
  SV_PUBKEY_VALIDATION_NOT_OK = 1,
  // The Public key in the SEI was not validated successfully. The video might be correct, but its
  // origin could not be verified.
  SV_PUBKEY_VALIDATION_OK = 2,
  // The Public key in the stream was validated successfully. The origin of the key is correct and
  // trustworthy when validating the video.
  SV_PUBKEY_VALIDATION_NUM_STATES
} SignedVideoPublicKeyValidation;

/**
 * Struct storing the latest validation result. In general, that spans an entire GOP, but for long
 * GOP lengths an intermediate validation may be provided.
 */
typedef struct {
  SignedVideoAuthenticityResult authenticity;
  // The result of the latest authenticity validation.
  bool public_key_has_changed;
  // A new Public key has been detected. Signing an ongoing stream with a new key is not allowed.
  int number_of_expected_picture_nalus;
  // Indicates how many picture NALUs (i.e., excluding SEI, PPS/SPS/VPS, AUD) were expected, and
  // part of the signature, since last validation. A negative value indicates that such information
  // is lacking due to a missing, or tampered, SEI.
  int number_of_received_picture_nalus;
  // Indicates how many picture NALUs (i.e., excluding SEI, PPS/SPS/VPS, AUD) have been received
  // since last validation, and used to verify the signature. If the signed video feature is
  // disabled, or an error occurred during validation, a negative value is set.
  int number_of_pending_picture_nalus;
  // Indicates how many picture NALUs (i.e., excluding SEI, PPS/SPS/VPS, AUD) are pending
  // validation.
  char *validation_str;
  // A string displaying the validation status of all the latest NALUs. The string ends with a null
  // terminated character. The validated NALUs are removed after fetching the authenticity_report.
  // This means that the user can count backwards from the latest/current NALU and verify each
  // NALU's authenticity individually. Each NALU is marked by one of these characters:
  // 'P' : Pending validation. This is the initial value. The NALU has been registered and waiting
  //       for authenticity validation.
  // 'U' : The NALU has an unknown authenticity. This occurs if the NALU could not be parsed, or if
  //     : the SEI is associated with NALUs not part of the validating segment.
  // '_' : The NALU is ignored and therefore not part of the signature. The NALU has no impact on
  //       the video and is considered validated as authentic.
  // '.' : The NALU has been validated as authentic.
  // 'N' : The NALU has been validated as not authentic.
  // 'M' : The validation has detected one or more missing NALUs at this position.
  // 'E' : An error occurred and validation could not be performed. This should be treated as an
  //       invalid NALU.

  // Example:
  // Two consecutive |validation_str|. After 10 NALUs a authentication result was received
  // generating the first string. Left for next validation are the three pending NALUs (P's) and
  // the ignored NALU ('_'). Five new NALUs were added before the authentication result was
  // updated. A new string has been generated (second line) and now the pending NALUs have been
  // validated successfully (the P's have been turned into '.'). Note that the ignored NALU ('_')
  // is still ignored.
  //   ..._..PP_P
  //         .._...PPP
  SignedVideoPublicKeyValidation public_key_validation;
  // The result of the latest Public key validation. If the Public key is present in the SEI, it has
  // to be validated to associate the video with a source. If it is not feasible to validate the
  // Public key, it should be validated manually to secure proper video authenticity.
} signed_video_latest_validation_t;

/**
 * A struct holding information of the overall authenticity of the session. Typically, this
 * information is used after screening an entire file, or when closing a session.
 */
typedef struct {
  SignedVideoAuthenticityResult authenticity;
  // The overall authenticity of the session.
  bool public_key_has_changed;
  // A new Public key has been detected. Signing an ongoing stream with a new key is not allowed. If
  // this flag is set the |authenticity| is automatically set to SV_AUTH_RESULT_NOT_OK.
  unsigned int number_of_received_nalus;
  // Total number of received NALUs, that is all NALUs added for validation.
  unsigned int number_of_validated_nalus;
  // Total number of validated NALUs, that is, how many of the received NALUs that so far have been
  // validated.
  unsigned int number_of_pending_nalus;
  // The number of NALUs that currently are pending validation.
  SignedVideoPublicKeyValidation public_key_validation;
  // The result of the Public key validation. If the Public key is present in the SEI, it has to be
  // validated to associate the video with a source. If it is not feasible to validate the Public
  // key, it should be validated manually to secure proper video authenticity.
} signed_video_accumulated_validation_t;

/**
 * Struct for holding strings to selected product information
 */
typedef struct {
  char *hardware_id;  // Hardware ID
  char *firmware_version;  // Firmware version
  char *serial_number;  // Serial number
  char *manufacturer;  // Manufacturer
  char *address;  // Address to manufacturer, contact info like url/email/mail address.
} signed_video_product_info_t;

/**
 * Authenticity Report
 *
 * This struct includes statistics and information of the authenticity validation process. This
 * should provide all necessary means to make a correct decision on the authenticity of the video.
 */
typedef struct {
  char *version_on_signing_side;
  // Code version used when signing the video.
  char *this_version;
  // Code version used when validating the authenticity.
  signed_video_product_info_t product_info;
  // Information about the product provided in a struct.
  signed_video_latest_validation_t latest_validation;
  // Holds the information of the latest validation.
  signed_video_accumulated_validation_t accumulated_validation;
  // Holds the information of the total validation since the first added NALU.
} signed_video_authenticity_t;

/**
 * @brief Frees the signed_video_authenticity_t report.
 *
 * Frees all memory used in the |authenticity_report|.
 *
 * @param authenticity_report Pointer to current Authenticity Report
 */
void
signed_video_authenticity_report_free(signed_video_authenticity_t *authenticity_report);

/**
 * @brief Returns a copy of the signed_video_authenticity_t report from the Signed Video session.
 *
 * The returned signed_video_authenticity_t report is a snapshot of the current validation status.
 * Hence, the returned report is not updated further with new statistics if the Signed Video session
 * proceeds. Note that also signed_video_add_nalu_and_authenticate(...) can report the current
 * validation status, hence use this function with care.
 *
 * Memory is transfered and the user is responsibe to free it using
 * signed_video_authenticity_report_free(...)
 *
 * @param self Pointer to the current Signed Video session.
 *
 * @returns A copy of the latest authenticity report
 */
signed_video_authenticity_t *
signed_video_get_authenticity_report(signed_video_t *self);

/* Example code
 *
 * Use case: Live monitoring
 *   signed_video_t *sv = signed_video_create(SV_CODEC_H264);
 *   signed_video_authenticity_t *auth_report = NULL;
 *
 *   // For every H26x NALU received do
 *   while (still_nalus_remaining) {
 *     SignedVideoReturnCode status = signed_video_add_nalu_and_authenticate(sv, nalu_data,
 *         nalu_data_size, &auth_report);
 *     if (status != SV_OK) {
 *       printf("Authentication encountered error (%d)\n", status);
 *     } else if (auth_report) {
 *       switch (auth_report->latest_validation.authenticity) {
 *         case SV_AUTH_RESULT_OK:
 *           printf("The video since last signature is authentic\n");
 *           break;
 *         case SV_AUTH_RESULT_NOT_OK:
 *           printf("The video since last signature is not authentic\n");
 *           break;
 *         case SV_AUTH_RESULT_OK_WITH_MISSING_INFO:
 *           printf("The video since last signature has missing information, but the last gop is \
 *               authentic\n");
 *           break;
 *         case SV_AUTH_RESULT_NOT_SIGNED:
 *           printf("The signed video feature is not present in this video\n");
 *           break;
 *         case SV_AUTH_RESULT_SIGNATURE_PRESENT:
 *           printf("The signed video feature has been detected and waiting for the first \
 *               signature\n");
 *           break;
 *         default:
 *           printf("Unexpected authentication result\n")
 *           break;
 *       }
 *       // Free |auth_report| if you are done with it
 *       signed_video_authenticity_report_free(auth_report);
 *     } else {
 *       printf("Waiting for next signature\n")
 *     }
 *   }
 *
 *   // Free the memory when session ends
 *   singed_video_free(sv);
 */

/**
 * @brief Add NALU data to the session and get an authentication report
 *
 * This function should be called for each H26x NALU the user receives. It is assumed that
 * |nalu_data| consists of one single NALU including Start Code and NALU, so that NALU type can be
 * parsed. That is, the format should look like this:
 *
 * |------------|------|
 * | Start Code | NALU |
 * |------------|------|
 *  3 or 4 bytes       ^
 *                     Including stop bit
 *
 * NOTE: NALUs sent into the API cannot be in packetized format (access units)!
 * The access unit has to be split into NALUs if so.
 *
 * The input |nalu_data| is not changed by this call. Note that it is assumed that ALL H26x NALUs
 * are passed to this function. Otherwise, they will be treated as missing/lost packets which may
 * affect the validation.
 *
 * Signatures are sent on regular basis. Currently this is done at the end of each GOP (Group Of
 * Pictures). For every input |nalu_data| with a signature, or when a signature is expected,
 * validation is performed and a copy of the |authenticity| result is provided. If a NALU does not
 * trigger a validation, |authenticity| is a NULL pointer. If one NALU is lost or tampered with
 * within a GOP, the whole GOP is marked as NOT OK, even if the other NALUs are correct.
 *
 * The user should continuously check the return value for errors and upon success check
 * |authenticity| for a new report.
 * Two typical use cases are; 1) live monitoring which could be screening the video until
 * authenticity can no longer be validated OK, and 2) screening a recording and get a full report at
 * the end. In the first case further operations can simply be aborted as soon as a validation
 * fails, whereas in the latter case all the NALUs need to be screened.
 * NOTE: Only the live monitoring use case is currently supported.
 *
 * Example code of usage; See example code above.
 *
 * @param self Pointer to the signed_video_t object to update
 * @param nalu_data Pointer to the H26x NALU data to be added
 * @param nalu_data_size Size of the nalu_data
 * @param authenticity Pointer to the autenticity report. Passing in a NULL pointer will not provide
 *     latest validation results. The user is then responsible to get a report using
 *     signed_video_get_authenticity_report(...).
 *
 * @returns A Signed Video Return Code (SignedVideoReturnCode)
 */
SignedVideoReturnCode
signed_video_add_nalu_and_authenticate(signed_video_t *self,
    const uint8_t *nalu_data,
    size_t nalu_data_size,
    signed_video_authenticity_t **authenticity);

/**
 * @brief Sets the public key used to validate the video authenticity
 *
 * For videos where the public key, necessary to verify the signature, is not present in the SEIs
 * the user needs to provide that key manually.
 *
 * This function allows the user to add the public key to the current Signed Video session. The
 * operation has to be performed before the session starts. It is not allowed to change the public
 * key on the fly, for which SV_NOT_SUPPORTED is returned.
 *
 * If the public key is added for a session already including a public key in the SEI, the key in
 * the SEI rules the other key.
 *
 * The |public_key| data is assumed to be in PEM format.
 *
 * @param self Pointer to the current Signed Video session
 * @param public_key Pointer to the public key data
 * @param public_key_size Size of the public key
 *
 * @returns A Signed Video Return Code (SignedVideoReturnCode)
 */
SignedVideoReturnCode
signed_video_set_public_key(signed_video_t *self, const char *public_key, size_t public_key_size);

#endif  // __SIGNED_VIDEO_AUTH_H__
