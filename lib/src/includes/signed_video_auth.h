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

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Status of authenticity validation since last result
 */
typedef enum {
  // The consumed Bitstream Units (NALUs or OBUs) so far contain no signature information.
  SV_AUTH_RESULT_NOT_SIGNED = 0,
  // Signed Video has been detected as present, but there is not enough information to complete a
  // validation. This state is shown until validation has been performed.
  SV_AUTH_RESULT_SIGNATURE_PRESENT = 1,
  // At least one Bitstream Unit (NALU or OBU) failed verification.
  SV_AUTH_RESULT_NOT_OK = 2,
  // Successfully verified all Bitstream Units (NALUs or OBUs) that could be verified, but missing
  // Bitstream Units were detected. Further actions need to be taken to judge these losses and
  // complete the authenticity validation.
  SV_AUTH_RESULT_OK_WITH_MISSING_INFO = 3,
  // Successfully verified all Bitstream Units (NALUs or OBUs) that could be verified, and all
  // expected Bitstream Units are present.
  SV_AUTH_RESULT_OK = 4,
  // Video has been signed with a version newer than that used by the validation part. Correct
  // validation cannot be guaranteed. The user is encouraged to update the validation code with a
  // newer version.
  SV_AUTH_RESULT_VERSION_MISMATCH = 5,
  SV_AUTH_NUM_SIGNED_GOP_VALID_STATES
} SignedVideoAuthenticityResult;

/**
 * Status of public key validation
 */
typedef enum {
  // There are no means to verify the public key. This happens if no attestation exists or if the
  // public key was not part of the stream.
  SV_PUBKEY_VALIDATION_NOT_FEASIBLE = 0,
  // The Public key in the SEI/OBU Metadata was not validated successfully. The video might be
  // correct, but its origin could not be verified.
  SV_PUBKEY_VALIDATION_NOT_OK = 1,
  // The Public key in the stream was validated successfully. The origin of the key is correct and
  // trustworthy when validating the video.
  SV_PUBKEY_VALIDATION_OK = 2,
  SV_PUBKEY_VALIDATION_NUM_STATES
} SignedVideoPublicKeyValidation;

/**
 * Struct storing the latest validation result. In general, that spans an entire GOP, but for long
 * GOP lengths an intermediate validation may be provided.
 */
typedef struct {
  // The result of the latest authenticity validation.
  SignedVideoAuthenticityResult authenticity;
  // A new Public key has been detected. Signing an ongoing stream with a new key is not allowed.
  bool public_key_has_changed;
  // Indicates how many picture Bitstream Units (NALUs or OBUs) were expected, and part of the
  // signature, since last validation. Note that this excludes SEI, PPS/SPS/VPS, AUD. A negative
  // value indicates that such information is lacking due to a missing, or tampered,
  // SEI/OBU Metadata.
  int number_of_expected_picture_nalus;
  // Indicates how many picture Bitstream Units (NALUs or OBUs) have been received since last
  // validation, and used to verify the signature. Note that this excludes SEI, PPS/SPS/VPS, AUD. If
  // the signed video feature is disabled, or an error occurred during validation, a negative value
  // is set.
  int number_of_received_picture_nalus;
  // Indicates how many picture Bitstream Units (NALUs or OBUs) are pending validation. Note that
  // this excludes SEI, PPS/SPS/VPS, AUD.
  int number_of_pending_picture_nalus;
  // A string displaying the validation status of all the latest Bitstream Units (NALUs or OBUs).
  // The string ends with a null terminated character. The validated Bitstream Units (NALUs or OBUs)
  // are removed after fetching the authenticity_report.
  // This means that the user can count backwards from the latest/current Bitstream Unit and verify
  // each Bitstream Unit's authenticity individually. Each Bitstream Unit is marked by one of these
  // characters:
  // 'P' : Pending validation. This is the initial value. The Bitstream Unit has been registered and
  //       waiting for authenticity validation.
  // 'U' : The Bitstream Unit has an unknown authenticity. This occurs if the Bitstream Unit could
  //       not be parsed, or if the SEI/OBU Metadata is associated with Bitstream Unit not part of
  //       the validating segment.
  // '_' : The Bitstream Unit is ignored and therefore not part of the signature. The Bitstream Unit
  //       has no impact on the video and is validated as authentic.
  // '.' : The Bitstream Unit has been validated as authentic.
  // 'N' : The Bitstream Unit has been validated as not authentic.
  // 'M' : The validation has detected one or more missing Bitstream Units at this position.
  // 'E' : An error occurred and validation could not be performed. This should be treated as an
  //       invalid Bitstream Unit.

  // Example:
  // Two consecutive |validation_str|. After 10 Bitstream Units a authentication result was received
  // generating the first string. Left for next validation are the three pending Bitstream Units
  // (P's) and the ignored Bitstream Unit ('_'). Five new Bitstream Units were added before the
  // authentication result was updated. A new string has been generated (second line) and now the
  // pending Bitstream Units have been validated successfully (the P's have been turned into '.').
  // Note that the ignored Bitstream Unit ('_') is still ignored.
  //   __....P_P.
  //         ._....PP.
  char *validation_str;
  // As a complement to the validation_str above, this string displays the type of all the latest
  // Bitstream Units. The string ends with a null terminated character. Each Bitstream Unit is
  // marked by one of these characters:
  // 'I' : I-frame (primary slice)
  // 'i' : I-frame (not primary slice)
  // 'P' : P-frame (primary slice)
  // 'p' : P-frame (not primary slice)
  // 'S' : SEI/OBU Metadata, generated by Signed Video including a signature
  // 's' : SEI/OBU Metadata, generated by Signed Video not including a signature
  // 'z' : SEI/OBU Metadata, other type than Signed Video generated
  // 'v' : Parameter Set, i.e., SPS/PPS/VPS, SH
  // '_' : AUD/TD
  // 'o' : Other valid type of Bitstream Unit
  // 'U' : Undefined Bitstream Unit
  // ' ' : No Bitstream Unit present, e.g., when missing Bitstream Units are detected

  // Example:
  // Complementing the example above.
  //         nalu_str:  vvIPPPIzPS
  //   validation_str:  __....P_P.
  //                          IzPSPPIPS
  //                          ._....PP.
  char *nalu_str;
  // The result of the latest Public key validation. If the Public key is present in the
  // SEI/OBU Metadata, it has to be validated to associate the video with a source. If it is not
  // feasible to validate the Public key, it should be validated manually to secure proper video
  // authenticity.
  SignedVideoPublicKeyValidation public_key_validation;
  // True if the timestamp member is valid to look at, false otherwise.
  bool has_timestamp;
  // Unix epoch UTC timestamp in microseconds of the latest signed Bitstream Unit.
  int64_t timestamp;
} signed_video_latest_validation_t;

/**
 * A struct holding information of the overall authenticity of the session. Typically, this
 * information is used after screening an entire file, or when closing a session.
 */
typedef struct {
  // The overall authenticity of the session.
  SignedVideoAuthenticityResult authenticity;
  // A new Public key has been detected. Signing an ongoing stream with a new key is not allowed. If
  // this flag is set the |authenticity| is automatically set to SV_AUTH_RESULT_NOT_OK.
  bool public_key_has_changed;
  // Total number of received Bitstream Units, that is all Bitstream Units added for validation.
  unsigned int number_of_received_nalus;
  // Total number of validated Bitstream Units, that is, how many of the received Bitstream Units
  // that so far have been validated.
  unsigned int number_of_validated_nalus;
  // The number of Bitstream Units that currently are pending validation.
  unsigned int number_of_pending_nalus;
  // The result of the Public key validation. If the Public key is present in the SEI/OBU Metadata,
  // it has to be validated to associate the video with a source. If it is not feasible to validate
  // the Public key, it should be validated manually to secure proper video authenticity.
  SignedVideoPublicKeyValidation public_key_validation;
  // True if the session included timestamps.
  bool has_timestamp;
  // Unix epoch UTC timestamp in microseconds of the first signed Bitstream Unit.
  int64_t first_timestamp;
  // Unix epoch UTC timestamp in microseconds of the last signed Bitstream Unit.
  int64_t last_timestamp;
} signed_video_accumulated_validation_t;

/**
 * Struct for holding strings to selected product information
 *
 * Note that the SEIs can only handle string lengths that can be represented by one byte,
 * that is, up to 255 character strings. If longer names are set, they will be truncated.
 */
typedef struct {
  char hardware_id[256];  // Hardware ID
  char firmware_version[256];  // Firmware version
  char serial_number[256];  // Serial number
  char manufacturer[256];  // Manufacturer
  char address[256];  // Address to manufacturer, contact info like url/email/mail address.
} signed_video_product_info_t;

/**
 * Authenticity Report
 *
 * This struct includes statistics and information of the authenticity validation process. This
 * should provide all necessary means to make a correct decision on the authenticity of the video.
 */
typedef struct {
  // Code version used when signing the video.
  char *version_on_signing_side;
  // Code version used when validating the authenticity.
  char *this_version;
  // Information about the product provided in a struct.
  signed_video_product_info_t product_info;
  // Holds the information of the latest validation.
  signed_video_latest_validation_t latest_validation;
  // Holds the information of the total validation since the first added Bitstream Unit.
  signed_video_accumulated_validation_t accumulated_validation;
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
 * @return A copy of the latest authenticity report
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
 *     SignedVideoReturnCode status = signed_video_add_nalu_and_authenticate(sv, bu_data,
 *         bu_data_size, &auth_report);
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
 * @brief Add Bitstream Unit data to the session and get an authentication report
 *
 * This function should be called for each codec specific Bitstream Unit (BU) the user
 * receives. A Bitstream Unit is a NALU for H.26x and an OBU for AV1. It is assumed that
 * |bu_data| consists of one single Bitstream Unit including Start Code for H.26x, so
 * that BU type can be parsed. That is, the format for H.26x should look like this:
 *
 * |------------|------|
 * | Start Code | NALU |
 * |------------|------|
 *  3 or 4 bytes       ^
 *                     Including stop bit
 *
 * @note: NALUs sent into the API cannot be in packetized format (access units)!
 * The access unit has to be split into NALUs if so.
 * @note: AV1 does not have start codes.
 *
 * The input |bu_data| is not changed by this call. Note that it is assumed that ALL
 * BUs are passed to this function. Otherwise, they will be treated as missing/lost
 * packets which may affect the validation.
 *
 * Signatures are sent on a regular basis. Currently this is done at the end of each GOP
 * (Group Of Pictures). For every input |bu_data| with a signature, or when a signature is
 * expected, validation is performed and a copy of the |authenticity| result is provided.
 * If a BU does not trigger a validation, |authenticity| is a NULL pointer. If one BU is
 * lost or tampered with within a GOP, the whole GOP is marked as NOT OK, even if the
 * other Bs are correct.
 *
 * The user should continuously check the return value for errors and upon success check
 * |authenticity| for a new report.
 * Two typical use cases are; 1) live monitoring which could be screening the video until
 * authenticity can no longer be validated OK, and 2) screening a recording and get a full report at
 * the end. In the first case further operations can simply be aborted as soon as a validation
 * fails, whereas in the latter case all the Bitstream Units need to be screened.
 * @note: Only the live monitoring use case is currently supported.
 *
 * Example code of usage; See example code above.
 *
 * @param self Pointer to the signed_video_t object to update
 * @param bu_data Pointer to the Bitstream Unit data (H26x NALU or AV1 OBU) to be added
 * @param bu_data_size Size of the |bu_data|
 * @param authenticity Pointer to the autenticity report. Passing in a NULL pointer will not provide
 *     latest validation results. The user is then responsible to get a report using
 *     signed_video_get_authenticity_report(...).
 *
 * @return A Signed Video Return Code (SignedVideoReturnCode)
 */
SignedVideoReturnCode
signed_video_add_nalu_and_authenticate(signed_video_t *self,
    const uint8_t *bu_data,
    size_t bu_data_size,
    signed_video_authenticity_t **authenticity);

/**
 * @brief Sets the public key used to validate the video authenticity
 *
 * For videos where the public key, necessary to verify the signature, is not present in the
 * SEIs/OBU Metadata the user needs to provide that key manually.
 *
 * This function allows the user to add the public key to the current Signed Video session. The
 * operation has to be performed before the session starts. It is not allowed to change the public
 * key on the fly, for which SV_NOT_SUPPORTED is returned.
 *
 * If the public key is added for a session already including a public key in the SEI/OBU Metadata,
 * the key in the SEI/OBU Metadata rules the other key.
 *
 * The |public_key| data is assumed to be in PEM format.
 *
 * @param self Pointer to the current Signed Video session
 * @param public_key Pointer to the public key data
 * @param public_key_size Size of the public key
 *
 * @return A Signed Video Return Code (SignedVideoReturnCode)
 */
SignedVideoReturnCode
signed_video_set_public_key(signed_video_t *self, const char *public_key, size_t public_key_size);

#ifdef __cplusplus
}
#endif

#endif  // __SIGNED_VIDEO_AUTH_H__
