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

#ifndef __SIGNED_VIDEO_COMMON_H__
#define __SIGNED_VIDEO_COMMON_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _signed_video_t signed_video_t;

/**
 * @brief Signed Video Return Code
 *
 * The error codes are categorized as
 * -(01-09): hardware issues like memory failure
 * -(10-19): user input errors like invalid parameters
 * -(20-29): internal or external signing errors
 * -(30-39): internal authentication errors
 *     -100: unknown failure
 */
typedef enum {
  SV_OK = 0,  // No error
  SV_MEMORY = -1,  // Memory related failure
  SV_INVALID_PARAMETER = -10,  // Invalid input parameter to function
  SV_NOT_SUPPORTED = -12,  // The operation is not supported
  SV_INCOMPATIBLE_VERSION = -15,  // Incompatible software version
  SV_EXTERNAL_ERROR = -20,  // Failure in external code, e.g., plugin or OpenSSL
  SV_VENDOR_ERROR = -21,  // Failure in vendor specific code
  SV_AUTHENTICATION_ERROR = -30,  // Failure related to validating the authenticity
  SV_UNKNOWN_FAILURE = -100,  // Unknown failure
} SignedVideoReturnCode;

/**
 * Signed Video Codec Type
 *
 * The following codecs are supported. The codec in use when creating the signed video session.
 */
typedef enum { SV_CODEC_H264 = 0, SV_CODEC_H265 = 1, SV_CODEC_NUM } SignedVideoCodec;

/**
 * @brief Creates a new signed video session.
 *
 * Creates a signed_video_t object which the user should keep across the entire streaming session.
 * The user is responsible to free the memory at the end of the session by calling the
 * signed_video_free() function. The returned struct can be used for either signing a video, or
 * validating the authenticity of a video.
 *
 * @param codec The codec used in this session.
 *
 * @returns A pointer to signed_video_t struct, allocated and initialized. A null pointer is
 *          returned if memory could not be allocated.
 */
signed_video_t*
signed_video_create(SignedVideoCodec codec);

/**
 * @brief Frees the memory of the signed_video_t object.
 *
 * All memory allocated to and by the signed_video_t object will be freed. This will affectivly end
 * the signed video session.
 *
 * @param self Pointer to the object which memory to free.
 */
void
signed_video_free(signed_video_t* self);

/**
 * @brief Resets the session to allow for, e.g., scrubbing signed video
 *
 * Resets the session and puts it in a pre-stream state, that is, waiting for a new GOP. Once a new
 * GOP is found the operations start over.
 *
 * For the signing part, this means starting to produce the required SEI-NALUs needed for
 * authentication. For the authentication part, this should be used when scrubbing the video.
 * Otherwise the lib will fail authentication due to skipped NALUs.
 *
 * @param self Signed Video session in use
 *
 * @returns A Signed Video Return Code (SignedVideoReturnCode)
 */
SignedVideoReturnCode
signed_video_reset(signed_video_t* self);

/**
 * @brief Returns the current software version as a null-terminated string.
 *
 * @returns A string with the current software version
 */
const char*
signed_video_get_version();

/**
 * @brief Compares two Signed Video versions
 *
 * @param version1 Version string to compare against |version2|
 * @param version2 Version string to compare against |version1|
 *
 * @returns 0 if |version1| is equal to |version2|
 *          1 if |version1| is newer than |version2|
 *          2 if |version1| is older than |version2|
 *          -1 Failure
 */
int
signed_video_compare_versions(const char* version1, const char* version2);

#ifdef __cplusplus
}
#endif

#endif  // __SIGNED_VIDEO_COMMON_H__
