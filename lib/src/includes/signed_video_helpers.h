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

#ifndef __SIGNED_VIDEO_HELPERS_H__
#define __SIGNED_VIDEO_HELPERS_H__

#include <stdint.h>  // uint8_t
#include <stdlib.h>  // size_t

#include "signed_video_common.h"

/**
 * @brief Parses a Bitstream Unit if it is a SEI/OBU Metadata
 *
 * @param bu A pointer to the Bitstream Unit data
 * @param bu_size Size of the |bu|
 * @param codec Codec for this particular bitstream unit
 *
 * @return True if |bu| is a golden SEI/OBU Metadata
 */
void
signed_video_parse_sei(uint8_t *bu, size_t bu_size, SignedVideoCodec codec);

#endif  // __SIGNED_VIDEO_HELPERS_H__
