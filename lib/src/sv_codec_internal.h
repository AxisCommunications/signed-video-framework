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
#ifndef __SV_CODEC_INTERNAL__
#define __SV_CODEC_INTERNAL__

#include <stdbool.h>  // bool

#include "sv_defines.h"  // svrc_t
#include "sv_internal.h"  // MAX_HASH_SIZE, validation_flags_t

/*
Common utility functions for parsing and extracting metadata from H264, H265, and AV1 bitstream
units. Used for authentication and signing.*/
/* Returns the payload size for an H264 bitstream unit. */
size_t
h26x_get_payload_size(const uint8_t *data, size_t *payload_size);

/* Parses the H264 NAL unit header and determines the BU type. */
bool
parse_h264_nalu_header(bu_info_t *bu);

/* Parses the H265 NAL unit header and determines the BU type. */
bool
parse_h265_nalu_header(bu_info_t *bu);

/* Returns the payload size for an AV1 bitstream unit. */
size_t
av1_get_payload_size(const uint8_t *data, size_t *payload_size);

/* Parses the AV1 OBU header and determines the BU type. */
bool
parse_av1_obu_header(bu_info_t *obu);

#endif  // __SV_CODEC_INTERNAL__
