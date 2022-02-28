/**
 * MIT License
 *
 * Copyright (c) 2022 Axis Communications AB
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

/* This header file includes all Axis Communications internal APIs needed to handle Axis specific
 * data in tests.
 */
#ifndef __SV_VENDOR_AXIS_COMMUNICATIONS_INTERNAL_TESTS_H__
#define __SV_VENDOR_AXIS_COMMUNICATIONS_INTERNAL_TESTS_H__

/**
 * @brief Helper function for tests to set |verify_pubkey_upon_call|
 *
 * This should only be used in tests where complete attestations and certificate_chains may not
 * exist.
 *
 * @param handle Pointer to the Axis Communications struct.
 */
void
verify_axis_communications_public_key_upon_request(void *handle);

#endif  // __SV_VENDOR_AXIS_COMMUNICATIONS_INTERNAL_TESTS_H__
