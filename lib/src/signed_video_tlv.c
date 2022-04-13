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
#include "signed_video_tlv.h"

#include <stdlib.h>  // free

#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
#include "axis-communications/sv_vendor_axis_communications_internal.h"
#endif
#include "includes/signed_video_auth.h"  // signed_video_product_info_t
#include "includes/signed_video_interfaces.h"  // signature_info_t, sign_algo_t
#include "includes/signed_video_openssl.h"  // openssl_key_memory_allocated()
#include "signed_video_authenticity.h"  // transfer_product_info()

/**
 * Encoder and decoder interfaces
 */

/**
 * @brief TLV encoder interface
 *
 * @param signed_video_t The Signed Video object to encode.
 * @param data Pointer to the data to write to. If NULL only returns the data size of the data.
 *
 * @returns The size of the data written.
 */
typedef size_t (*sv_tlv_encoder_t)(signed_video_t *, uint8_t *);

/**
 * @brief TLV decoder interface
 *
 * @param data Pointer to the data to decode.
 * @param data_size Size of the data.
 * @param signed_video_t The Signed Video object to write to.
 *
 * @returns SVI_OK if successful otherwise an error code.
 */
typedef svi_rc (*sv_tlv_decoder_t)(signed_video_t *, const uint8_t *, size_t);

/**
 * Declarations of encoder and decoder implementations.
 */
static size_t
encode_general(signed_video_t *self, uint8_t *data);
static svi_rc
decode_general(signed_video_t *self, const uint8_t *data, size_t data_size);

static size_t
encode_public_key(signed_video_t *self, uint8_t *data);
static svi_rc
decode_public_key(signed_video_t *self, const uint8_t *data, size_t data_size);

static size_t
encode_arbitrary_data(signed_video_t *self, uint8_t *data);
static svi_rc
decode_arbitrary_data(signed_video_t *self, const uint8_t *data, size_t data_size);

static size_t
encode_product_info(signed_video_t *self, uint8_t *data);
static svi_rc
decode_product_info(signed_video_t *self, const uint8_t *data, size_t data_size);

static size_t
encode_hash_list(signed_video_t *self, uint8_t *data);
static svi_rc
decode_hash_list(signed_video_t *self, const uint8_t *data, size_t data_size);

static size_t
encode_signature(signed_video_t *self, uint8_t *data);
static svi_rc
decode_signature(signed_video_t *self, const uint8_t *data, size_t data_size);

// Vendor specific encoders and decoders. Serves as wrappers of vendor specific calls with
// |vendor_handle| as input.
static size_t
encode_axis_communications(signed_video_t *self, uint8_t *data);
static svi_rc
decode_axis_communications(signed_video_t *self, const uint8_t *data, size_t data_size);

/**
 * Definition of a TLV tuple associating the TLV Tag with an encoder, a decoder and the number of
 * bytes to represent the Length.
 */
typedef struct {
  sv_tlv_tag_t tag;
  uint8_t bytes_for_length;
  sv_tlv_encoder_t encoder;
  sv_tlv_decoder_t decoder;
  bool is_always_present;
} sv_tlv_tuple_t;

/**
 * This is an array of all available TLV tuples. The first and last tuples, which are invalid tags,
 * have dummy values to avoid the risk of reading outside memory.
 *
 * NOTE: They HAVE TO be in the same order as the available tags!
 *
 * When you add a new tag you have to add the tuple to this array as well.
 */
static const sv_tlv_tuple_t tlv_tuples[] = {
    {UNDEFINED_TAG, 0, NULL, NULL, true},
    {GENERAL_TAG, 1, encode_general, decode_general, true},
    {PUBLIC_KEY_TAG, 2, encode_public_key, decode_public_key, false},
    {PRODUCT_INFO_TAG, 2, encode_product_info, decode_product_info, false},
    {HASH_LIST_TAG, 2, encode_hash_list, decode_hash_list, true},
    {SIGNATURE_TAG, 2, encode_signature, decode_signature, true},
    {ARBITRARY_DATA_TAG, 2, encode_arbitrary_data, decode_arbitrary_data, true},
    {NUMBER_OF_TLV_TAGS, 0, NULL, NULL, true},
};

/**
 * This is an array of all available Vendor TLV tuples. The first and last tuples, which are
 * invalid tags, have dummy values to avoid the risk of reading outside memory.
 * The tuples are offset with UNDEFINED_VENDOR_TAG since they start at UNDEFINED_VENDOR_TAG in
 * sv_tlv_tag_t.
 *
 * NOTE: They HAVE TO be in the same order as the available tags!
 *
 * When you add a new vendor tag you have to add the tuple to this array as well.
 */
static const sv_tlv_tuple_t vendor_tlv_tuples[] = {
    {UNDEFINED_VENDOR_TAG, 0, NULL, NULL, true},
    {VENDOR_AXIS_COMMUNICATIONS_TAG, 2, encode_axis_communications, decode_axis_communications,
        false},
    {NUMBER_OF_VENDOR_TLV_TAGS, 0, NULL, NULL, true},
};

/**
 * Declarations of STATIC functions.
 */
static sv_tlv_decoder_t
get_decoder(sv_tlv_tag_t tag);
static sv_tlv_tuple_t
get_tlv_tuple(sv_tlv_tag_t tag);
static svi_rc
decode_tlv_header(const uint8_t *data, size_t *read_data_bytes, sv_tlv_tag_t *tag, size_t *length);

/* Selects and returns the correct decoder from either |tlv_tuples| or |vendor_tlv_tuples|. */
static sv_tlv_decoder_t
get_decoder(sv_tlv_tag_t tag)
{
  if (tag > UNDEFINED_VENDOR_TAG) {
    // Vendor tag.
    return vendor_tlv_tuples[tag - UNDEFINED_VENDOR_TAG].decoder;
  } else {
    // Library tag.
    return tlv_tuples[tag].decoder;
  }
}

/* Selects and returns the correct tlv_tuple from either |tlv_tuples| or |vendor_tlv_tuples|. */
static sv_tlv_tuple_t
get_tlv_tuple(sv_tlv_tag_t tag)
{
  if ((tag > UNDEFINED_TAG) && (tag < NUMBER_OF_TLV_TAGS)) {
    // Library tag.
    return tlv_tuples[tag];
  } else if ((tag > UNDEFINED_VENDOR_TAG) && (tag < NUMBER_OF_VENDOR_TLV_TAGS)) {
    // Vendor tag.
    return vendor_tlv_tuples[tag - UNDEFINED_VENDOR_TAG];
  } else {
    // Unknown tag.
    return tlv_tuples[UNDEFINED_TAG];
  }
}

/**
 * @brief Encodes the GENERAL_TAG into data
 */
static size_t
encode_general(signed_video_t *self, uint8_t *data)
{
  gop_info_t *gop_info = self->gop_info;
  size_t data_size = 0;
  uint32_t gop_counter = gop_info->global_gop_counter + 1;
  uint16_t num_nalus_in_gop_hash = gop_info->num_nalus_in_gop_hash;
  const uint8_t version = 1;

  // Get size of data
  data_size += sizeof(version);
  data_size += sizeof(gop_counter);
  data_size += sizeof(num_nalus_in_gop_hash);
  data_size += SV_VERSION_BYTES;

  if (!data) {
    DEBUG_LOG("Returning computed size %zu", data_size);
    return data_size;
  }

  DEBUG_LOG("Encoding GOP counter = %u", gop_counter);

  uint8_t *data_ptr = data;
  uint16_t *last_two_bytes = &self->last_two_bytes;
  // Fill Camera Info data
  // Version
  write_byte(last_two_bytes, &data_ptr, version, true);
  // GOP counter; 4 bytes
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((gop_counter >> 24) & 0x000000ff), true);
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((gop_counter >> 16) & 0x000000ff), true);
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((gop_counter >> 8) & 0x000000ff), true);
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((gop_counter)&0x000000ff), true);
  // Write num_nalus_in_gop_hash; 2 bytes
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((num_nalus_in_gop_hash >> 8) & 0x00ff), true);
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((num_nalus_in_gop_hash)&0x00ff), true);

  for (int i = 0; i < SV_VERSION_BYTES; i++) {
    write_byte(last_two_bytes, &data_ptr, (uint8_t)self->code_version[i], true);
  }

  gop_info->global_gop_counter = gop_counter;

  return (data_ptr - data);
}

/**
 * @brief Decodes the GENERAL_TAG from data
 */
static svi_rc
decode_general(signed_video_t *self, const uint8_t *data, size_t data_size)
{
  if (!self || !data) return SVI_INVALID_PARAMETER;

  const uint8_t *data_ptr = data;
  gop_info_t *gop_info = self->gop_info;
  uint8_t version = *data_ptr++;
  svi_rc status = SVI_UNKNOWN;

  SVI_TRY()
    SVI_THROW_IF(version == 0, SVI_INCOMPATIBLE_VERSION);

    data_ptr += read_32bits(data_ptr, &gop_info->global_gop_counter);
    DEBUG_LOG("Found GOP counter = %u", gop_info->global_gop_counter);
    data_ptr += read_16bits(data_ptr, &gop_info->num_sent_nalus);
    DEBUG_LOG("Number of sent NALUs = %u", gop_info->num_sent_nalus);

    for (int i = 0; i < SV_VERSION_BYTES; i++) {
      self->code_version[i] = *data_ptr++;
    }
    bytes_to_version_str(self->code_version, self->authenticity->version_on_signing_side);

    SVI_THROW_IF(data_ptr != data + data_size, SVI_DECODING_ERROR);
  SVI_CATCH()
  SVI_DONE(status)

  return status;
}

void
write_byte_many(uint8_t **dest,
    char *src,
    size_t size,
    uint16_t *last_two_bytes,
    bool do_emulation_prevention)
{
  if (!src) return;

  for (size_t ii = 0; ii < size; ++ii) {
    uint8_t ch = src[ii];
    write_byte(last_two_bytes, dest, ch, do_emulation_prevention);
  }
}

/**
 * @brief Encodes the PRODUCT_INFO_TAG into data
 *
 * @param self Session struct
 * @param data Location to write TLV into payload
 */
static size_t
encode_product_info(signed_video_t *self, uint8_t *data)
{
  signed_video_product_info_t *product_info = self->product_info;
  size_t data_size = 0;
  const uint8_t version = 1;
  const uint8_t kFullByte = 255;

  // Version 1:
  //  - version (1 byte)
  //  - hardware_id_size (1 byte)
  //  - hardware_id
  //  - firmware_version
  //  - firmware_version_size (1 byte)
  //  - serial_number
  //  - serial_number_size (1 byte)
  //  - manufacturer
  //  - manufacturer_size (1 byte)
  //  - address
  //  - address_size (1 byte)

  data_size += sizeof(version);

  // Determine sizes including null-terminated character and truncate to fit in one byte.
  data_size += 1;
  size_t hardware_id_size = product_info->hardware_id ? strlen(product_info->hardware_id) + 1 : 1;
  bool hardware_id_too_long = (hardware_id_size > kFullByte);
  const uint8_t hardware_id_size_onebyte =
      hardware_id_too_long ? kFullByte : (uint8_t)hardware_id_size;
  data_size += hardware_id_size_onebyte;

  data_size += 1;
  size_t firmware_version_size =
      product_info->firmware_version ? strlen(product_info->firmware_version) + 1 : 1;
  bool firmware_version_too_long = (firmware_version_size > kFullByte);
  const uint8_t firmware_version_size_onebyte =
      firmware_version_too_long ? kFullByte : (uint8_t)firmware_version_size;
  data_size += firmware_version_size_onebyte;

  data_size += 1;
  size_t serial_number_size =
      product_info->serial_number ? strlen(product_info->serial_number) + 1 : 1;
  bool serial_number_too_long = (serial_number_size > kFullByte);
  const uint8_t serial_number_size_onebyte =
      serial_number_too_long ? kFullByte : (uint8_t)serial_number_size;
  data_size += serial_number_size_onebyte;

  data_size += 1;
  size_t manufacturer_size =
      product_info->manufacturer ? strlen(product_info->manufacturer) + 1 : 1;
  bool manufacturer_too_long = (manufacturer_size > kFullByte);
  const uint8_t manufacturer_size_onebyte =
      manufacturer_too_long ? kFullByte : (uint8_t)manufacturer_size;
  data_size += manufacturer_size_onebyte;

  data_size += 1;
  size_t address_size = product_info->address ? strlen(product_info->address) + 1 : 1;
  bool address_too_long = (address_size > kFullByte);
  const uint8_t address_size_onebyte = address_too_long ? kFullByte : (uint8_t)address_size;
  data_size += address_size_onebyte;

  if (!data) return data_size;

  uint8_t *data_ptr = data;
  uint16_t *last_two_bytes = &self->last_two_bytes;
  uint8_t str_end_byte = '\0';
  // Version
  write_byte(last_two_bytes, &data_ptr, version, true);

  // Write |hardware_id|.
  write_byte(last_two_bytes, &data_ptr, hardware_id_size_onebyte, true);
  // Write all but the last character.
  write_byte_many(
      &data_ptr, product_info->hardware_id, hardware_id_size_onebyte - 1, last_two_bytes, true);
  // Determine and write the last character.
  str_end_byte = (hardware_id_too_long || !product_info->hardware_id)
      ? '\0'
      : product_info->hardware_id[hardware_id_size_onebyte - 1];
  write_byte(last_two_bytes, &data_ptr, str_end_byte, true);

  // Write |firmware_version|.
  write_byte(last_two_bytes, &data_ptr, firmware_version_size_onebyte, true);
  // Write all but the last character.
  write_byte_many(&data_ptr, product_info->firmware_version, firmware_version_size_onebyte - 1,
      last_two_bytes, true);
  // Determine and write the last character.
  str_end_byte = (firmware_version_too_long || !product_info->firmware_version)
      ? '\0'
      : product_info->firmware_version[firmware_version_size_onebyte - 1];
  write_byte(last_two_bytes, &data_ptr, str_end_byte, true);

  // Write |serial_number|.
  write_byte(last_two_bytes, &data_ptr, serial_number_size_onebyte, true);
  // Write all but the last character.
  write_byte_many(
      &data_ptr, product_info->serial_number, serial_number_size_onebyte - 1, last_two_bytes, true);
  // Determine and write the last character.
  str_end_byte = (serial_number_too_long || !product_info->serial_number)
      ? '\0'
      : product_info->serial_number[serial_number_size_onebyte - 1];
  write_byte(last_two_bytes, &data_ptr, str_end_byte, true);

  // Write |manufacturer|.
  write_byte(last_two_bytes, &data_ptr, manufacturer_size_onebyte, true);
  // Write all but the last character.
  write_byte_many(
      &data_ptr, product_info->manufacturer, manufacturer_size_onebyte - 1, last_two_bytes, true);
  // Determine and write the last character.
  str_end_byte = (manufacturer_too_long || !product_info->manufacturer)
      ? '\0'
      : product_info->manufacturer[manufacturer_size_onebyte - 1];
  write_byte(last_two_bytes, &data_ptr, str_end_byte, true);

  // Write |address|.
  write_byte(last_two_bytes, &data_ptr, address_size_onebyte, true);
  // Write all but the last character.
  write_byte_many(&data_ptr, product_info->address, address_size_onebyte - 1, last_two_bytes, true);
  // Determine and write the last character.
  str_end_byte = (address_too_long || !product_info->address)
      ? '\0'
      : product_info->address[address_size_onebyte - 1];
  write_byte(last_two_bytes, &data_ptr, str_end_byte, true);

  return (data_ptr - data);
}

/**
 * @brief Decodes the PRODUCT_INFO_TAG from data
 *
 * @param data Payload to write to
 * @param data_size Size of this TLV
 * @param self Session struct
 */
static svi_rc
decode_product_info(signed_video_t *self, const uint8_t *data, size_t data_size)
{
  const uint8_t *data_ptr = data;
  uint8_t version = *data_ptr++;
  svi_rc status = SVI_UNKNOWN;

  if (!self || !self->product_info) return SVI_NULL_PTR;

  SVI_TRY()
    SVI_THROW_IF(version == 0, SVI_INCOMPATIBLE_VERSION);

    signed_video_product_info_t *product_info = self->product_info;

    uint8_t hardware_id_size = *data_ptr++;
    SVI_THROW(allocate_memory_and_copy_string(&product_info->hardware_id, (const char *)data_ptr));
    data_ptr += hardware_id_size;

    uint8_t firmware_version_size = *data_ptr++;
    SVI_THROW(
        allocate_memory_and_copy_string(&product_info->firmware_version, (const char *)data_ptr));
    data_ptr += firmware_version_size;

    uint8_t serial_number_size = *data_ptr++;
    SVI_THROW(
        allocate_memory_and_copy_string(&product_info->serial_number, (const char *)data_ptr));
    data_ptr += serial_number_size;

    uint8_t manufacturer_size = *data_ptr++;
    SVI_THROW(allocate_memory_and_copy_string(&product_info->manufacturer, (const char *)data_ptr));
    data_ptr += manufacturer_size;

    uint8_t address_size = *data_ptr++;
    SVI_THROW(allocate_memory_and_copy_string(&product_info->address, (const char *)data_ptr));
    data_ptr += address_size;

    // Transfer the decoded |product_info| to the authenticity report.
    SVI_THROW(transfer_product_info(&self->authenticity->product_info, product_info));

    SVI_THROW_IF(data_ptr != data + data_size, SVI_DECODING_ERROR);

  SVI_CATCH()
  SVI_DONE(status)

  return status;
}

/**
 * @brief Encodes the ARBITRARY_DATA_TAG into data
 *
 */
static size_t
encode_arbitrary_data(signed_video_t *self, uint8_t *data)
{
  size_t data_size = 0;
  const uint8_t version = 1;

  if (!self->arbitrary_data || self->arbitrary_data_size == 0) return 0;

  data_size += sizeof(version);

  // Size of arbitrary_data
  data_size += self->arbitrary_data_size;

  if (!data) return data_size;

  uint8_t *data_ptr = data;
  uint16_t *last_two_bytes = &self->last_two_bytes;
  // Version
  write_byte(last_two_bytes, &data_ptr, version, true);

  for (size_t ii = 0; ii < self->arbitrary_data_size; ++ii) {
    write_byte(last_two_bytes, &data_ptr, self->arbitrary_data[ii], true);
  }

  return (data_ptr - data);
}

/**
 * @brief Decodes the ARBITRARY_DATA_TAG from data
 *
 */
static svi_rc
decode_arbitrary_data(signed_video_t *self, const uint8_t *data, size_t data_size)
{
  const uint8_t *data_ptr = data;
  uint8_t version = *data_ptr++;
  uint16_t arbdata_size = (uint16_t)(data_size - 1);
  svi_rc status = SVI_UNKNOWN;

  SVI_TRY()
    SVI_THROW_IF(version == 0, SVI_INCOMPATIBLE_VERSION);
    SVI_THROW_IF(arbdata_size == 0, SVI_DECODING_ERROR);
    uint8_t *arbdata = realloc(self->arbitrary_data, arbdata_size);
    SVI_THROW_IF(!arbdata, SVI_MEMORY);
    memcpy(arbdata, data_ptr, arbdata_size);
    self->arbitrary_data = arbdata;
    self->arbitrary_data_size = arbdata_size;
    data_ptr += arbdata_size;
    SVI_THROW_IF(data_ptr != data + data_size, SVI_DECODING_ERROR);
  SVI_CATCH()
  {
    free(self->arbitrary_data);
    self->arbitrary_data = NULL;
    self->arbitrary_data_size = 0;
  }
  SVI_DONE(status)

  return status;
}
/**
 * @brief Encodes the PUBLIC_KEY_TAG into data
 *
 */
static size_t
encode_public_key(signed_video_t *self, uint8_t *data)
{
  signature_info_t *signature_info = self->signature_info;
  size_t data_size = 0;
  const uint8_t version = 1;

  // If there is no public key, skip encoding, that is return 0.
  if (!signature_info->public_key || !self->public_key_in_sei) return 0;

  // Version 1:
  //  - version (1 byte)
  //  - public_key
  //
  // Note that we do not have to store the size of the public. We already know it from the TLV
  // length.

  data_size += sizeof(version);
  // Casting enum to uint8_t
  data_size += sizeof((uint8_t)signature_info->algo);

  // Size of pubkey
  data_size += signature_info->public_key_size;

  if (!data) return data_size;

  uint8_t *data_ptr = data;
  uint16_t *last_two_bytes = &self->last_two_bytes;
  uint8_t *public_key = signature_info->public_key;

  // Fill Camera Info data
  // Version
  write_byte(last_two_bytes, &data_ptr, version, true);
  write_byte(last_two_bytes, &data_ptr, signature_info->algo, true);

  // public_key; public_key_size (451) bytes
  for (size_t ii = 0; ii < signature_info->public_key_size; ++ii) {
    write_byte(last_two_bytes, &data_ptr, public_key[ii], true);
  }

  return (data_ptr - data);
}

/**
 * @brief Decodes the PUBLIC_KEY_TAG from data
 *
 */
static svi_rc
decode_public_key(signed_video_t *self, const uint8_t *data, size_t data_size)
{
  const uint8_t *data_ptr = data;
  signature_info_t *signature_info = self->signature_info;
  uint8_t version = *data_ptr++;
  sign_algo_t algo = *data_ptr++;
  uint16_t pubkey_size = (uint16_t)(data_size - 2);  // We only store version, algo and the key.

  svi_rc status = SVI_UNKNOWN;

  SVI_TRY()
    SVI_THROW_IF(version == 0, SVI_INCOMPATIBLE_VERSION);
    SVI_THROW_IF(pubkey_size == 0, SVI_OK);
    SVI_THROW_IF(algo < SIGN_ALGO_RSA || algo >= SIGN_ALGO_NUM, SVI_DECODING_ERROR);

    SVI_THROW(sv_rc_to_svi_rc(openssl_key_memory_allocated(
        &signature_info->public_key, &signature_info->public_key_size, pubkey_size)));

    if (self->has_public_key && memcmp(data_ptr, signature_info->public_key, pubkey_size)) {
      self->latest_validation->public_key_has_changed = true;
    }
    memcpy(signature_info->public_key, data_ptr, pubkey_size);
    self->has_public_key = true;
    data_ptr += pubkey_size;

    SVI_THROW_IF(data_ptr != data + data_size, SVI_DECODING_ERROR);
    self->signature_info->algo = algo;
  SVI_CATCH()
  SVI_DONE(status)

  return status;
}

/**
 * @brief Encodes the HASH_LIST_TAG into data
 *
 */
static size_t
encode_hash_list(signed_video_t *self, uint8_t *data)
{
  gop_info_t *gop_info = self->gop_info;
  size_t data_size = 0;
  const uint8_t version = 1;  // Increment when the change breaks the format

  // If the |hash_list| is empty, or invalid, skip encoding, that is, return 0. Also, if we do not
  // use SV_AUTHENTICITY_LEVEL_FRAME skip encoding.
  if (gop_info->list_idx <= 0 || self->authenticity_level != SV_AUTHENTICITY_LEVEL_FRAME) return 0;

  // Version 1:
  // - version (1 byte)
  // - hash_list (list_idx bytes)
  data_size += sizeof(version);
  data_size += gop_info->list_idx * sizeof(gop_info->hash_list[0]);

  if (!data) return data_size;

  uint8_t *data_ptr = data;
  uint16_t *last_two_bytes = &self->last_two_bytes;
  // Write version
  write_byte(last_two_bytes, &data_ptr, version, true);
  // Write hash_list data
  for (int i = 0; i < gop_info->list_idx; i++) {
    write_byte(last_two_bytes, &data_ptr, gop_info->hash_list[i], true);
  }

  // Having successfully encoded the hash_list means we should sign the document_hash and not the
  // gop_hash.
  self->gop_info->signature_hash_type = DOCUMENT_HASH;

  return (data_ptr - data);
}

/**
 * @brief Decodes the HASH_LIST_TAG from data
 *
 */
static svi_rc
decode_hash_list(signed_video_t *self, const uint8_t *data, size_t data_size)
{
  const uint8_t *data_ptr = data;
  uint8_t version = *data_ptr++;
  size_t hash_list_size = data_size - (data_ptr - data);

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    SVI_THROW_IF(version == 0, SVI_INCOMPATIBLE_VERSION);
    SVI_THROW_IF_WITH_MSG(
        hash_list_size > HASH_LIST_SIZE, SVI_MEMORY, "Found more hashes than fit in hash_list");
    memcpy(self->gop_info->hash_list, data_ptr, hash_list_size);
    self->gop_info->list_idx = (int)hash_list_size;

    data_ptr += hash_list_size;

    SVI_THROW_IF(data_ptr != data + data_size, SVI_DECODING_ERROR);

  SVI_CATCH()
  SVI_DONE(status)

  return status;
}

/**
 * @brief Encodes the SIGNATURE_TAG into data
 *
 */
static size_t
encode_signature(signed_video_t *self, uint8_t *data)
{
  gop_info_t *gop_info = self->gop_info;
  signature_info_t *signature_info = self->signature_info;
  size_t data_size = 0;
  const uint8_t version = 1;  // Increment when the change breaks the format

  // TODO: Signaling which type of hash that was signed can be put in the info field with a bit
  // mask. Also, if the document hash was signed, there is no need to transmit the gop_hash init
  // value. Let us fix this when we have all functionality in place and want to reduce the bitrate.
  // For now it is better to have a clear and readable structure.

  // Version 1:
  //  - version (1 byte)
  //  - info field (1 byte)
  //  - hash type (1 byte)
  //  - signature size (2 bytes)
  //  - signed hash (256 bytes)

  data_size += sizeof(version);
  // Info field. This field holds information on whether the GOP info was correctly created or if
  // there were errors. This means that the authenticator is informed what can be verified and what
  // cannot.

  data_size += sizeof(gop_info->encoding_status);  // Info field
  data_size += 1;  // hash type
  data_size += 2;  // 2 bytes to store the actual size of the signature.
  data_size += signature_info->max_signature_size;  // Allocated size of the signature

  if (!data) return data_size;

  uint8_t *data_ptr = data;
  uint16_t *last_two_bytes = &self->last_two_bytes;
  uint16_t signature_size = (uint16_t)signature_info->signature_size;
  // Write version
  write_byte(last_two_bytes, &data_ptr, version, true);
  // Write info field
  write_byte(last_two_bytes, &data_ptr, gop_info->encoding_status, true);
  // Write hash type
  write_byte(last_two_bytes, &data_ptr, (uint8_t)gop_info->signature_hash_type, true);
  // Write actual signature size (2 bytes)
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((signature_size >> 8) & 0x00ff), true);
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((signature_size)&0x00ff), true);
  // Write signature
  size_t i = 0;
  for (; i < signature_info->signature_size; i++) {
    write_byte(last_two_bytes, &data_ptr, signature_info->signature[i], true);
  }
  for (; i < signature_info->max_signature_size; i++) {
    // Write 1's in the unused bytes to avoid emulation prevention bytes.
    write_byte(last_two_bytes, &data_ptr, 1, true);
  }

  return (data_ptr - data);
}

/**
 * @brief Decodes the SIGNATURE_TAG from data
 *
 */
static svi_rc
decode_signature(signed_video_t *self, const uint8_t *data, size_t data_size)
{
  const uint8_t *data_ptr = data;
  gop_info_t *gop_info = self->gop_info;
  signature_info_t *signature_info = self->signature_info;
  uint8_t **signature_ptr = &signature_info->signature;
  uint8_t version = *data_ptr++;
  uint8_t encoding_status = *data_ptr++;
  hash_type_t hash_type = *data_ptr++;
  uint16_t signature_size = 0;
  size_t max_signature_size = 0;

  // Read true size of the signature.
  data_ptr += read_16bits(data_ptr, &signature_size);
  // The rest should now be the allocated size for the signature.
  max_signature_size = data_size - (data_ptr - data);

  svi_rc status = SVI_UNKNOWN;

  SVI_TRY()
    SVI_THROW_IF(version == 0, SVI_INCOMPATIBLE_VERSION);
    SVI_THROW_IF(hash_type < 0 || hash_type >= NUM_HASH_TYPES, SVI_DECODING_ERROR);
    SVI_THROW_IF(max_signature_size < signature_size, SVI_DECODING_ERROR);
    if (!*signature_ptr) {
      signature_info->max_signature_size = 0;
      signature_info->signature_size = 0;
      // Allocate enough space for future signatures as well, that is, max_signature_size.
      *signature_ptr = sv_interface_malloc(max_signature_size);
      SVI_THROW_IF(!*signature_ptr, SVI_MEMORY);
      // Set memory size.
      signature_info->max_signature_size = max_signature_size;
    }
    SVI_THROW_IF(signature_info->max_signature_size != max_signature_size, SVI_MEMORY);
    memcpy(*signature_ptr, data_ptr, max_signature_size);
    data_ptr += max_signature_size;

    // Set true signature size.
    signature_info->signature_size = signature_size;
    gop_info->encoding_status = encoding_status;
    gop_info->signature_hash_type = hash_type;
    SVI_THROW_IF(data_ptr != data + data_size, SVI_DECODING_ERROR);
  SVI_CATCH()
  SVI_DONE(status)

  return status;
}

// Vendor specific encoders and decoders.

/**
 * @brief Encodes the VENDOR_AXIS_COMMUNICATIONS_TAG into data
 *
 */
static size_t
#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
encode_axis_communications(signed_video_t *self, uint8_t *data)
{
  return encode_axis_communications_handle(self->vendor_handle, &self->last_two_bytes, data);
#else
encode_axis_communications(signed_video_t ATTR_UNUSED *self, uint8_t ATTR_UNUSED *data)
{
  // Vendor Axis Communications not selected.
  return 0;
#endif
}

/**
 * @brief Decodes the VENDOR_AXIS_COMMUNICATIONS_TAG from data
 *
 */
static svi_rc
#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
decode_axis_communications(signed_video_t *self, const uint8_t *data, size_t data_size)
{
  return decode_axis_communications_handle(self->vendor_handle, data, data_size);
#else
decode_axis_communications(signed_video_t ATTR_UNUSED *self,
    const uint8_t ATTR_UNUSED *data,
    size_t ATTR_UNUSED data_size)
{
  // Vendor Axis Communications not selected.
  return SVI_NOT_SUPPORTED;
#endif
}

static size_t
tlv_encode_or_get_size_generic(signed_video_t *self, const sv_tlv_tuple_t tlv, uint8_t *data)
{
  size_t tl_size = 0;
  size_t v_size = 0;

  // TLV:
  //  - tag (1 byte)
  //  - length (1 or 2 bytes)
  //  - value (variable, dependent on encoder/decoder)

  tl_size += 1;
  tl_size += tlv.bytes_for_length;
  v_size = tlv.encoder(self, NULL);

  if (v_size == 0) {
    // If there is no data to encode, there is no point in transmitting an empty tag.
    DEBUG_LOG("Tag %u is without payload", tlv.tag);
    return 0;
  }

  if (!data) {
    DEBUG_LOG("Tag %u is of total size %zu", tlv.tag, tl_size + v_size);
    return tl_size + v_size;
  }

  uint8_t *data_ptr = data;
  uint16_t *last_two_bytes = &self->last_two_bytes;
  // Write Tag
  write_byte(last_two_bytes, &data_ptr, (uint8_t)tlv.tag, true);
  // Write length
  if (tlv.bytes_for_length == 2) {
    write_byte(last_two_bytes, &data_ptr, (uint8_t)((v_size >> 8) & 0x000000ff), true);
  }
  write_byte(last_two_bytes, &data_ptr, (uint8_t)(v_size & 0x000000ff), true);

  // Write value, i.e. the actual data of the TLV
  size_t v_size_written = tlv.encoder(self, data_ptr);

  if (v_size_written < v_size) {
    DEBUG_LOG("Written size %zu < %zu computed size", v_size_written, v_size);
    return 0;
  }
  data_ptr += v_size_written;

  return data_ptr - data;
}

size_t
tlv_list_encode_or_get_size(signed_video_t *self,
    const sv_tlv_tag_t *tags,
    size_t num_tags,
    uint8_t *data)
{
  if (!self || !tags || !num_tags) return SVI_INVALID_PARAMETER;

  size_t tlv_list_size = 0;
  uint8_t *data_ptr = data;

  for (size_t ii = 0; ii < num_tags; ++ii) {
    sv_tlv_tag_t tag = tags[ii];
    sv_tlv_tuple_t tlv = get_tlv_tuple(tag);
    if (tlv.tag != tag) {
      DEBUG_LOG("Did not find TLV tuple from tag (%d)", tag);
      continue;
    }

    if (tlv.is_always_present || self->has_recurrent_data) {
      size_t tlv_size = tlv_encode_or_get_size_generic(self, tlv, data_ptr);
      tlv_list_size += tlv_size;
      // Increment data_ptr if we're writing data
      if (data) data_ptr += tlv_size;
    }
  }
  return tlv_list_size;
}

static svi_rc
decode_tlv_header(const uint8_t *data, size_t *read_data_bytes, sv_tlv_tag_t *tag, size_t *length)
{
  // Sanity checks on input parameters.
  if (!data || !read_data_bytes || !tag || !length) return SVI_INVALID_PARAMETER;

  const uint8_t *data_ptr = data;
  sv_tlv_tag_t tag_from_data = (sv_tlv_tag_t)(*data_ptr++);
  *read_data_bytes = 0;
  sv_tlv_tuple_t tlv = get_tlv_tuple(tag_from_data);
  if (tlv.tag != tag_from_data) {
    DEBUG_LOG("Parsed an invalid tag (%d) in the data", tag_from_data);
    return SVI_INVALID_PARAMETER;
  }
  *tag = tag_from_data;

  if (tlv.bytes_for_length == 2) {
    data_ptr += read_16bits(data_ptr, (uint16_t *)length);
  } else {
    *length = *data_ptr++;
  }

  *read_data_bytes = (data_ptr - data);

  return SVI_OK;
}

svi_rc
tlv_decode(signed_video_t *self, const uint8_t *data, size_t data_size)
{
  svi_rc status = SVI_INVALID_PARAMETER;
  const uint8_t *data_ptr = data;

  if (!self || !data || data_size == 0) return SVI_INVALID_PARAMETER;

  while (data_ptr < data + data_size) {
    sv_tlv_tag_t tag = 0;
    size_t tlv_header_size = 0;
    size_t length = 0;
    status = decode_tlv_header(data_ptr, &tlv_header_size, &tag, &length);
    if (status != SVI_OK) {
      DEBUG_LOG("Could not decode TLV header (error %d)", status);
      break;
    }
    data_ptr += tlv_header_size;

    sv_tlv_decoder_t decoder = get_decoder(tag);
    status = decoder(self, data_ptr, length);
    if (status != SVI_OK) {
      DEBUG_LOG("Could not decode data (error %d)", status);
      break;
    }
    data_ptr += length;
  }

  return status;
}

const uint8_t *
tlv_find_tag(const uint8_t *tlv_data, size_t tlv_data_size, sv_tlv_tag_t tag, bool with_ep)
{
  const uint8_t *tlv_data_ptr = tlv_data;
  const uint8_t *latest_tag_location = NULL;

  if (!tlv_data || tlv_data_size == 0) return 0;

  uint16_t last_two_bytes = LAST_TWO_BYTES_INIT_VALUE;
  while (tlv_data_ptr < tlv_data + tlv_data_size) {
    latest_tag_location = tlv_data_ptr;
    // Read the tag
    sv_tlv_tag_t this_tag = read_byte(&last_two_bytes, &tlv_data_ptr, with_ep);
    if (this_tag == tag) return latest_tag_location;

    // Read the length
    uint16_t length = read_byte(&last_two_bytes, &tlv_data_ptr, with_ep);
    sv_tlv_tuple_t tlv = get_tlv_tuple(this_tag);
    if (tlv.bytes_for_length == 2) {
      length <<= 8;
      length |= read_byte(&last_two_bytes, &tlv_data_ptr, with_ep);
    }
    // Scan past the data
    for (int i = 0; i < length; i++) {
      read_byte(&last_two_bytes, &tlv_data_ptr, with_ep);
    }
  }
  DEBUG_LOG("Never found the tag");

  return NULL;
}

bool
tlv_find_and_decode_recurrent_tags(signed_video_t *self,
    const uint8_t *tlv_data,
    size_t tlv_data_size)
{
  const uint8_t *tlv_data_ptr = tlv_data;

  if (!self || !tlv_data || tlv_data_size == 0) return false;

  svi_rc status = SVI_UNKNOWN;
  bool recurrent_tags_decoded = false;
  while (tlv_data_ptr < tlv_data + tlv_data_size) {
    size_t tlv_header_size = 0;
    size_t length = 0;
    sv_tlv_tag_t this_tag = UNDEFINED_TAG;
    status = decode_tlv_header(tlv_data_ptr, &tlv_header_size, &this_tag, &length);
    if (status != SVI_OK) {
      DEBUG_LOG("Could not decode tlv header");
      break;
    }
    tlv_data_ptr += tlv_header_size;
    if (!tlv_tuples[this_tag].is_always_present) {
      sv_tlv_decoder_t decoder = get_decoder(this_tag);
      status = decoder(self, tlv_data_ptr, length);
      if (status != SVI_OK) {
        DEBUG_LOG("Could not decode");
        break;
      }
      recurrent_tags_decoded = true;
    }
    tlv_data_ptr += length;
  }

  return recurrent_tags_decoded;
}

size_t
read_32bits(const uint8_t *p, uint32_t *val)
{
  if (!p || !val) return 0;
  *val = (uint32_t)(p[0] << 24);
  *val += (uint32_t)(p[1] << 16);
  *val += (uint32_t)(p[2] << 8);
  *val += (uint32_t)(p[3]);

  return 4;
}

size_t
read_16bits(const uint8_t *p, uint16_t *val)
{
  if (!p || !val) return 0;
  *val = (uint16_t)(p[0] << 8);
  *val += (uint16_t)(p[1]);

  return 2;
}

void
write_byte(uint16_t *last_two_bytes,
    uint8_t **data,
    uint8_t curr_byte,
    bool do_emulation_prevention)
{
  if (do_emulation_prevention && (curr_byte & (~0x03)) == 0 && *last_two_bytes == 0) {
    // Emulation prevention adds 0x03
    **data = 0x03;
    (*data)++;
    *last_two_bytes <<= 8;
    *last_two_bytes |= 0x0003;
  }

  **data = curr_byte;
  (*data)++;
  *last_two_bytes <<= 8;
  *last_two_bytes |= (uint16_t)curr_byte;
}

uint8_t
read_byte(uint16_t *last_two_bytes, const uint8_t **data, bool do_emulation_prevention)
{
  uint8_t curr_byte = **data;
  if (do_emulation_prevention && curr_byte == 0x03 && *last_two_bytes == 0) {
    // Emulation prevention byte (0x03) detected. Move to next byte and return.
    *last_two_bytes <<= 8;
    *last_two_bytes |= (uint16_t)curr_byte;
    (*data)++;
    curr_byte = **data;
  }

  *last_two_bytes <<= 8;
  *last_two_bytes |= (uint16_t)curr_byte;
  (*data)++;

  return curr_byte;
}
