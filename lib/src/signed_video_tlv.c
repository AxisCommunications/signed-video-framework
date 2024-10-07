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

#ifdef PRINT_DECODED_SEI
#include <stdio.h>
#endif

#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
#include "axis-communications/sv_vendor_axis_communications_internal.h"
#endif
#include "includes/signed_video_auth.h"  // signed_video_product_info_t
#include "includes/signed_video_openssl.h"  // pem_pkey_t, sign_or_verify_data_t
#include "signed_video_authenticity.h"  // transfer_product_info()
#include "signed_video_openssl_internal.h"  // openssl_public_key_malloc()

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
 * @returns SV_OK if successful otherwise an error code.
 */
typedef svrc_t (*sv_tlv_decoder_t)(signed_video_t *, const uint8_t *, size_t);

/**
 * Declarations of encoder and decoder implementations.
 */
static size_t
encode_general(signed_video_t *self, uint8_t *data);
static svrc_t
decode_general(signed_video_t *self, const uint8_t *data, size_t data_size);

static size_t
encode_public_key(signed_video_t *self, uint8_t *data);
static svrc_t
decode_public_key(signed_video_t *self, const uint8_t *data, size_t data_size);

static size_t
encode_arbitrary_data(signed_video_t *self, uint8_t *data);
static svrc_t
decode_arbitrary_data(signed_video_t *self, const uint8_t *data, size_t data_size);

static size_t
encode_product_info(signed_video_t *self, uint8_t *data);
static svrc_t
decode_product_info(signed_video_t *self, const uint8_t *data, size_t data_size);

static size_t
encode_hash_list(signed_video_t *self, uint8_t *data);
static svrc_t
decode_hash_list(signed_video_t *self, const uint8_t *data, size_t data_size);

static size_t
encode_signature(signed_video_t *self, uint8_t *data);
static svrc_t
decode_signature(signed_video_t *self, const uint8_t *data, size_t data_size);

static size_t
encode_crypto_info(signed_video_t *self, uint8_t *data);
static svrc_t
decode_crypto_info(signed_video_t *self, const uint8_t *data, size_t data_size);

// Vendor specific encoders and decoders. Serves as wrappers of vendor specific calls with
// |vendor_handle| as input.
static size_t
encode_axis_communications(signed_video_t *self, uint8_t *data);
static svrc_t
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
    {CRYPTO_INFO_TAG, 1, encode_crypto_info, decode_crypto_info, false},
    {NUMBER_OF_TLV_TAGS, 0, NULL, NULL, true},
};

/*
 * This is an array that contains only optional tags (not |is_always_present|).
 */
static const sv_tlv_tag_t optional_tags[] = {
    PUBLIC_KEY_TAG,
    PRODUCT_INFO_TAG,
    CRYPTO_INFO_TAG,
};

/*
 * This is an array that contains only mandatory tags (|is_always_present|).
 * Array excludes the SIGNATURE_TAG since it has to be treated separately.
 */
static const sv_tlv_tag_t mandatory_tags[] = {
    GENERAL_TAG,
    HASH_LIST_TAG,
    ARBITRARY_DATA_TAG,
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
static svrc_t
decode_tlv_header(const uint8_t *data, size_t *data_bytes_read, sv_tlv_tag_t *tag, size_t *length);

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
  const uint8_t version = 3;
  int64_t timestamp = self->gop_info->timestamp;
  uint8_t flags = 0;

  // Value fields:
  //  - version (1 byte)
  //  - gop_counter (4 bytes)
  //  - num_nalus_in_gop_hash (2 bytes)
  //  - signed video version (SV_VERSION_BYTES bytes)
  //  - flags (1 byte)
  //  - timestamp (8 bytes) requires version 2+
  //  - linked_hash (hash_size bytes) requires version 3+
  //  - computed_gop_hash (hash_size bytes) requires version 3+

  // Get size of data
  data_size += sizeof(version);
  data_size += sizeof(gop_counter);
  data_size += sizeof(num_nalus_in_gop_hash);
  data_size += SV_VERSION_BYTES;
  data_size += sizeof(flags);
  if (gop_info->has_timestamp) {
    data_size += sizeof(timestamp);
  }
  data_size += self->sign_data->hash_size * 2;

  if (!data) {
    DEBUG_LOG("General tag has size %zu", data_size);
    return data_size;
  }

  DEBUG_LOG("Encoding GOP counter = %u", gop_counter);

  uint8_t *data_ptr = data;
  uint16_t *last_two_bytes = &self->last_two_bytes;
  bool epb = self->sei_epb;

  // Version
  write_byte(last_two_bytes, &data_ptr, version, epb);
  // GOP counter; 4 bytes
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((gop_counter >> 24) & 0x000000ff), epb);
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((gop_counter >> 16) & 0x000000ff), epb);
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((gop_counter >> 8) & 0x000000ff), epb);
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((gop_counter)&0x000000ff), epb);
  // Write num_nalus_in_gop_hash; 2 bytes
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((num_nalus_in_gop_hash >> 8) & 0x00ff), epb);
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((num_nalus_in_gop_hash)&0x00ff), epb);

  for (int i = 0; i < SV_VERSION_BYTES; i++) {
    write_byte(last_two_bytes, &data_ptr, (uint8_t)self->code_version[i], epb);
  }

  // Write bool flags; 1 byte
  flags |= (gop_info->has_timestamp << 0) & 0x01;
  write_byte(last_two_bytes, &data_ptr, flags, epb);
  if (gop_info->has_timestamp) {
    // Write timestamp; 8 bytes
    write_byte(last_two_bytes, &data_ptr, (uint8_t)((timestamp >> 56) & 0x000000ff), epb);
    write_byte(last_two_bytes, &data_ptr, (uint8_t)((timestamp >> 48) & 0x000000ff), epb);
    write_byte(last_two_bytes, &data_ptr, (uint8_t)((timestamp >> 40) & 0x000000ff), epb);
    write_byte(last_two_bytes, &data_ptr, (uint8_t)((timestamp >> 32) & 0x000000ff), epb);
    write_byte(last_two_bytes, &data_ptr, (uint8_t)((timestamp >> 24) & 0x000000ff), epb);
    write_byte(last_two_bytes, &data_ptr, (uint8_t)((timestamp >> 16) & 0x000000ff), epb);
    write_byte(last_two_bytes, &data_ptr, (uint8_t)((timestamp >> 8) & 0x000000ff), epb);
    write_byte(last_two_bytes, &data_ptr, (uint8_t)((timestamp)&0x000000ff), epb);
  }

  // Write linked hash; hash_size bytes
  for (size_t i = 0; i < self->sign_data->hash_size; i++) {
    write_byte(last_two_bytes, &data_ptr, gop_info->linked_hashes[i], epb);
  }

  // Write GOP hash; hash_size bytes
  for (size_t i = 0; i < self->sign_data->hash_size; i++) {
    write_byte(last_two_bytes, &data_ptr, gop_info->computed_gop_hash[i], epb);
  }

  gop_info->global_gop_counter = gop_counter;

  return (data_ptr - data);
}

/**
 * @brief Decodes the GENERAL_TAG from data
 */
static svrc_t
decode_general(signed_video_t *self, const uint8_t *data, size_t data_size)
{
  if (!self || !data) return SV_INVALID_PARAMETER;

  const uint8_t *data_ptr = data;
  gop_info_t *gop_info = self->gop_info;
  uint8_t version = *data_ptr++;
  char sw_version_str[SV_VERSION_MAX_STRLEN] = {0};
  char *code_version_str = sw_version_str;
  size_t hash_size = 0;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW_IF(version < 1 || version > 3, SV_INCOMPATIBLE_VERSION);

    data_ptr += read_32bits(data_ptr, &gop_info->global_gop_counter);
    DEBUG_LOG("Found GOP counter = %u", gop_info->global_gop_counter);
    data_ptr += read_16bits(data_ptr, &gop_info->num_sent_nalus);
    DEBUG_LOG("Number of sent NAL Units = %u", gop_info->num_sent_nalus);

    for (int i = 0; i < SV_VERSION_BYTES; i++) {
      self->code_version[i] = *data_ptr++;
    }
    if (self->authenticity) {
      code_version_str = self->authenticity->version_on_signing_side;
    }
    bytes_to_version_str(self->code_version, code_version_str);

    if (version >= 2) {
      // Read bool flags
      uint8_t flags = 0;
      data_ptr += read_8bits(data_ptr, &flags);
      gop_info->has_timestamp = flags & 0x01;
      if (gop_info->has_timestamp) {
        data_ptr += read_64bits_signed(data_ptr, &gop_info->timestamp);
      }
      if (self->latest_validation) {
        self->latest_validation->has_timestamp = gop_info->has_timestamp;
        if (gop_info->has_timestamp) {
          self->latest_validation->timestamp = gop_info->timestamp;
        }
      }
    }
    if (version >= 3) {
      hash_size = (data_size - (data_ptr - data)) / 2;
      // Decode linked hash data.
      memcpy(self->received_linked_hash, data_ptr, hash_size);
      data_ptr += hash_size;
      // Decode gop hash data.
      memcpy(self->received_gop_hash, data_ptr, hash_size);
      data_ptr += hash_size;
    }
    SV_THROW_IF(data_ptr != data + data_size, SV_AUTHENTICATION_ERROR);
#ifdef PRINT_DECODED_SEI
    printf("\nGeneral Information Tag\n");
    printf("             tag version: %u\n", version);
    printf("                   GOP #: %u\n", gop_info->global_gop_counter);
    printf("      # hashed NAL Units: %u\n", gop_info->num_sent_nalus);
    printf("              SW version: %s\n", code_version_str);
    if (version >= 2) {
      if (gop_info->has_timestamp) {
        printf("               timestamp: %ld\n", gop_info->timestamp);
      } else {
        printf("               timestamp: not present\n");
      }
    }
    if (version >= 3) {
      sv_print_hex_data(self->received_linked_hash, hash_size, "             linked hash: ");
      sv_print_hex_data(self->received_gop_hash, hash_size, "                GOP hash: ");
    }
#endif
  SV_CATCH()
  SV_DONE(status)

  return status;
}

/**
 * @brief Encodes the PRODUCT_INFO_TAG into data
 */
static size_t
encode_product_info(signed_video_t *self, uint8_t *data)
{
  signed_video_product_info_t *product_info = self->product_info;
  size_t data_size = 0;
  const uint8_t version = 1;
  const uint8_t kFullByte = 255;

  // Value fields:
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
  bool epb = self->sei_epb;
  uint8_t str_end_byte = '\0';
  // Version
  write_byte(last_two_bytes, &data_ptr, version, epb);

  // Write |hardware_id|.
  write_byte(last_two_bytes, &data_ptr, hardware_id_size_onebyte, epb);
  // Write all but the last character.
  write_byte_many(
      &data_ptr, product_info->hardware_id, hardware_id_size_onebyte - 1, last_two_bytes, epb);
  // Determine and write the last character.
  str_end_byte = (hardware_id_too_long || !product_info->hardware_id)
      ? '\0'
      : product_info->hardware_id[hardware_id_size_onebyte - 1];
  write_byte(last_two_bytes, &data_ptr, str_end_byte, epb);

  // Write |firmware_version|.
  write_byte(last_two_bytes, &data_ptr, firmware_version_size_onebyte, epb);
  // Write all but the last character.
  write_byte_many(&data_ptr, product_info->firmware_version, firmware_version_size_onebyte - 1,
      last_two_bytes, epb);
  // Determine and write the last character.
  str_end_byte = (firmware_version_too_long || !product_info->firmware_version)
      ? '\0'
      : product_info->firmware_version[firmware_version_size_onebyte - 1];
  write_byte(last_two_bytes, &data_ptr, str_end_byte, epb);

  // Write |serial_number|.
  write_byte(last_two_bytes, &data_ptr, serial_number_size_onebyte, epb);
  // Write all but the last character.
  write_byte_many(
      &data_ptr, product_info->serial_number, serial_number_size_onebyte - 1, last_two_bytes, epb);
  // Determine and write the last character.
  str_end_byte = (serial_number_too_long || !product_info->serial_number)
      ? '\0'
      : product_info->serial_number[serial_number_size_onebyte - 1];
  write_byte(last_two_bytes, &data_ptr, str_end_byte, epb);

  // Write |manufacturer|.
  write_byte(last_two_bytes, &data_ptr, manufacturer_size_onebyte, epb);
  // Write all but the last character.
  write_byte_many(
      &data_ptr, product_info->manufacturer, manufacturer_size_onebyte - 1, last_two_bytes, epb);
  // Determine and write the last character.
  str_end_byte = (manufacturer_too_long || !product_info->manufacturer)
      ? '\0'
      : product_info->manufacturer[manufacturer_size_onebyte - 1];
  write_byte(last_two_bytes, &data_ptr, str_end_byte, epb);

  // Write |address|.
  write_byte(last_two_bytes, &data_ptr, address_size_onebyte, epb);
  // Write all but the last character.
  write_byte_many(&data_ptr, product_info->address, address_size_onebyte - 1, last_two_bytes, epb);
  // Determine and write the last character.
  str_end_byte = (address_too_long || !product_info->address)
      ? '\0'
      : product_info->address[address_size_onebyte - 1];
  write_byte(last_two_bytes, &data_ptr, str_end_byte, epb);

  return (data_ptr - data);
}

/**
 * @brief Decodes the PRODUCT_INFO_TAG from data
 */
static svrc_t
decode_product_info(signed_video_t *self, const uint8_t *data, size_t data_size)
{
  const uint8_t *data_ptr = data;
  uint8_t version = *data_ptr++;
  svrc_t status = SV_UNKNOWN_FAILURE;

  if (!self || !self->product_info) return SV_INVALID_PARAMETER;

  SV_TRY()
    SV_THROW_IF(version == 0, SV_INCOMPATIBLE_VERSION);

    signed_video_product_info_t *product_info = self->product_info;

    uint8_t hardware_id_size = *data_ptr++;
    SV_THROW(allocate_memory_and_copy_string(&product_info->hardware_id, (const char *)data_ptr));
    data_ptr += hardware_id_size;

    uint8_t firmware_version_size = *data_ptr++;
    SV_THROW(
        allocate_memory_and_copy_string(&product_info->firmware_version, (const char *)data_ptr));
    data_ptr += firmware_version_size;

    uint8_t serial_number_size = *data_ptr++;
    SV_THROW(allocate_memory_and_copy_string(&product_info->serial_number, (const char *)data_ptr));
    data_ptr += serial_number_size;

    uint8_t manufacturer_size = *data_ptr++;
    SV_THROW(allocate_memory_and_copy_string(&product_info->manufacturer, (const char *)data_ptr));
    data_ptr += manufacturer_size;

    uint8_t address_size = *data_ptr++;
    SV_THROW(allocate_memory_and_copy_string(&product_info->address, (const char *)data_ptr));
    data_ptr += address_size;

    // Transfer the decoded |product_info| to the authenticity report.
    if (self->authenticity) {
      SV_THROW(transfer_product_info(&self->authenticity->product_info, product_info));
    }

    SV_THROW_IF(data_ptr != data + data_size, SV_AUTHENTICATION_ERROR);
#ifdef PRINT_DECODED_SEI
    printf("\nProduct Information Tag\n");
    printf("             tag version: %u\n", version);
    printf("             hardware id: %s\n", product_info->hardware_id);
    printf("        firmware version: %s\n", product_info->firmware_version);
    printf("           serial number: %s\n", product_info->serial_number);
    printf("            manufacturer: %s\n", product_info->manufacturer);
    printf("                 address: %s\n", product_info->address);
#endif
  SV_CATCH()
  SV_DONE(status)

  return status;
}

/**
 * @brief Encodes the ARBITRARY_DATA_TAG into data
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
  bool epb = self->sei_epb;
  // Version
  write_byte(last_two_bytes, &data_ptr, version, epb);

  for (size_t ii = 0; ii < self->arbitrary_data_size; ++ii) {
    write_byte(last_two_bytes, &data_ptr, self->arbitrary_data[ii], epb);
  }

  return (data_ptr - data);
}

/**
 * @brief Decodes the ARBITRARY_DATA_TAG from data
 */
static svrc_t
decode_arbitrary_data(signed_video_t *self, const uint8_t *data, size_t data_size)
{
  const uint8_t *data_ptr = data;
  uint8_t version = *data_ptr++;
  uint16_t arbdata_size = (uint16_t)(data_size - 1);
  svrc_t status = SV_UNKNOWN_FAILURE;

  SV_TRY()
    SV_THROW_IF(version == 0, SV_INCOMPATIBLE_VERSION);
    SV_THROW_IF(arbdata_size == 0, SV_AUTHENTICATION_ERROR);
    uint8_t *arbdata = realloc(self->arbitrary_data, arbdata_size);
    SV_THROW_IF(!arbdata, SV_MEMORY);
    memcpy(arbdata, data_ptr, arbdata_size);
    self->arbitrary_data = arbdata;
    self->arbitrary_data_size = arbdata_size;
    data_ptr += arbdata_size;
    SV_THROW_IF(data_ptr != data + data_size, SV_AUTHENTICATION_ERROR);
#ifdef PRINT_DECODED_SEI
    printf("\nArbitrary Data Tag\n");
    printf("             tag version: %u\n", version);
    printf("     arbitrary data size: %u\n", arbdata_size);
    sv_print_hex_data(arbdata, arbdata_size, "          arbitrary data: ");
#endif
  SV_CATCH()
  {
    free(self->arbitrary_data);
    self->arbitrary_data = NULL;
    self->arbitrary_data_size = 0;
  }
  SV_DONE(status)

  return status;
}

/**
 * @brief Encodes the PUBLIC_KEY_TAG into data
 */
static size_t
encode_public_key(signed_video_t *self, uint8_t *data)
{
  pem_pkey_t *pem_public_key = &self->pem_public_key;
  size_t data_size = 0;
  const uint8_t version = 2;

  // If there is no |key| present, or if it should not be added to the SEI, skip encoding,
  // that is, return 0.
  if (!pem_public_key->key || !self->add_public_key_to_sei) return 0;

  // Value fields:
  //  - version (1 byte)
  //  - public_key (key_size bytes)
  //  - num_nalus_in_gop_hash (2 bytes)
  //  - signed video version (SV_VERSION_BYTES bytes)
  //  - flags (1 byte)
  //  - timestamp (8 bytes) requires version 2+
  //
  // Note that we do not have to store the size of the public. We already know it from the TLV
  // length.

  data_size += sizeof(version);

  // Size of pubkey
  data_size += pem_public_key->key_size;

  if (!data) return data_size;

  uint8_t *data_ptr = data;
  uint16_t *last_two_bytes = &self->last_two_bytes;
  bool epb = self->sei_epb;
  uint8_t *public_key = (uint8_t *)pem_public_key->key;

  // Version
  write_byte(last_two_bytes, &data_ptr, version, epb);

  // public_key; public_key_size bytes
  for (size_t ii = 0; ii < pem_public_key->key_size; ++ii) {
    write_byte(last_two_bytes, &data_ptr, public_key[ii], epb);
  }

  return (data_ptr - data);
}

/**
 * @brief Decodes the PUBLIC_KEY_TAG from data
 *
 */
static svrc_t
decode_public_key(signed_video_t *self, const uint8_t *data, size_t data_size)
{
  const uint8_t *data_ptr = data;
  pem_pkey_t *pem_public_key = &self->pem_public_key;
  uint8_t version = *data_ptr++;
  uint16_t pubkey_size = (uint16_t)(data_size - 1);  // We only store version and the key.

  // The algo was removed in version 2 since it is not needed. Simply move to next byte if
  // older version.
  if (version < 2) {
    data_ptr++;
    pubkey_size -= 1;
  }

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW_IF(version == 0, SV_INCOMPATIBLE_VERSION);
    SV_THROW_IF(pubkey_size == 0, SV_AUTHENTICATION_ERROR);

    if (pem_public_key->key_size != pubkey_size) {
      free(pem_public_key->key);
      pem_public_key->key = calloc(1, pubkey_size);
      SV_THROW_IF(!pem_public_key->key, SV_MEMORY);
      pem_public_key->key_size = pubkey_size;
    }

    int key_diff = memcmp(data_ptr, pem_public_key->key, pubkey_size);
    if (self->has_public_key && key_diff && self->latest_validation) {
      self->latest_validation->public_key_has_changed = true;
    }
    memcpy(pem_public_key->key, data_ptr, pubkey_size);
    self->has_public_key = true;
    data_ptr += pubkey_size;

    // Convert to EVP_PKEY_CTX
    SV_THROW(openssl_public_key_malloc(self->verify_data, &self->pem_public_key));

#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
    // If "Axis Communications AB" can be identified from the |product_info|, set |public_key| to
    // |vendor_handle|.
    if (self->product_info->manufacturer &&
        strcmp(self->product_info->manufacturer, "Axis Communications AB") == 0) {
      // Set public key.
      SV_THROW(set_axis_communications_public_key(self->vendor_handle, self->verify_data->key,
          self->latest_validation->public_key_has_changed));
    }
#endif

    SV_THROW_IF(data_ptr != data + data_size, SV_AUTHENTICATION_ERROR);
  SV_CATCH()
  SV_DONE(status)

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

  // Value fields:
  //  - version (1 byte)
  //  - hash_list (list_idx bytes)

  data_size += sizeof(version);
  data_size += gop_info->list_idx * sizeof(gop_info->hash_list[0]);

  if (!data) return data_size;

  uint8_t *data_ptr = data;
  uint16_t *last_two_bytes = &self->last_two_bytes;
  bool epb = self->sei_epb;
  // Write version
  write_byte(last_two_bytes, &data_ptr, version, epb);
  // Write hash_list data
  for (int i = 0; i < gop_info->list_idx; i++) {
    write_byte(last_two_bytes, &data_ptr, gop_info->hash_list[i], epb);
  }

  // Having successfully encoded the hash_list means we should sign the document_hash and not the
  // gop_hash.
  self->gop_info->signature_hash_type = DOCUMENT_HASH;

  return (data_ptr - data);
}

/**
 * @brief Decodes the HASH_LIST_TAG from data
 */
static svrc_t
decode_hash_list(signed_video_t *self, const uint8_t *data, size_t data_size)
{
  const uint8_t *data_ptr = data;
  uint8_t version = *data_ptr++;
  size_t hash_list_size = data_size - (data_ptr - data);

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW_IF(version == 0, SV_INCOMPATIBLE_VERSION);
    SV_THROW_IF_WITH_MSG(
        hash_list_size > HASH_LIST_SIZE, SV_MEMORY, "Found more hashes than fit in hash_list");
    memcpy(self->gop_info->hash_list, data_ptr, hash_list_size);
    self->gop_info->list_idx = (int)hash_list_size;

    data_ptr += hash_list_size;

    SV_THROW_IF(data_ptr != data + data_size, SV_AUTHENTICATION_ERROR);

  SV_CATCH()
  SV_DONE(status)

  return status;
}

/**
 * @brief Encodes the SIGNATURE_TAG into data
 */
static size_t
encode_signature(signed_video_t *self, uint8_t *data)
{
  gop_info_t *gop_info = self->gop_info;
  sign_or_verify_data_t *sign_data = self->sign_data;
  size_t data_size = 0;
  const uint8_t version = 1;  // Increment when the change breaks the format

  // Value fields:
  //  - version (1 byte)
  //  - info field (1 byte)
  //  - hash type (1 byte)
  //  - signature size (2 bytes)
  //  - signature (max_signature_size bytes)

  data_size += sizeof(version);

  // Info field. This field holds information on whether the GOP info was correctly created or if
  // there were errors. This means that the validator is informed what can be verified and what
  // cannot.
  data_size += sizeof(gop_info->encoding_status);  // Info field
  data_size += 1;  // hash type
  data_size += 2;  // 2 bytes to store the actual size of the signature.
  data_size += sign_data->max_signature_size;  // Allocated size of the signature

  if (!data) return data_size;

  uint8_t *data_ptr = data;
  uint16_t *last_two_bytes = &self->last_two_bytes;
  bool epb = self->sei_epb;
  uint16_t signature_size = (uint16_t)sign_data->signature_size;
  // Write version
  write_byte(last_two_bytes, &data_ptr, version, epb);
  // Write info field
  write_byte(last_two_bytes, &data_ptr, gop_info->encoding_status, epb);
  // Write hash type
  write_byte(last_two_bytes, &data_ptr, (uint8_t)gop_info->signature_hash_type, epb);
  // Write actual signature size (2 bytes)
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((signature_size >> 8) & 0x00ff), epb);
  write_byte(last_two_bytes, &data_ptr, (uint8_t)((signature_size)&0x00ff), epb);
  // Write signature
  size_t i = 0;
  for (; i < signature_size; i++) {
    write_byte(last_two_bytes, &data_ptr, sign_data->signature[i], epb);
  }
  for (; i < sign_data->max_signature_size; i++) {
    // Write 1's in the unused bytes to avoid emulation prevention bytes.
    write_byte(last_two_bytes, &data_ptr, 1, epb);
  }

  return (data_ptr - data);
}

/**
 * @brief Decodes the SIGNATURE_TAG from data
 */
static svrc_t
decode_signature(signed_video_t *self, const uint8_t *data, size_t data_size)
{
  const uint8_t *data_ptr = data;
  gop_info_t *gop_info = self->gop_info;
  sign_or_verify_data_t *verify_data = self->verify_data;
  uint8_t **signature_ptr = &verify_data->signature;
  uint8_t version = *data_ptr++;
  uint8_t encoding_status = *data_ptr++;
  hash_type_t hash_type = *data_ptr++;
  uint16_t signature_size = 0;
  size_t max_signature_size = 0;

  // Read true size of the signature.
  data_ptr += read_16bits(data_ptr, &signature_size);
  // The rest of the value bytes should now be the allocated size for the signature.
  max_signature_size = data_size - (data_ptr - data);

  svrc_t status = SV_UNKNOWN_FAILURE;

  SV_TRY()
    SV_THROW_IF(version == 0, SV_INCOMPATIBLE_VERSION);
    SV_THROW_IF(hash_type < 0 || hash_type >= NUM_HASH_TYPES, SV_AUTHENTICATION_ERROR);
    SV_THROW_IF(max_signature_size < signature_size, SV_AUTHENTICATION_ERROR);
    if (!*signature_ptr) {
      verify_data->max_signature_size = 0;
      verify_data->signature_size = 0;
      // Allocate enough space for future signatures as well, that is, max_signature_size.
      *signature_ptr = malloc(max_signature_size);
      SV_THROW_IF(!*signature_ptr, SV_MEMORY);
      // Set memory size.
      verify_data->max_signature_size = max_signature_size;
    }
    SV_THROW_IF(verify_data->max_signature_size != max_signature_size, SV_MEMORY);
    memcpy(*signature_ptr, data_ptr, max_signature_size);
    data_ptr += max_signature_size;

    // Set true signature size.
    verify_data->signature_size = signature_size;
    gop_info->encoding_status = encoding_status;
    gop_info->signature_hash_type = hash_type;
    SV_THROW_IF(data_ptr != data + data_size, SV_AUTHENTICATION_ERROR);
  SV_CATCH()
  SV_DONE(status)

  return status;
}

/**
 * @brief Encodes the CRYPTO_INFO_TAG into data
 */
static size_t
encode_crypto_info(signed_video_t *self, uint8_t *data)
{
  size_t hash_algo_encoded_oid_size = 0;
  const unsigned char *hash_algo_encoded_oid =
      openssl_get_hash_algo_encoded_oid(self->crypto_handle, &hash_algo_encoded_oid_size);
  size_t data_size = 0;
  const uint8_t version = 1;

  // If there is no hash algorithm present skip encoding, that is, return 0.
  if (!hash_algo_encoded_oid || !hash_algo_encoded_oid_size) return 0;

  // Value fields:
  //  - version (1 byte)
  //  - size of hash algo OID (serialized form) (1 byte)
  //  - hash algo (hash_algo_encoded_oid_size bytes)

  data_size += sizeof(version);
  data_size += sizeof(uint8_t);
  // Size of hash algorithm in OID serialized form
  data_size += hash_algo_encoded_oid_size;

  if (!data) return data_size;

  uint8_t *data_ptr = data;
  uint16_t *last_two_bytes = &self->last_two_bytes;
  bool epb = self->sei_epb;

  // Version
  write_byte(last_two_bytes, &data_ptr, version, epb);
  // OID size
  write_byte(last_two_bytes, &data_ptr, (uint8_t)hash_algo_encoded_oid_size, epb);

  // OID data; hash_algo_encoded_oid_size bytes
  for (size_t ii = 0; ii < hash_algo_encoded_oid_size; ++ii) {
    write_byte(last_two_bytes, &data_ptr, hash_algo_encoded_oid[ii], epb);
  }

  return (data_ptr - data);
}

/**
 * @brief Decodes the CRYPTO_INFO_TAG from data
 */
static svrc_t
decode_crypto_info(signed_video_t *self, const uint8_t *data, size_t data_size)
{
  const uint8_t *data_ptr = data;
  uint8_t version = *data_ptr++;
  size_t hash_algo_encoded_oid_size = *data_ptr++;
  const unsigned char *hash_algo_encoded_oid = (const unsigned char *)data_ptr;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW_IF(version == 0, SV_INCOMPATIBLE_VERSION);
    SV_THROW_IF(hash_algo_encoded_oid_size == 0, SV_AUTHENTICATION_ERROR);
    SV_THROW(openssl_set_hash_algo_by_encoded_oid(
        self->crypto_handle, hash_algo_encoded_oid, hash_algo_encoded_oid_size));
    self->validation_flags.hash_algo_known = true;
    self->verify_data->hash_size = openssl_get_hash_size(self->crypto_handle);
    self->gop_info->nalu_hash = self->gop_info->hashes + self->verify_data->hash_size;
    data_ptr += hash_algo_encoded_oid_size;

    SV_THROW_IF(data_ptr != data + data_size, SV_AUTHENTICATION_ERROR);
  SV_CATCH()
  SV_DONE(status)

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
  bool epb = self->sei_epb;
  return encode_axis_communications_handle(self->vendor_handle, &self->last_two_bytes, epb, data);
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
static svrc_t
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
  return SV_NOT_SUPPORTED;
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

  tl_size += 1;  // For tag
  tl_size += tlv.bytes_for_length;  // For length
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
  bool epb = self->sei_epb;
  // Write Tag
  write_byte(last_two_bytes, &data_ptr, (uint8_t)tlv.tag, epb);
  // Write length
  if (tlv.bytes_for_length == 2) {
    write_byte(last_two_bytes, &data_ptr, (uint8_t)((v_size >> 8) & 0x000000ff), epb);
  }
  write_byte(last_two_bytes, &data_ptr, (uint8_t)(v_size & 0x000000ff), epb);

  // Write value, i.e., the actual data of the TLV
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
  if (!self || !tags || !num_tags) return SV_INVALID_PARAMETER;

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
      // Increment data_ptr if data is written
      if (data) data_ptr += tlv_size;
    }
  }
  return tlv_list_size;
}

static svrc_t
decode_tlv_header(const uint8_t *data, size_t *data_bytes_read, sv_tlv_tag_t *tag, size_t *length)
{
  // Sanity checks on input parameters.
  if (!data || !data_bytes_read || !tag || !length) return SV_INVALID_PARAMETER;

  const uint8_t *data_ptr = data;
  sv_tlv_tag_t tag_from_data = (sv_tlv_tag_t)(*data_ptr++);
  *data_bytes_read = 0;
  sv_tlv_tuple_t tlv = get_tlv_tuple(tag_from_data);
  if (tlv.tag != tag_from_data) {
    DEBUG_LOG("Parsed an invalid tag (%d) in the data", tag_from_data);
    return SV_INVALID_PARAMETER;
  }
  *tag = tag_from_data;

  if (tlv.bytes_for_length == 2) {
    data_ptr += read_16bits(data_ptr, (uint16_t *)length);
  } else {
    *length = *data_ptr++;
  }

  *data_bytes_read = (data_ptr - data);

  return SV_OK;
}

svrc_t
tlv_decode(signed_video_t *self, const uint8_t *data, size_t data_size)
{
  svrc_t status = SV_INVALID_PARAMETER;
  const uint8_t *data_ptr = data;

  if (!self || !data || data_size == 0) return SV_INVALID_PARAMETER;

  while (data_ptr < data + data_size) {
    sv_tlv_tag_t tag = 0;
    size_t tlv_header_size = 0;
    size_t length = 0;
    status = decode_tlv_header(data_ptr, &tlv_header_size, &tag, &length);
    if (status != SV_OK) {
      DEBUG_LOG("Could not decode TLV header (error %d)", status);
      break;
    }
    data_ptr += tlv_header_size;

    sv_tlv_decoder_t decoder = get_decoder(tag);
    status = decoder(self, data_ptr, length);
    if (status != SV_OK) {
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
    if (this_tag == tag) {
      return latest_tag_location;
    }

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
  DEBUG_LOG("Never found the tag %d", tag);

  return NULL;
}

bool
tlv_find_and_decode_optional_tags(signed_video_t *self,
    const uint8_t *tlv_data,
    size_t tlv_data_size)
{
  const uint8_t *tlv_data_ptr = tlv_data;

  if (!self || !tlv_data || tlv_data_size == 0) return false;

  svrc_t status = SV_UNKNOWN_FAILURE;
  bool optional_tags_decoded = false;
  while (tlv_data_ptr < tlv_data + tlv_data_size) {
    size_t tlv_header_size = 0;
    size_t length = 0;
    sv_tlv_tag_t this_tag = UNDEFINED_TAG;
    status = decode_tlv_header(tlv_data_ptr, &tlv_header_size, &this_tag, &length);
    if (status != SV_OK) {
      DEBUG_LOG("Could not decode tlv header");
      break;
    }
    tlv_data_ptr += tlv_header_size;
    if (!tlv_tuples[this_tag].is_always_present) {
      sv_tlv_decoder_t decoder = get_decoder(this_tag);
      status = decoder(self, tlv_data_ptr, length);
      if (status != SV_OK) {
        DEBUG_LOG("Could not decode tlv values");
        break;
      }
      optional_tags_decoded = true;
    }
    tlv_data_ptr += length;
  }

  return optional_tags_decoded;
}

const sv_tlv_tag_t *
get_optional_tags(size_t *num_of_optional_tags)
{
  *num_of_optional_tags = ARRAY_SIZE(optional_tags);
  return optional_tags;
}

const sv_tlv_tag_t *
get_mandatory_tags(size_t *num_of_mandatory_tags)
{
  *num_of_mandatory_tags = ARRAY_SIZE(mandatory_tags);
  return mandatory_tags;
}

size_t
read_64bits(const uint8_t *p, uint64_t *val)
{
  if (!p || !val) return 0;
  *val = ((uint64_t)p[0]) << 56;
  *val += ((uint64_t)p[1]) << 48;
  *val += ((uint64_t)p[2]) << 40;
  *val += ((uint64_t)p[3]) << 32;
  *val += ((uint64_t)p[4]) << 24;
  *val += ((uint64_t)p[5]) << 16;
  *val += ((uint64_t)p[6]) << 8;
  *val += (uint64_t)p[7];

  return 8;
}

size_t
read_64bits_signed(const uint8_t *p, int64_t *val)
{
  uint64_t tmp_val = 0;
  size_t bytes_read = read_64bits(p, &tmp_val);
  *val = (int64_t)tmp_val;
  return bytes_read;
}

size_t
read_32bits(const uint8_t *p, uint32_t *val)
{
  if (!p || !val) return 0;
  *val = ((uint32_t)p[0]) << 24;
  *val += ((uint32_t)p[1]) << 16;
  *val += ((uint32_t)p[2]) << 8;
  *val += (uint32_t)p[3];

  return 4;
}

size_t
read_16bits(const uint8_t *p, uint16_t *val)
{
  if (!p || !val) return 0;
  *val = ((uint16_t)p[0]) << 8;
  *val += (uint16_t)p[1];

  return 2;
}

size_t
read_8bits(const uint8_t *p, uint8_t *val)
{
  if (!p || !val) return 0;
  *val = *p;

  return 1;
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

void
write_byte_many(uint8_t **dst,
    char *src,
    size_t size,
    uint16_t *last_two_bytes,
    bool do_emulation_prevention)
{
  if (!src) return;

  for (size_t ii = 0; ii < size; ++ii) {
    uint8_t ch = src[ii];
    write_byte(last_two_bytes, dst, ch, do_emulation_prevention);
  }
}
