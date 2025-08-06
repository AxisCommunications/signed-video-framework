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
#include "sv_tlv.h"

#ifdef PRINT_DECODED_SEI
#include <stdio.h>
#endif

#include "includes/signed_video_auth.h"  // signed_video_product_info_t
#include "includes/signed_video_openssl.h"  // pem_pkey_t, sign_or_verify_data_t
#include "sv_authenticity.h"  // transfer_product_info()
#include "sv_axis_communications_internal.h"
#include "sv_openssl_internal.h"  // openssl_public_key_malloc()

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
 * @param signed_video_t The Signed Video object to write to.
 * @param data Pointer to the data to decode.
 * @param data_size Size of the data.
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
 * Definition of a TLV tuple associating the TLV Tag with an encoder, a decoder and the
 * number of bytes to represent the Length. Also associates the tag with a flag indicating
 * if this should always be present */
typedef struct {
  sv_tlv_tag_t tag;
  uint8_t bytes_for_length;
  sv_tlv_encoder_t encoder;
  sv_tlv_decoder_t decoder;
  bool is_always_present;
} sv_tlv_tuple_t;

/**
 * This is an array of all available TLV tuples. The first and last tuples, which are
 * invalid tags, have dummy values to avoid the risk of reading outside memory.
 *
 * @note: They HAVE TO be in the same order as the available tags!
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
    VENDOR_AXIS_COMMUNICATIONS_TAG,
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
 * This is an array of all available Vendor TLV tuples. The first and last tuples, which
 * are invalid tags, have dummy values to avoid the risk of reading outside memory.
 * The tuples are offset with UNDEFINED_VENDOR_TAG since they start at
 * UNDEFINED_VENDOR_TAG in sv_tlv_tag_t.
 *
 * @note: They HAVE TO be in the same order as the available tags!
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
  uint32_t gop_counter = (uint32_t)(gop_info->current_partial_gop & 0xffffffff);
  uint16_t num_in_partial_gop = gop_info->num_in_partial_gop;
  const uint8_t version = 4;
  int64_t start_ts = gop_info->start_timestamp;
  int64_t end_ts = gop_info->end_timestamp;
  uint8_t flags = 0;

  // Value fields:
  //  - version (1 byte)
  //  - gop_counter (4 bytes)
  //  - num_in_partial_gop (2 bytes)
  //  - signed video version (SV_VERSION_BYTES bytes)
  //  - flags (1 byte)
  //  - start_timestamp (8 bytes) requires version 2+
  //  - end_timestamp (8 bytes) requires version 4+
  //  - linked_hash (hash_size bytes) requires version 3+
  //  - computed_gop_hash (hash_size bytes) requires version 3+

  // Get size of data
  data_size += sizeof(version);
  data_size += sizeof(gop_counter);
  data_size += sizeof(num_in_partial_gop);
  data_size += SV_VERSION_BYTES;
  data_size += sizeof(flags);
  if (gop_info->has_timestamp) {
    data_size += sizeof(start_ts) * 2;
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
  sv_write_byte(last_two_bytes, &data_ptr, version, epb);
  // GOP counter; 4 bytes
  sv_write_byte(last_two_bytes, &data_ptr, (uint8_t)((gop_counter >> 24) & 0x000000ff), epb);
  sv_write_byte(last_two_bytes, &data_ptr, (uint8_t)((gop_counter >> 16) & 0x000000ff), epb);
  sv_write_byte(last_two_bytes, &data_ptr, (uint8_t)((gop_counter >> 8) & 0x000000ff), epb);
  sv_write_byte(last_two_bytes, &data_ptr, (uint8_t)((gop_counter)&0x000000ff), epb);
  // Write num_in_partial_gop; 2 bytes
  sv_write_byte(last_two_bytes, &data_ptr, (uint8_t)((num_in_partial_gop >> 8) & 0x00ff), epb);
  sv_write_byte(last_two_bytes, &data_ptr, (uint8_t)((num_in_partial_gop)&0x00ff), epb);

  for (int i = 0; i < SV_VERSION_BYTES; i++) {
    sv_write_byte(last_two_bytes, &data_ptr, (uint8_t)self->code_version[i], epb);
  }

  // Write bool flags; 1 byte | xxxxxx | triggered_partial_gop | has_timestamp |
  flags |= (gop_info->has_timestamp << 0) & 0x01;
  flags |= (gop_info->triggered_partial_gop << 1) & 0x02;
  sv_write_byte(last_two_bytes, &data_ptr, flags, epb);
  if (gop_info->has_timestamp) {
    // Write timestamps; 8 bytes each
    sv_write_byte(last_two_bytes, &data_ptr, (uint8_t)((start_ts >> 56) & 0x000000ff), epb);
    sv_write_byte(last_two_bytes, &data_ptr, (uint8_t)((start_ts >> 48) & 0x000000ff), epb);
    sv_write_byte(last_two_bytes, &data_ptr, (uint8_t)((start_ts >> 40) & 0x000000ff), epb);
    sv_write_byte(last_two_bytes, &data_ptr, (uint8_t)((start_ts >> 32) & 0x000000ff), epb);
    sv_write_byte(last_two_bytes, &data_ptr, (uint8_t)((start_ts >> 24) & 0x000000ff), epb);
    sv_write_byte(last_two_bytes, &data_ptr, (uint8_t)((start_ts >> 16) & 0x000000ff), epb);
    sv_write_byte(last_two_bytes, &data_ptr, (uint8_t)((start_ts >> 8) & 0x000000ff), epb);
    sv_write_byte(last_two_bytes, &data_ptr, (uint8_t)((start_ts)&0x000000ff), epb);
    sv_write_byte(last_two_bytes, &data_ptr, (uint8_t)((end_ts >> 56) & 0x000000ff), epb);
    sv_write_byte(last_two_bytes, &data_ptr, (uint8_t)((end_ts >> 48) & 0x000000ff), epb);
    sv_write_byte(last_two_bytes, &data_ptr, (uint8_t)((end_ts >> 40) & 0x000000ff), epb);
    sv_write_byte(last_two_bytes, &data_ptr, (uint8_t)((end_ts >> 32) & 0x000000ff), epb);
    sv_write_byte(last_two_bytes, &data_ptr, (uint8_t)((end_ts >> 24) & 0x000000ff), epb);
    sv_write_byte(last_two_bytes, &data_ptr, (uint8_t)((end_ts >> 16) & 0x000000ff), epb);
    sv_write_byte(last_two_bytes, &data_ptr, (uint8_t)((end_ts >> 8) & 0x000000ff), epb);
    sv_write_byte(last_two_bytes, &data_ptr, (uint8_t)((end_ts)&0x000000ff), epb);
  }

  // Write linked hash; hash_size bytes
  for (size_t i = 0; i < self->sign_data->hash_size; i++) {
    sv_write_byte(last_two_bytes, &data_ptr, gop_info->linked_hashes[i], epb);
  }

  // Write GOP hash; hash_size bytes
  for (size_t i = 0; i < self->sign_data->hash_size; i++) {
    sv_write_byte(last_two_bytes, &data_ptr, gop_info->computed_gop_hash[i], epb);
  }

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
  uint8_t flags = 0;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW_IF(version < 1 || version > 4, SV_INCOMPATIBLE_VERSION);

    data_ptr += sv_read_32bits(data_ptr, &gop_info->next_partial_gop);
    DEBUG_LOG("Found GOP counter = %u", gop_info->next_partial_gop);
    data_ptr += sv_read_16bits(data_ptr, &gop_info->num_sent);
    DEBUG_LOG("Number of sent Bitstream Units = %u", gop_info->num_sent);

    for (int i = 0; i < SV_VERSION_BYTES; i++) {
      self->code_version[i] = *data_ptr++;
    }
    if (self->authenticity) {
      code_version_str = self->authenticity->version_on_signing_side;
    }
    sv_bytes_to_version_str(self->code_version, code_version_str);

    if (version >= 2) {
      // Read bool flags
      data_ptr += sv_read_8bits(data_ptr, &flags);
      gop_info->has_timestamp = flags & 0x01;
      gop_info->triggered_partial_gop = !!(flags & 0x02);
      if (gop_info->has_timestamp) {
        data_ptr += sv_read_64bits_signed(data_ptr, &gop_info->start_timestamp);
        if (version >= 4) {
          data_ptr += sv_read_64bits_signed(data_ptr, &gop_info->end_timestamp);
        } else {
          gop_info->end_timestamp = gop_info->start_timestamp;
        }
      }
      if (self->latest_validation) {
        self->latest_validation->has_timestamp = gop_info->has_timestamp;
        if (gop_info->has_timestamp) {
          self->latest_validation->start_timestamp = gop_info->start_timestamp;
          self->latest_validation->end_timestamp = gop_info->end_timestamp;
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
    printf("                   flags: %u\n", flags);
    printf("           partial GOP #: %u\n", gop_info->next_partial_gop);
    printf("triggered by partial GOP: %s\n", gop_info->triggered_partial_gop ? "true" : "false");
    printf("# hashed Bitstream Units: %u\n", gop_info->num_sent);
    printf("              SW version: %s\n", code_version_str);
    if (version >= 2) {
      if (gop_info->has_timestamp) {
        printf("         start_timestamp: %ld\n", gop_info->start_timestamp);
        printf("           end_timestamp: %ld\n", gop_info->end_timestamp);
      } else {
        printf("         start_timestamp: not present\n");
        printf("           end_timestamp: not present\n");
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
  signed_video_product_info_t *product_info = &self->product_info;
  size_t data_size = 0;
  const uint8_t version = 2;

  // Value fields:
  //  - version (1 byte)
  //  - hardware_id_size (1 byte)
  //  - hardware_id
  //  - firmware_version_size (1 byte)
  //  - firmware_version
  //  - serial_number_size (1 byte)
  //  - serial_number
  //  - manufacturer_size (1 byte)
  //  - manufacturer
  //  - address_size (1 byte)
  //  - address

  data_size += sizeof(version);

  // Determine sizes excluding null-terminated character
  data_size += 1;
  size_t hardware_id_size = strlen(product_info->hardware_id);
  data_size += hardware_id_size;

  data_size += 1;
  size_t firmware_version_size = strlen(product_info->firmware_version);
  data_size += firmware_version_size;

  data_size += 1;
  size_t serial_number_size = strlen(product_info->serial_number);
  data_size += serial_number_size;

  data_size += 1;
  size_t manufacturer_size = strlen(product_info->manufacturer);
  data_size += manufacturer_size;

  data_size += 1;
  size_t address_size = strlen(product_info->address);
  data_size += address_size;

  if (!data) return data_size;

  uint8_t *data_ptr = data;
  uint16_t *last_two_bytes = &self->last_two_bytes;
  bool epb = self->sei_epb;
  // Version
  sv_write_byte(last_two_bytes, &data_ptr, version, epb);

  // Write |hardware_id|, i.e., size + string.
  sv_write_byte(last_two_bytes, &data_ptr, hardware_id_size, epb);
  // Write all but the null-terminated character.
  sv_write_byte_many(&data_ptr, product_info->hardware_id, hardware_id_size, last_two_bytes, epb);

  // Write |firmware_version|, i.e., size + string.
  sv_write_byte(last_two_bytes, &data_ptr, firmware_version_size, epb);
  // Write all but the null-terminated character.
  sv_write_byte_many(
      &data_ptr, product_info->firmware_version, firmware_version_size, last_two_bytes, epb);

  // Write |serial_number|, i.e., size + string.
  sv_write_byte(last_two_bytes, &data_ptr, serial_number_size, epb);
  // Write all but the null-terminated character.
  sv_write_byte_many(
      &data_ptr, product_info->serial_number, serial_number_size, last_two_bytes, epb);

  // Write |manufacturer|, i.e., size + string.
  sv_write_byte(last_two_bytes, &data_ptr, manufacturer_size, epb);
  // Write all but the null-terminated character.
  sv_write_byte_many(&data_ptr, product_info->manufacturer, manufacturer_size, last_two_bytes, epb);

  // Write |address|, i.e., size + string.
  sv_write_byte(last_two_bytes, &data_ptr, address_size, epb);
  // Write all but the null-terminated character.
  sv_write_byte_many(&data_ptr, product_info->address, address_size, last_two_bytes, epb);

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

  if (!self) return SV_INVALID_PARAMETER;

  SV_TRY()
    SV_THROW_IF(version < 1 || version > 2, SV_INCOMPATIBLE_VERSION);

    signed_video_product_info_t *product_info = &self->product_info;

    product_info_reset_members(product_info);

    uint8_t hardware_id_size = *data_ptr++;
    memcpy(product_info->hardware_id, (const char *)data_ptr, hardware_id_size);
    // Note that version 1 writes |hardware_id| including null-terminated character.
    // Adding another one after the string does not affect its content. Therefore, there
    // is no need to treat version 1 separately. This holds for all members in
    // |product_info|.
    product_info->hardware_id[hardware_id_size] = '\0';
    data_ptr += hardware_id_size;

    uint8_t firmware_version_size = *data_ptr++;
    memcpy(product_info->firmware_version, (const char *)data_ptr, firmware_version_size);
    product_info->firmware_version[firmware_version_size] = '\0';
    data_ptr += firmware_version_size;

    uint8_t serial_number_size = *data_ptr++;
    memcpy(product_info->serial_number, (const char *)data_ptr, serial_number_size);
    product_info->serial_number[serial_number_size] = '\0';
    data_ptr += serial_number_size;

    uint8_t manufacturer_size = *data_ptr++;
    memcpy(product_info->manufacturer, (const char *)data_ptr, manufacturer_size);
    product_info->manufacturer[manufacturer_size] = '\0';
    data_ptr += manufacturer_size;

    uint8_t address_size = *data_ptr++;
    memcpy(product_info->address, (const char *)data_ptr, address_size);
    product_info->address[address_size] = '\0';
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
  sv_write_byte(last_two_bytes, &data_ptr, version, epb);

  for (size_t ii = 0; ii < self->arbitrary_data_size; ++ii) {
    sv_write_byte(last_two_bytes, &data_ptr, self->arbitrary_data[ii], epb);
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
    SV_THROW_IF(version != 1, SV_INCOMPATIBLE_VERSION);
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
  //
  // Note that it is not necessary to store the size of the public key. It can be computed
  // from the TLV length.

  data_size += sizeof(version);

  // Size of pubkey
  data_size += pem_public_key->key_size;

  if (!data) return data_size;

  uint8_t *data_ptr = data;
  uint16_t *last_two_bytes = &self->last_two_bytes;
  bool epb = self->sei_epb;
  uint8_t *public_key = (uint8_t *)pem_public_key->key;

  // Version
  sv_write_byte(last_two_bytes, &data_ptr, version, epb);

  // public_key; public_key_size bytes
  for (size_t ii = 0; ii < pem_public_key->key_size; ++ii) {
    sv_write_byte(last_two_bytes, &data_ptr, public_key[ii], epb);
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
  uint16_t pubkey_size = (uint16_t)(data_size - 1);  // Only version and the key is stored
  bool public_key_has_changed = false;

  // The algo was removed in version 2 since it is not needed. Simply move to next byte if
  // older version.
  if (version < 2) {
    data_ptr++;
    pubkey_size -= 1;
  }

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW_IF(version < 1 || version > 2, SV_INCOMPATIBLE_VERSION);
    SV_THROW_IF(pubkey_size == 0, SV_AUTHENTICATION_ERROR);

    if (pem_public_key->key_size != pubkey_size) {
      free(pem_public_key->key);
      pem_public_key->key = calloc(1, pubkey_size);
      SV_THROW_IF(!pem_public_key->key, SV_MEMORY);
      pem_public_key->key_size = pubkey_size;
    }

    int key_diff = memcmp(data_ptr, pem_public_key->key, pubkey_size);
    public_key_has_changed = self->has_public_key && key_diff;
    if (self->latest_validation) {
      self->latest_validation->public_key_has_changed = public_key_has_changed;
    }
    if (!public_key_has_changed) {
      memcpy(pem_public_key->key, data_ptr, pubkey_size);
      self->has_public_key = true;
    }
    data_ptr += pubkey_size;

    // Convert to EVP_PKEY_CTX
    SV_THROW(openssl_public_key_malloc(self->verify_data, &self->pem_public_key));

    // If "Axis Communications AB" can be identified from the |product_info|, set |public_key| to
    // |vendor_handle|.
    if (strcmp(self->product_info.manufacturer, "Axis Communications AB") == 0) {
      // Set public key.
      SV_THROW(set_axis_communications_public_key(self->vendor_handle, self->verify_data->key,
          self->latest_validation->public_key_has_changed));
    }

    SV_THROW_IF(data_ptr != data + data_size, SV_AUTHENTICATION_ERROR);
#ifdef PRINT_DECODED_SEI
    char *public_key_str = calloc(1, pubkey_size + 1);
    SV_THROW_IF(!public_key_str, SV_MEMORY);
    memcpy(public_key_str, pem_public_key->key, pubkey_size);
    printf("\nPublic Key Tag\n");
    printf("             tag version: %u\n", version);
    printf("         public key size: %u\n", pubkey_size);
    printf("              public key:\n%s\n", public_key_str);
    free(public_key_str);
#endif
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

  // If the |hash_list| is empty, or invalid, skip encoding, that is, return 0. Also, skip
  // encoding if SV_AUTHENTICITY_LEVEL_FRAME is used.
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
  sv_write_byte(last_two_bytes, &data_ptr, version, epb);
  // Write hash_list data
  for (int i = 0; i < gop_info->list_idx; i++) {
    sv_write_byte(last_two_bytes, &data_ptr, gop_info->hash_list[i], epb);
  }

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
    SV_THROW_IF(version != 1, SV_INCOMPATIBLE_VERSION);
    SV_THROW_IF_WITH_MSG(
        hash_list_size > HASH_LIST_SIZE, SV_MEMORY, "Found more hashes than fit in hash_list");
    memcpy(self->gop_info->hash_list, data_ptr, hash_list_size);
    self->gop_info->list_idx = (int)hash_list_size;

    data_ptr += hash_list_size;

    SV_THROW_IF(data_ptr != data + data_size, SV_AUTHENTICATION_ERROR);
#ifdef PRINT_DECODED_SEI
    size_t hash_size = sv_openssl_get_hash_size(self->crypto_handle);
    printf("\nHash list Tag\n");
    printf("             tag version: %u\n", version);
    printf("  hash list (%3zu hashes): \n", hash_list_size / hash_size);
    for (size_t i = 0; i < hash_list_size; i += hash_size) {
      sv_print_hex_data(&self->gop_info->hash_list[i], hash_size, "");
    }
#endif
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
  const uint8_t version = 2;  // Increment when the change breaks the format

  // Value fields:
  //  - version (1 byte)
  //  - info field (1 byte)
  //  - signature size (2 bytes)
  //  - signature (max_signature_size bytes)

  data_size += sizeof(version);

  // Info field. This field holds information on whether the GOP info was correctly created or if
  // there were errors. This means that the validator is informed what can be verified and what
  // cannot.
  data_size += sizeof(gop_info->encoding_status);  // Info field
  data_size += 2;  // 2 bytes to store the actual size of the signature.
  data_size += sign_data->max_signature_size;  // Allocated size of the signature

  if (!data) return data_size;

  uint8_t *data_ptr = data;
  uint16_t *last_two_bytes = &self->last_two_bytes;
  bool epb = self->sei_epb;
  uint16_t signature_size = (uint16_t)sign_data->signature_size;
  // Write version
  sv_write_byte(last_two_bytes, &data_ptr, version, epb);
  // Write info field
  sv_write_byte(last_two_bytes, &data_ptr, gop_info->encoding_status, epb);
  // Write hash type
  // Write actual signature size (2 bytes)
  sv_write_byte(last_two_bytes, &data_ptr, (uint8_t)((signature_size >> 8) & 0x00ff), epb);
  sv_write_byte(last_two_bytes, &data_ptr, (uint8_t)((signature_size)&0x00ff), epb);
  // Write signature
  size_t i = 0;
  for (; i < signature_size; i++) {
    sv_write_byte(last_two_bytes, &data_ptr, sign_data->signature[i], epb);
  }
  for (; i < sign_data->max_signature_size; i++) {
    // Write 1's in the unused bytes to avoid emulation prevention bytes.
    sv_write_byte(last_two_bytes, &data_ptr, 1, epb);
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
  if (version < 2) {
    // Move past the written hash type since it is never used.
    data_ptr++;
  }
  uint16_t signature_size = 0;
  size_t max_signature_size = 0;

  // Read true size of the signature.
  data_ptr += sv_read_16bits(data_ptr, &signature_size);
  // The rest of the value bytes should now be the allocated size for the signature.
  max_signature_size = data_size - (data_ptr - data);

  svrc_t status = SV_UNKNOWN_FAILURE;

  SV_TRY()
    SV_THROW_IF(version < 1 || version > 2, SV_INCOMPATIBLE_VERSION);
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
    SV_THROW_IF(data_ptr != data + data_size, SV_AUTHENTICATION_ERROR);
#ifdef PRINT_DECODED_SEI
    printf("\nSignature Tag\n");
    printf("             tag version: %u\n", version);
    printf("          signature size: %u\n", signature_size);
    sv_print_hex_data(verify_data->signature, signature_size, "               signature: ");
#endif
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
      sv_openssl_get_hash_algo_encoded_oid(self->crypto_handle, &hash_algo_encoded_oid_size);
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
  sv_write_byte(last_two_bytes, &data_ptr, version, epb);
  // OID size
  sv_write_byte(last_two_bytes, &data_ptr, (uint8_t)hash_algo_encoded_oid_size, epb);

  // OID data; hash_algo_encoded_oid_size bytes
  for (size_t ii = 0; ii < hash_algo_encoded_oid_size; ++ii) {
    sv_write_byte(last_two_bytes, &data_ptr, hash_algo_encoded_oid[ii], epb);
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
  char *hash_algo_name =
      sv_openssl_encoded_oid_to_str(hash_algo_encoded_oid, hash_algo_encoded_oid_size);

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW_IF(version != 1, SV_INCOMPATIBLE_VERSION);
    SV_THROW_IF(hash_algo_encoded_oid_size == 0, SV_AUTHENTICATION_ERROR);
    SV_THROW(sv_openssl_set_hash_algo_by_encoded_oid(
        self->crypto_handle, hash_algo_encoded_oid, hash_algo_encoded_oid_size));
    self->validation_flags.hash_algo_known = true;
    self->verify_data->hash_size = sv_openssl_get_hash_size(self->crypto_handle);
    data_ptr += hash_algo_encoded_oid_size;

    SV_THROW_IF(data_ptr != data + data_size, SV_AUTHENTICATION_ERROR);
#ifdef PRINT_DECODED_SEI
    printf("\nCrypto Information Tag\n");
    printf("             tag version: %u\n", version);
    printf("hashing algo (ASN.1/DER): ");
    for (size_t i = 0; i < hash_algo_encoded_oid_size; i++) {
      printf("%02x", hash_algo_encoded_oid[i]);
    }
    printf(" -> %s\n", hash_algo_name);
#endif
  SV_CATCH()
  SV_DONE(status)

  free(hash_algo_name);

  return status;
}

// Vendor specific encoders and decoders.

/**
 * @brief Encodes the VENDOR_AXIS_COMMUNICATIONS_TAG into data
 *
 */
static size_t
encode_axis_communications(signed_video_t *self, uint8_t *data)
{
  bool epb = self->sei_epb;
  return encode_axis_communications_handle(self->vendor_handle, &self->last_two_bytes, epb, data);
}

/**
 * @brief Decodes the VENDOR_AXIS_COMMUNICATIONS_TAG from data
 *
 */
static svrc_t
decode_axis_communications(signed_video_t *self, const uint8_t *data, size_t data_size)
{
  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW(decode_axis_communications_handle(self->vendor_handle, data, data_size));
    // If the signing key is provisioned in factory, the public key is transmitted through the leaf
    // certificate of the certificate chain.
    if (!self->has_public_key) {
      SV_THROW(get_axis_communications_public_key(self->vendor_handle, &(self->verify_data->key)));
      self->has_public_key = (self->verify_data->key != NULL);
    }
  SV_CATCH()
  SV_DONE(status)

  return status;
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
  sv_write_byte(last_two_bytes, &data_ptr, (uint8_t)tlv.tag, epb);
  // Write length
  if (tlv.bytes_for_length == 2) {
    sv_write_byte(last_two_bytes, &data_ptr, (uint8_t)((v_size >> 8) & 0x000000ff), epb);
  }
  sv_write_byte(last_two_bytes, &data_ptr, (uint8_t)(v_size & 0x000000ff), epb);

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
sv_tlv_list_encode_or_get_size(signed_video_t *self,
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
    data_ptr += sv_read_16bits(data_ptr, (uint16_t *)length);
  } else {
    *length = *data_ptr++;
  }

  *data_bytes_read = (data_ptr - data);

  return SV_OK;
}

svrc_t
sv_tlv_decode(signed_video_t *self, const uint8_t *data, size_t data_size)
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
sv_tlv_find_tag(const uint8_t *tlv_data, size_t tlv_data_size, sv_tlv_tag_t tag, bool with_ep)
{
  const uint8_t *tlv_data_ptr = tlv_data;
  const uint8_t *latest_tag_location = NULL;

  if (!tlv_data || tlv_data_size == 0) return 0;

  uint16_t last_two_bytes = LAST_TWO_BYTES_INIT_VALUE;
  while (tlv_data_ptr < tlv_data + tlv_data_size) {
    latest_tag_location = tlv_data_ptr;
    // Read the tag
    sv_tlv_tag_t this_tag = sv_read_byte(&last_two_bytes, &tlv_data_ptr, with_ep);
    if (this_tag == tag) {
      return latest_tag_location;
    }

    // Read the length
    uint16_t length = sv_read_byte(&last_two_bytes, &tlv_data_ptr, with_ep);
    sv_tlv_tuple_t tlv = get_tlv_tuple(this_tag);
    if (tlv.bytes_for_length == 2) {
      length <<= 8;
      length |= sv_read_byte(&last_two_bytes, &tlv_data_ptr, with_ep);
    }
    if (tlv_data_ptr + length > tlv_data + tlv_data_size) {
      DEBUG_LOG("TLV length (%u) too large", length);
      return NULL;
    }
    // Scan past the data
    for (int i = 0; i < length; i++) {
      sv_read_byte(&last_two_bytes, &tlv_data_ptr, with_ep);
    }
  }

  return NULL;
}

static bool
tag_is_present(sv_tlv_tag_t tag, const sv_tlv_tag_t *tags, size_t num_of_tags)
{
  for (size_t i = 0; i < num_of_tags; i++) {
    if (tag == tags[i]) {
      return true;
    }
  }

  return false;
}

bool
sv_tlv_find_and_decode_tags(signed_video_t *self,
    const uint8_t *tlv_data,
    size_t tlv_data_size,
    const sv_tlv_tag_t *tags,
    size_t num_of_tags)
{
  const uint8_t *tlv_data_ptr = tlv_data;

  if (!self || !tlv_data || tlv_data_size == 0) return false;

  svrc_t status = SV_UNKNOWN_FAILURE;
  int decoded_tags = 0;
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
    if (tag_is_present(this_tag, tags, num_of_tags)) {
      sv_tlv_decoder_t decoder = get_decoder(this_tag);
      status = decoder(self, tlv_data_ptr, length);
      if (status != SV_OK) {
        DEBUG_LOG("Could not decode tlv values");
        break;
      }
      decoded_tags++;
    }
    tlv_data_ptr += length;
  }

  return decoded_tags > 0;
}

const sv_tlv_tag_t *
sv_get_optional_tags(size_t *num_of_optional_tags)
{
  *num_of_optional_tags = ARRAY_SIZE(optional_tags);
  return optional_tags;
}

const sv_tlv_tag_t *
sv_get_mandatory_tags(size_t *num_of_mandatory_tags)
{
  *num_of_mandatory_tags = ARRAY_SIZE(mandatory_tags);
  return mandatory_tags;
}

sv_tlv_tag_t
sv_get_signature_tag()
{
  return SIGNATURE_TAG;
}

size_t
sv_read_64bits(const uint8_t *p, uint64_t *val)
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
sv_read_64bits_signed(const uint8_t *p, int64_t *val)
{
  uint64_t tmp_val = 0;
  size_t bytes_read = sv_read_64bits(p, &tmp_val);
  *val = (int64_t)tmp_val;
  return bytes_read;
}

size_t
sv_read_32bits(const uint8_t *p, uint32_t *val)
{
  if (!p || !val) return 0;
  *val = ((uint32_t)p[0]) << 24;
  *val += ((uint32_t)p[1]) << 16;
  *val += ((uint32_t)p[2]) << 8;
  *val += (uint32_t)p[3];

  return 4;
}

size_t
sv_read_16bits(const uint8_t *p, uint16_t *val)
{
  if (!p || !val) return 0;
  *val = ((uint16_t)p[0]) << 8;
  *val += (uint16_t)p[1];

  return 2;
}

size_t
sv_read_8bits(const uint8_t *p, uint8_t *val)
{
  if (!p || !val) return 0;
  *val = *p;

  return 1;
}

uint8_t
sv_read_byte(uint16_t *last_two_bytes, const uint8_t **data, bool do_emulation_prevention)
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
sv_write_byte(uint16_t *last_two_bytes,
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
sv_write_byte_many(uint8_t **dst,
    char *src,
    size_t size,
    uint16_t *last_two_bytes,
    bool do_emulation_prevention)
{
  if (!src) return;

  for (size_t ii = 0; ii < size; ++ii) {
    uint8_t ch = src[ii];
    sv_write_byte(last_two_bytes, dst, ch, do_emulation_prevention);
  }
}
