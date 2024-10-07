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
#include "legacy/legacy_tlv.h"

#ifdef PRINT_DECODED_SEI
#include <stdio.h>
#endif
#include <string.h>

#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
#include "axis-communications/sv_vendor_axis_communications_internal.h"
#endif
#include "includes/signed_video_common.h"  // Return codes
#include "includes/signed_video_openssl.h"  // sign_or_verify_data_t
#include "signed_video_authenticity.h"  // allocate_memory_and_copy_string, transfer_product_info()
#include "signed_video_openssl_internal.h"  // openssl_public_key_malloc()
#include "signed_video_tlv.h"  // read_8bits, read_16bits, read_32bits, read_64bits_signed

/**
 * Decoder interfaces
 */

/**
 * @brief TLV decoder interface
 *
 * @param data Pointer to the data to decode.
 * @param data_size Size of the data.
 * @param legacy_sv_t The Signed Video object to write to.
 *
 * @returns SV_OK if successful otherwise an error code.
 */
typedef svrc_t (*legacy_sv_tlv_decoder_t)(legacy_sv_t *, const uint8_t *, size_t);

/**
 * Declarations of decoder implementations.
 */
static svrc_t
legacy_decode_general(legacy_sv_t *self, const uint8_t *data, size_t data_size);

static svrc_t
legacy_decode_public_key(legacy_sv_t *self, const uint8_t *data, size_t data_size);

static svrc_t
legacy_decode_arbitrary_data(legacy_sv_t *self, const uint8_t *data, size_t data_size);

static svrc_t
legacy_decode_product_info(legacy_sv_t *self, const uint8_t *data, size_t data_size);

static svrc_t
legacy_decode_hash_list(legacy_sv_t *self, const uint8_t *data, size_t data_size);

static svrc_t
legacy_decode_signature(legacy_sv_t *self, const uint8_t *data, size_t data_size);

static svrc_t
legacy_decode_crypto_info(legacy_sv_t *self, const uint8_t *data, size_t data_size);

// Vendor specific decoders. Serves as wrappers of vendor specific calls with
// |vendor_handle| as input.
static svrc_t
legacy_decode_axis_communications(legacy_sv_t *self, const uint8_t *data, size_t data_size);

/**
 * Definition of a TLV tuple associating the TLV Tag with an encoder, a decoder and the number of
 * bytes to represent the Length.
 */
typedef struct {
  sv_tlv_tag_t tag;
  uint8_t bytes_for_length;
  legacy_sv_tlv_decoder_t decoder;
  bool is_always_present;
} legacy_sv_tlv_tuple_t;

/**
 * This is an array of all available TLV tuples. The first and last tuples, which are invalid tags,
 * have dummy values to avoid the risk of reading outside memory.
 *
 * NOTE: They HAVE TO be in the same order as the available tags!
 *
 * When you add a new tag you have to add the tuple to this array as well.
 */
static const legacy_sv_tlv_tuple_t tlv_tuples[] = {
    {UNDEFINED_TAG, 0, NULL, true},
    {GENERAL_TAG, 1, legacy_decode_general, true},
    {PUBLIC_KEY_TAG, 2, legacy_decode_public_key, false},
    {PRODUCT_INFO_TAG, 2, legacy_decode_product_info, false},
    {HASH_LIST_TAG, 2, legacy_decode_hash_list, true},
    {SIGNATURE_TAG, 2, legacy_decode_signature, true},
    {ARBITRARY_DATA_TAG, 2, legacy_decode_arbitrary_data, true},
    {CRYPTO_INFO_TAG, 1, legacy_decode_crypto_info, false},
    {NUMBER_OF_TLV_TAGS, 0, NULL, true},
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
static const legacy_sv_tlv_tuple_t vendor_tlv_tuples[] = {
    {UNDEFINED_VENDOR_TAG, 0, NULL, true},
    {VENDOR_AXIS_COMMUNICATIONS_TAG, 2, legacy_decode_axis_communications, false},
    {NUMBER_OF_VENDOR_TLV_TAGS, 0, NULL, true},
};

/**
 * Declarations of STATIC functions.
 */
static legacy_sv_tlv_decoder_t
legacy_get_decoder(sv_tlv_tag_t tag);
static legacy_sv_tlv_tuple_t
legacy_get_tlv_tuple(sv_tlv_tag_t tag);
static svrc_t
legacy_decode_tlv_header(const uint8_t *data,
    size_t *data_bytes_read,
    sv_tlv_tag_t *tag,
    size_t *length);

/* Selects and returns the correct decoder from either |tlv_tuples| or |vendor_tlv_tuples|. */
static legacy_sv_tlv_decoder_t
legacy_get_decoder(sv_tlv_tag_t tag)
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
static legacy_sv_tlv_tuple_t
legacy_get_tlv_tuple(sv_tlv_tag_t tag)
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
 * @brief Decodes the GENERAL_TAG from data
 */
static svrc_t
legacy_decode_general(legacy_sv_t *self, const uint8_t *data, size_t data_size)
{
  if (!self || !data) return SV_INVALID_PARAMETER;

  const uint8_t *data_ptr = data;
  legacy_gop_info_t *gop_info = self->gop_info;
  uint8_t version = *data_ptr++;
  char sw_version_str[SV_VERSION_MAX_STRLEN] = {0};
  char *code_version_str = sw_version_str;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW_IF(version < 1 || version > 2, SV_INCOMPATIBLE_VERSION);

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
#endif
  SV_CATCH()
  SV_DONE(status)

  return status;
}

/**
 * @brief Decodes the PRODUCT_INFO_TAG from data
 */
static svrc_t
legacy_decode_product_info(legacy_sv_t *self, const uint8_t *data, size_t data_size)
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
    SV_THROW(transfer_product_info(&self->authenticity->product_info, product_info));

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
 * @brief Decodes the ARBITRARY_DATA_TAG from data
 */
static svrc_t
legacy_decode_arbitrary_data(legacy_sv_t *self, const uint8_t *data, size_t data_size)
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
 * @brief Decodes the PUBLIC_KEY_TAG from data
 *
 */
static svrc_t
legacy_decode_public_key(legacy_sv_t *self, const uint8_t *data, size_t data_size)
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
    if (self->has_public_key && key_diff) {
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
 * @brief Decodes the HASH_LIST_TAG from data
 */
static svrc_t
legacy_decode_hash_list(legacy_sv_t *self, const uint8_t *data, size_t data_size)
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
#ifdef PRINT_DECODED_SEI
    size_t hash_size = openssl_get_hash_size(self->crypto_handle);
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
 * @brief Decodes the SIGNATURE_TAG from data
 */
static svrc_t
legacy_decode_signature(legacy_sv_t *self, const uint8_t *data, size_t data_size)
{
  const uint8_t *data_ptr = data;
  legacy_gop_info_t *gop_info = self->gop_info;
  sign_or_verify_data_t *verify_data = self->verify_data;
  uint8_t **signature_ptr = &verify_data->signature;
  uint8_t version = *data_ptr++;
  uint8_t encoding_status = *data_ptr++;
  legacy_hash_type_t hash_type = *data_ptr++;
  uint16_t signature_size = 0;
  size_t max_signature_size = 0;

  // Read true size of the signature.
  data_ptr += read_16bits(data_ptr, &signature_size);
  // The rest of the value bytes should now be the allocated size for the signature.
  max_signature_size = data_size - (data_ptr - data);

  svrc_t status = SV_UNKNOWN_FAILURE;

  SV_TRY()
    SV_THROW_IF(version == 0, SV_INCOMPATIBLE_VERSION);
    SV_THROW_IF(hash_type < 0 || hash_type >= LEGACY_NUM_HASH_TYPES, SV_AUTHENTICATION_ERROR);
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
 * @brief Decodes the CRYPTO_INFO_TAG from data
 */
static svrc_t
legacy_decode_crypto_info(legacy_sv_t *self, const uint8_t *data, size_t data_size)
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
    self->verify_data->hash_size = openssl_get_hash_size(self->crypto_handle);
    data_ptr += hash_algo_encoded_oid_size;

    SV_THROW_IF(data_ptr != data + data_size, SV_AUTHENTICATION_ERROR);
  SV_CATCH()
  SV_DONE(status)

  return status;
}

// Vendor specific encoders and decoders.

/**
 * @brief Decodes the VENDOR_AXIS_COMMUNICATIONS_TAG from data
 *
 */
static svrc_t
#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
legacy_decode_axis_communications(legacy_sv_t *self, const uint8_t *data, size_t data_size)
{
  return decode_axis_communications_handle(self->vendor_handle, data, data_size);
#else
legacy_decode_axis_communications(legacy_sv_t ATTR_UNUSED *self,
    const uint8_t ATTR_UNUSED *data,
    size_t ATTR_UNUSED data_size)
{
  // Vendor Axis Communications not selected.
  return SV_NOT_SUPPORTED;
#endif
}

static svrc_t
legacy_decode_tlv_header(const uint8_t *data,
    size_t *data_bytes_read,
    sv_tlv_tag_t *tag,
    size_t *length)
{
  // Sanity checks on input parameters.
  if (!data || !data_bytes_read || !tag || !length) return SV_INVALID_PARAMETER;

  const uint8_t *data_ptr = data;
  sv_tlv_tag_t tag_from_data = (sv_tlv_tag_t)(*data_ptr++);
  *data_bytes_read = 0;
  legacy_sv_tlv_tuple_t tlv = legacy_get_tlv_tuple(tag_from_data);
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
legacy_tlv_decode(legacy_sv_t *self, const uint8_t *data, size_t data_size)
{
  svrc_t status = SV_INVALID_PARAMETER;
  const uint8_t *data_ptr = data;

  if (!self || !data || data_size == 0) return SV_INVALID_PARAMETER;

  while (data_ptr < data + data_size) {
    sv_tlv_tag_t tag = 0;
    size_t tlv_header_size = 0;
    size_t length = 0;
    status = legacy_decode_tlv_header(data_ptr, &tlv_header_size, &tag, &length);
    if (status != SV_OK) {
      DEBUG_LOG("Could not decode TLV header (error %d)", status);
      break;
    }
    data_ptr += tlv_header_size;

    legacy_sv_tlv_decoder_t decoder = legacy_get_decoder(tag);
    status = decoder(self, data_ptr, length);
    if (status != SV_OK) {
      DEBUG_LOG("Could not decode data (error %d)", status);
      break;
    }
    data_ptr += length;
  }

  return status;
}

bool
legacy_tlv_find_and_decode_optional_tags(legacy_sv_t *self,
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
    status = legacy_decode_tlv_header(tlv_data_ptr, &tlv_header_size, &this_tag, &length);
    if (status != SV_OK) {
      DEBUG_LOG("Could not decode tlv header");
      break;
    }
    tlv_data_ptr += tlv_header_size;
    if (!tlv_tuples[this_tag].is_always_present) {
      legacy_sv_tlv_decoder_t decoder = legacy_get_decoder(this_tag);
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
