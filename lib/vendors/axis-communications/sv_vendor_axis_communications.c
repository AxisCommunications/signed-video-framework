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
#include "includes/sv_vendor_axis_communications.h"

#include <openssl/bio.h>  // BIO_*
#include <openssl/evp.h>  // EVP_*
#include <openssl/pem.h>  // PEM_*
#include <openssl/x509.h>  // X509_*
#include <stdbool.h>
#include <stdlib.h>  // malloc, memcpy, calloc, free

#include "includes/signed_video_openssl.h"
#include "signed_video_internal.h"
#include "signed_video_tlv.h"
#include "sv_vendor_axis_communications_internal.h"
#include "sv_vendor_axis_communications_internal_tests.h"

// List of TLV encoders to include in SEI.
#define AXIS_COMMUNICATIONS_NUM_ENCODERS 1
static const sv_tlv_tag_t axis_communications_encoders[AXIS_COMMUNICATIONS_NUM_ENCODERS] = {
    VENDOR_AXIS_COMMUNICATIONS_TAG,
};

#define CHIP_ID_SIZE 18
#define CHIP_ID_PREFIX_SIZE 4
#define NUM_UNTRUSTED_CERTIFICATES 2  // Expect 2 untrusted certificates in |certificate_chain|
#define PUBLIC_KEY_UNCOMPRESSED_SIZE 65
#define PUBLIC_KEY_UNCOMPRESSED_PREFIX 0x04
#define BINARY_RAW_DATA_SIZE 40
#define AXIS_EDGE_VAULT_ATTESTATION_STR "Axis Edge Vault Attestation "

static const char *kTrustedAxisRootCA =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIClDCCAfagAwIBAgIBATAKBggqhkjOPQQDBDBcMR8wHQYDVQQKExZBeGlzIENv\n"
    "bW11bmljYXRpb25zIEFCMRgwFgYDVQQLEw9BeGlzIEVkZ2UgVmF1bHQxHzAdBgNV\n"
    "BAMTFkF4aXMgRWRnZSBWYXVsdCBDQSBFQ0MwHhcNMjAxMDI2MDg0MzEzWhcNMzUx\n"
    "MDI2MDg0MzEzWjBcMR8wHQYDVQQKExZBeGlzIENvbW11bmljYXRpb25zIEFCMRgw\n"
    "FgYDVQQLEw9BeGlzIEVkZ2UgVmF1bHQxHzAdBgNVBAMTFkF4aXMgRWRnZSBWYXVs\n"
    "dCBDQSBFQ0MwgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABAEmfjxRiTrvjLZol9gG\n"
    "3YCUxcoWihbz2L3+6sp120I+KA/tLhYIDMais32M0tAqld5VDo1FWvi6kEVtqQn4\n"
    "3+rOzgH8XkXolP+QFNSdKUPyJawnM4B9/jPZ6OA5bG7R1CNKmP4JpkYWqrD22hjc\n"
    "AV9Hf/hz5TK2pc5IBHIxZyMcnlBc26NmMGQwHQYDVR0OBBYEFJBaAarD0kirmPmR\n"
    "vCdrM6kt0XChMB8GA1UdIwQYMBaAFJBaAarD0kirmPmRvCdrM6kt0XChMBIGA1Ud\n"
    "EwEB/wQIMAYBAf8CAQEwDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMEA4GLADCB\n"
    "hwJBUfwiBK0TIRJebWm9/nsNAEkjbxao40oeMUg+I3mDNr7guNJUo4ugOfToGpnm\n"
    "3QLOhEJzyHqPBHTChxEd5bGVUW8CQgDR/ZAr405Ohk5kpM/gmzELP+fYDZfuTFut\n"
    "w3S8HMYSvMWbTCzN+qnq+GV1goSS6vjVr95EpDxCVIxkKOvuxhyVDg==\n"
    "-----END CERTIFICATE-----\n";

#define ATTRIBUTES_LENGTH 37
static const uint8_t kAttributes[ATTRIBUTES_LENGTH] = {0x7b, 0x00, 0x02, 0x01, 0x29, 0x01, 0x00,
    0x00, 0x7b, 0x00, 0x00, 0x03, 0x00, 0x00, 0x08, 0x7b, 0x00, 0x00, 0x03, 0x1f, 0x3c, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00};

#define FRESHNESS_LENGTH 16
static const uint8_t kFreshness[FRESHNESS_LENGTH] = {
    0x92, 0xbb, 0xed, 0xfb, 0x98, 0x82, 0xac, 0x16, 0xc7, 0xf0, 0x1a, 0xe4, 0x59, 0x05, 0x96, 0x04};

#define SIGNED_DATA_SIZE (HASH_DIGEST_SIZE + 52 + PUBLIC_KEY_UNCOMPRESSED_SIZE + ATTRIBUTES_LENGTH)

#define OBJECT_ID_SIZE 4
#define TIMESTAMP_SIZE 12
struct attestation_report {
  // Header
  uint8_t header[2];
  // Version of the report
  uint8_t version[2];
  // The ID of a Secure Element object
  uint8_t object_id[OBJECT_ID_SIZE];
  // An array of attestation reports, but only one element is supported
  size_t attestation_list_length;
  // Store a single element in |attestation_list|, since only one is expected and correct
  struct attestation_data {
    // The timestamp for this attestation part
    uint8_t timestamp[TIMESTAMP_SIZE];
    // The signature data
    size_t signature_size;
    uint8_t signature[512];
  } attestation_list;
};

// Definition of |vendor_handle|.
typedef struct _sv_vendor_axis_communications_t {
  void *attestation;
  uint8_t attestation_size;
  char *certificate_chain;

  // Public key to validate using |attestation| and |certificate_chain|
  void *public_key;  // The public key used for validation in a pem file format.
  size_t public_key_size;  // The size of the |public_key|.

  // Information needed for public key validation, but can be created once.
  EVP_MD_CTX *md_ctx;  // ctx for verifying the public key
  X509 *trusted_ca;  // The trusted Axis root CA in X509 form
  uint8_t chip_id[CHIP_ID_SIZE];
  struct attestation_report attestation_report;
  bool attestation_certificate_is_valid;

  // Public key validation results
  svi_rc pubkey_verification_status;
  sv_vendor_axis_supplemental_authenticity_t supplemental_authenticity;

  // Setter used by tests
  bool verify_pubkey_upon_call;
} sv_vendor_axis_communications_t;

// Declarations of static functions.
static svi_rc
verify_and_parse_certificate_chain(sv_vendor_axis_communications_t *self);
static svi_rc
deserialize_attestation(sv_vendor_axis_communications_t *self);
static svi_rc
verify_certificate_chain(X509 *trusted_ca, STACK_OF(X509) * untrusted_certificates);
static size_t
get_untrusted_certificates_size(const sv_vendor_axis_communications_t *self);
static svi_rc
verify_axis_communications_public_key(sv_vendor_axis_communications_t *self);

// Definitions of static functions.

/* Puts the untrusted certificate chain in a stack of certificates of form X509. This stack is then
 * verified against the trusted Axis root CA. Upon success, parses |chip_id|, |serial_number| and
 * gets the public key from the |attestation_certificate|. Further, a message digest context
 * |md_ctx| is created and initiated.
 *
 * If all goes well, ownership of |md_ctx| is transfered to |self|.
 */
static svi_rc
verify_and_parse_certificate_chain(sv_vendor_axis_communications_t *self)
{
  if (!self || !self->certificate_chain) return SVI_INVALID_PARAMETER;

  BIO *stackbio = NULL;
  EVP_MD_CTX *md_ctx = NULL;
  STACK_OF(X509) *untrusted_certificates = NULL;
  int num_certificates = 0;
  ASN1_STRING *entry_data = NULL;
  const uint8_t kChipIDPrefix[CHIP_ID_PREFIX_SIZE] = {0x04, 0x00, 0x50, 0x01};

  self->attestation_certificate_is_valid = false;

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    stackbio = BIO_new_mem_buf(self->certificate_chain, strlen(self->certificate_chain));
    SVI_THROW_IF(!stackbio, SVI_VENDOR);

    untrusted_certificates = sk_X509_new_null();
    SVI_THROW_IF(!untrusted_certificates, SVI_VENDOR);
    sk_X509_zero(untrusted_certificates);

    // Turn |certificate_chain| into stack of X509.
    // Loop through |certificate_chain|, with a hard coded maximum number of certificates to avoid
    // deadlock, i.e., if we extract at least NUM_UNTRUSTED_CERTIFICATES + 1 certificates, something
    // is wrong.
    X509 *certificate = PEM_read_bio_X509(stackbio, NULL, NULL, NULL);
    X509 *attestation_certificate = certificate;
    while (certificate && num_certificates < NUM_UNTRUSTED_CERTIFICATES + 1) {
      num_certificates = sk_X509_push(untrusted_certificates, certificate);
      certificate = PEM_read_bio_X509(stackbio, NULL, NULL, NULL);
    }
    SVI_THROW_IF(num_certificates > NUM_UNTRUSTED_CERTIFICATES, SVI_VENDOR);

    SVI_THROW(verify_certificate_chain(self->trusted_ca, untrusted_certificates));

    // Extract |chip_id| from the |attestation_certificate|.
    X509_NAME *subject = X509_get_subject_name(attestation_certificate);
    int common_name_index = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
    if (common_name_index >= 0) {
      entry_data = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subject, common_name_index));
      unsigned char *common_name_str;
      if (ASN1_STRING_to_UTF8(&common_name_str, entry_data) > 0) {
        // Find the Chip ID string.
        char *chip_id_str = strstr((char *)common_name_str, AXIS_EDGE_VAULT_ATTESTATION_STR);
        if (chip_id_str) {
          char *pos = chip_id_str + strlen(AXIS_EDGE_VAULT_ATTESTATION_STR);
          size_t chip_id_size = strlen(pos);
          // Note that chip id is displayed in hexadecimal form.
          SVI_THROW_IF(chip_id_size != CHIP_ID_SIZE * 2, SVI_VENDOR);
          for (int idx = 0; idx < CHIP_ID_SIZE; idx++, pos += 2) {
            sscanf(pos, "%2hhx", &self->chip_id[idx]);
          }
          // Check that the chip ID has correct prefix.
          SVI_THROW_IF(memcmp(self->chip_id, kChipIDPrefix, CHIP_ID_PREFIX_SIZE) != 0, SVI_VENDOR);
        }
        free(common_name_str);
      }
    }
    // Extract |serial_number| from the |attestation_certificate|.
    int ser_no_idx = X509_NAME_get_index_by_NID(subject, NID_serialNumber, -1);
    if (ser_no_idx >= 0) {
      entry_data = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subject, ser_no_idx));
      unsigned char *serial_number = NULL;
      // If no serial number can be found, copy "Unknown" to |serial_number|.
      if (ASN1_STRING_to_UTF8(&serial_number, entry_data) <= 0) {
        memset(self->supplemental_authenticity.serial_number, 0, SV_VENDOR_AXIS_SER_NO_MAX_LENGTH);
        strcpy(self->supplemental_authenticity.serial_number, "Unknown");
      } else if (strcmp(self->supplemental_authenticity.serial_number, (char *)serial_number)) {
        // Serial number differ. Copy to |supplemental_authenticity|.
        memset(self->supplemental_authenticity.serial_number, 0, SV_VENDOR_AXIS_SER_NO_MAX_LENGTH);
        strcpy(self->supplemental_authenticity.serial_number, (char *)serial_number);
      }
      free(serial_number);
    }

    // Get public key from |attestation_certificate| and verify it.
    EVP_PKEY *pub_attestation_key = X509_get0_pubkey(attestation_certificate);
    SVI_THROW_IF(!pub_attestation_key, SVI_VENDOR);
    SVI_THROW_IF(EVP_PKEY_base_id(pub_attestation_key) != EVP_PKEY_EC, SVI_VENDOR);
    // Create a new message digest context and initiate it.
    md_ctx = EVP_MD_CTX_new();
    SVI_THROW_IF(!md_ctx, SVI_EXTERNAL_FAILURE);
    SVI_THROW_IF(EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pub_attestation_key) < 1,
        SVI_EXTERNAL_FAILURE);

    // Successfully extraced necessary information and verified the |attestation_certificate|.
    self->attestation_certificate_is_valid = true;

    // Transfer ownership.
    if (self->md_ctx) EVP_MD_CTX_free(self->md_ctx);
    self->md_ctx = md_ctx;

  SVI_CATCH()
  {
    EVP_MD_CTX_free(md_ctx);
  }
  SVI_DONE(status)

  OPENSSL_free(untrusted_certificates);
  BIO_free(stackbio);

  return status;
}

/* Deserializes |attestation| into |attestation_report|.
 * The structure of |attestation| is:
 *   - header (2 bytes)
 *   - version (2 bytes)
 *   - object_id (4 bytes)
 *   - attestation_list_length (1 byte) NOTE: Only support one list item
 *   - attestation_list
 *     - timestamp (12 bytes)
 *     - signature_size (2 bytes)
 *     - signature (|signature_size| bytes) */
static svi_rc
deserialize_attestation(sv_vendor_axis_communications_t *self)
{
  uint8_t *attestation_ptr = (uint8_t *)self->attestation;
  size_t signature_size = 0;

  if (!self->attestation) return SVI_VENDOR;
  // The |attestation_size| has to be at least 23 bytes to be deserialized.
  if (self->attestation_size < 24) return SVI_VENDOR;

  // Check if |attestation_list_length| != 1 before deserializing.
  if (*(attestation_ptr + 8) != 1) {
    DEBUG_LOG("Attestation has more than 1 item in attestation list.");
    return SVI_VENDOR;
  }
  // Copy header (2 bytes)
  memcpy(self->attestation_report.header, attestation_ptr, 2);
  attestation_ptr += 2;
  // Copy version (2 bytes)
  memcpy(self->attestation_report.version, attestation_ptr, 2);
  attestation_ptr += 2;
  // Copy object_id (4 bytes)
  memcpy(self->attestation_report.object_id, attestation_ptr, 4);
  attestation_ptr += 4;
  // Copy attestation_list_length (1 byte)
  memcpy(&self->attestation_report.attestation_list_length, attestation_ptr, 1);
  attestation_ptr += 1;
  // Copy timestamp (12 byte)
  memcpy(self->attestation_report.attestation_list.timestamp, attestation_ptr, 12);
  attestation_ptr += 12;
  // Copy signature_size (2 byte)
  signature_size = (*attestation_ptr << 8) + *(attestation_ptr + 1);
  attestation_ptr += 2;
  if (attestation_ptr + signature_size != self->attestation + (size_t)self->attestation_size) {
    return SVI_VENDOR;
  }
  self->attestation_report.attestation_list.signature_size = signature_size;
  // Copy signature (signature_size byte)
  memcpy(self->attestation_report.attestation_list.signature, attestation_ptr, signature_size);
  attestation_ptr += signature_size;

  return SVI_OK;
}

/* Verifies the untrusted certificate chain.
 *
 * Uses the |trusted_ca| to verify the first certificate in the chain. The last certificate verified
 * is the |attestation_certificate| which is used to verify the transmitted public key. */
static svi_rc
verify_certificate_chain(X509 *trusted_ca, STACK_OF(X509) * untrusted_certificates)
{
  X509_STORE *store = NULL;
  X509_STORE_CTX *ctx = NULL;

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    store = X509_STORE_new();
    SVI_THROW_IF(!store, SVI_VENDOR);
    // Load trusted CA certificate(s)
    SVI_THROW_IF(X509_STORE_add_cert(store, trusted_ca) != 1, SVI_VENDOR);

    ctx = X509_STORE_CTX_new();
    SVI_THROW_IF(!ctx, SVI_VENDOR);

    // The |attestation_certificate| is the first certificate in the stack, which is the final
    // certificate to verify.
    X509 *attestation_certificate = sk_X509_value(untrusted_certificates, 0);
    SVI_THROW_IF(
        X509_STORE_CTX_init(ctx, store, attestation_certificate, untrusted_certificates) != 1,
        SVI_VENDOR);
    SVI_THROW_IF(X509_verify_cert(ctx) != 1, SVI_VENDOR);

  SVI_CATCH()
  SVI_DONE(status)

  X509_STORE_CTX_free(ctx);
  X509_STORE_free(store);

  return status;
}

/* This function finds the beginning of the last certificate, which is the trusted public Axis root
 * CA certificate. The size of the other certificates is returned. If the last certificate differs
 * from what is expected, or if number of certificates is not equal to three, 0 is returned.
 *
 * Note that the returned size excludes any null-terminated characters.
 */
static size_t
get_untrusted_certificates_size(const sv_vendor_axis_communications_t *self)
{
  size_t certificate_chain_encode_size = 0;

  // Find the start of the third certificate in |certificate_chain|, which should be the
  // |kTrustedAxisRootCA|.
  const char *cert_chain_ptr = self->certificate_chain;
  const char *cert_ptr = self->certificate_chain;
  int certs_left = NUM_UNTRUSTED_CERTIFICATES + 1;
  while (certs_left > 0 && cert_ptr) {
    cert_ptr = strstr(cert_chain_ptr, "-----BEGIN CERTIFICATE-----");
    certs_left--;
    cert_chain_ptr = cert_ptr + 1;
  }
  // Check if |cert_ptr| is the third certificate and compare it against expected
  // |kTrustedAxisRootCA|.
  if ((certs_left == 0) && cert_ptr && (strcmp(cert_ptr, kTrustedAxisRootCA) == 0)) {
    certificate_chain_encode_size = cert_ptr - self->certificate_chain;
  }

  return certificate_chain_encode_size;
}

/* Verifies the transmitted public key, given the |attestation| and |certificate_chain|.
 *
 * This function should be called before using the transmitted public key.
 *
 * The procedure is to construct data following the same scheme as on camera and then verify
 * the signature with it. */
static svi_rc
verify_axis_communications_public_key(sv_vendor_axis_communications_t *self)
{
  if (!self) return SVI_INVALID_PARAMETER;

  BIO *bio = NULL;
  EVP_PKEY *pkey = NULL;
  uint8_t *public_key_uncompressed = NULL;
  size_t public_key_uncompressed_size = 0;
  uint8_t *signed_data = NULL;
  // Initiate verification to not feasible/error.
  int verified_signature = -1;

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    SVI_THROW_IF(!self->attestation_certificate_is_valid, SVI_VENDOR);
    // Convert |public_key| to uncompressed Weierstrass form
    //   public_key -> BIO -> EVP_PKEY -> EC_KEY -> EC_KEY_key2buf
    bio = BIO_new_mem_buf(self->public_key, (int)self->public_key_size);
    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    const EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
    public_key_uncompressed_size =
        EC_KEY_key2buf(ec_key, POINT_CONVERSION_UNCOMPRESSED, &public_key_uncompressed, NULL);
    SVI_THROW_IF(public_key_uncompressed_size != PUBLIC_KEY_UNCOMPRESSED_SIZE, SVI_VENDOR);
    SVI_THROW_IF(public_key_uncompressed[0] != PUBLIC_KEY_UNCOMPRESSED_PREFIX, SVI_VENDOR);

    // Construct the binary raw data.
    uint8_t binary_raw_data[BINARY_RAW_DATA_SIZE] = {0x80, 0x22, 0x00, 0x00, 0x00, 0x00, 0x21, 0x41,
        0x04, 0xf0, 0x00, 0x00, 0x12, 0x45, 0x04, 0xf0, 0x00, 0x00, 0x12, 0x46, 0x01, 0x21, 0x47,
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00};
    // Add Object ID at positions 9-12
    memcpy(&binary_raw_data[9], kAttributes, OBJECT_ID_SIZE);
    // Add Freshness at positions 24-39
    memcpy(&binary_raw_data[24], kFreshness, FRESHNESS_LENGTH);
    // Hash |binary_raw_data|.
    uint8_t binary_raw_data_hash[HASH_DIGEST_SIZE] = {0};
    SVI_THROW(openssl_hash_data(binary_raw_data, BINARY_RAW_DATA_SIZE, binary_raw_data_hash));
    signed_data = calloc(1, SIGNED_DATA_SIZE);

    // Fill in |signed_data|.
    uint8_t *sd_ptr = signed_data;
    memcpy(sd_ptr, binary_raw_data_hash, HASH_DIGEST_SIZE);
    sd_ptr += HASH_DIGEST_SIZE;
    *sd_ptr++ = 0x41;
    *sd_ptr++ = 0x82;

    *sd_ptr++ = (uint8_t)((PUBLIC_KEY_UNCOMPRESSED_SIZE >> 8) & 0x000000ff);
    *sd_ptr++ = (uint8_t)(PUBLIC_KEY_UNCOMPRESSED_SIZE & 0x000000ff);
    memcpy(sd_ptr, public_key_uncompressed, PUBLIC_KEY_UNCOMPRESSED_SIZE);
    sd_ptr += PUBLIC_KEY_UNCOMPRESSED_SIZE;

    *sd_ptr++ = 0x42;
    *sd_ptr++ = 0x82;
    *sd_ptr++ = 0x00;
    *sd_ptr++ = 0x12;
    memcpy(sd_ptr, self->chip_id, CHIP_ID_SIZE);
    sd_ptr += CHIP_ID_SIZE;

    *sd_ptr++ = 0x43;
    *sd_ptr++ = 0x82;
    *sd_ptr++ = 0x00;
    *sd_ptr++ = ATTRIBUTES_LENGTH;
    memcpy(sd_ptr, kAttributes, ATTRIBUTES_LENGTH);
    sd_ptr += ATTRIBUTES_LENGTH;

    *sd_ptr++ = 0x44;
    *sd_ptr++ = 0x82;
    *sd_ptr++ = 0x00;
    *sd_ptr++ = 0x02;
    *sd_ptr++ = 0x00;
    *sd_ptr++ = 0x20;
    *sd_ptr++ = 0x4f;
    *sd_ptr++ = 0x82;
    *sd_ptr++ = 0x00;
    *sd_ptr++ = 0x0c;
    memcpy(sd_ptr, self->attestation_report.attestation_list.timestamp, TIMESTAMP_SIZE);
    sd_ptr += TIMESTAMP_SIZE;

    verified_signature = EVP_DigestVerify(self->md_ctx,
        self->attestation_report.attestation_list.signature,
        self->attestation_report.attestation_list.signature_size, signed_data, SIGNED_DATA_SIZE);
    SVI_THROW_IF(verified_signature < 0, SVI_EXTERNAL_FAILURE);

    // If verification failes (is 0) the result should never be overwritten with success (1) later.
    self->supplemental_authenticity.public_key_validation &= verified_signature;

  SVI_CATCH()
  SVI_DONE(status)

  if (status == SVI_VENDOR) {
    // A step in the validation process failed. Mark public key as invalid.
    self->supplemental_authenticity.public_key_validation &= 0;
  }
  self->pubkey_verification_status = status;

  free(signed_data);
  free(public_key_uncompressed);
  EVP_PKEY_free(pkey);
  BIO_free(bio);

  return status;
}

// Definitions of non-public APIs, declared in sv_vendor_axis_communications_internal.h.

void *
sv_vendor_axis_communications_setup(void)
{
  sv_vendor_axis_communications_t *self = calloc(1, sizeof(sv_vendor_axis_communications_t));

  if (!self) return NULL;

  // Store the |kTrustedAxisRootCA| in X509 format.
  BIO *ca_bio = BIO_new(BIO_s_mem());
  if (ca_bio) {
    if (BIO_puts(ca_bio, kTrustedAxisRootCA) > 0) {
      // Successfully written |kTrustedAxisRootCA| to |ca_bio|. Convert to X509.
      self->trusted_ca = PEM_read_bio_X509(ca_bio, NULL, NULL, NULL);
    }
    BIO_free(ca_bio);
  }

  // Initialize |public_key_validation| to unknown/error.
  self->supplemental_authenticity.public_key_validation = -1;
  strcpy(self->supplemental_authenticity.serial_number, "Unknown");
  self->pubkey_verification_status = SVI_UNKNOWN;

  if (!self->trusted_ca) {
    DEBUG_LOG("Could not convert Axis root CA to X509");
    sv_vendor_axis_communications_teardown((void *)self);
    self = NULL;
  }

  return (void *)self;
}

void
sv_vendor_axis_communications_teardown(void *handle)
{
  sv_vendor_axis_communications_t *self = (sv_vendor_axis_communications_t *)handle;
  if (!self) return;

  free(self->public_key);
  free(self->attestation);
  free(self->certificate_chain);
  X509_free(self->trusted_ca);
  EVP_MD_CTX_free(self->md_ctx);
  free(self);
}

/* Encodes the handle data into the TLV tag VENDOR_AXIS_COMMUNICATIONS_TAG. */
size_t
encode_axis_communications_handle(void *handle, uint16_t *last_two_bytes, uint8_t *data)
{
  sv_vendor_axis_communications_t *self = (sv_vendor_axis_communications_t *)handle;
  if (!self) return 0;

  size_t data_size = 0;
  // Get the size of the untrusted certificates that will be added to the tag.
  size_t certificate_chain_encode_size = get_untrusted_certificates_size(self);
  const uint8_t version = 1;  // Increment when the change breaks the format

  // If there is no attestation report or certificate chain, skip encoding, that is return 0.
  if (!self->attestation || !self->certificate_chain) return 0;

  // Version 1:
  //  - version (1 byte)
  //  - attestation_size (1 byte)
  //  - attestation (attestation_size bytes)
  //  - certificate_chain (certificate_chain_size bytes) excluding |kTrustedAxisRootCA|

  data_size += sizeof(version);
  // Size of attestation report
  data_size += 1;  // To write |attestation_size|
  data_size += self->attestation_size;  // To write |attestation|

  // Size of certificate chain
  data_size += certificate_chain_encode_size;

  if (!data) return data_size;

  uint8_t *data_ptr = data;
  uint8_t *attestation = self->attestation;

  // Write version.
  write_byte(last_two_bytes, &data_ptr, version, true);
  // Write |attestation_size|.
  write_byte(last_two_bytes, &data_ptr, self->attestation_size, true);
  // Write |attestation|.
  for (size_t jj = 0; jj < self->attestation_size; ++jj) {
    write_byte(last_two_bytes, &data_ptr, attestation[jj], true);
  }
  // Write |certificate_chain|.
  write_byte_many(
      &data_ptr, self->certificate_chain, certificate_chain_encode_size, last_two_bytes, true);

  return (data_ptr - data);
}

/* Dencodes the TLV tag VENDOR_AXIS_COMMUNICATIONS_TAG to the handle data. */
svi_rc
decode_axis_communications_handle(void *handle, const uint8_t *data, size_t data_size)
{
  sv_vendor_axis_communications_t *self = (sv_vendor_axis_communications_t *)handle;
  if (!self) return SVI_INVALID_PARAMETER;

  const uint8_t *data_ptr = data;
  uint8_t version = *data_ptr++;
  uint8_t attestation_size = 0;
  size_t cert_size = 0;

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    SVI_THROW_IF(version != 1, SVI_INCOMPATIBLE_VERSION);
    // Read |attestation_size|.
    attestation_size = *data_ptr++;
    SVI_THROW_IF(attestation_size == 0, SVI_NOT_SUPPORTED);
    // Allocate memory for |attestation|.
    if (!self->attestation) {
      self->attestation = malloc(attestation_size);
      SVI_THROW_IF(!self->attestation, SVI_MEMORY);
      // Read |attestation|
      memcpy(self->attestation, data_ptr, attestation_size);
      self->attestation_size = attestation_size;
    }
    // Check if the received |attestation| differ from the present one. If so, return
    // SVI_NOT_SUPPORTED, since a change in attestation is not allowed.
    SVI_THROW_IF(attestation_size != self->attestation_size, SVI_NOT_SUPPORTED);
    SVI_THROW_IF(memcmp(data_ptr, self->attestation, attestation_size), SVI_NOT_SUPPORTED);
    // Move pointer past |attestation|
    data_ptr += attestation_size;

    // Determine size of |certificate_chain|. Equals |data_size| minus
    //  - 1 byte for version
    //  - 1 bytes for |attestation_size|
    //  - |attestation_size| bytes for |attestation|
    SVI_THROW_IF(data_size <= (size_t)attestation_size + 2, SVI_DECODING_ERROR);
    cert_size = data_size - attestation_size - 2;

    // Allocate memory for |certificate_chain| including null-terminated character.
    if (!self->certificate_chain) {
      self->certificate_chain = calloc(1, cert_size + 1);
      SVI_THROW_IF(!self->certificate_chain, SVI_MEMORY);
      memcpy(self->certificate_chain, data_ptr, cert_size);
    }
    SVI_THROW_IF(memcmp(data_ptr, self->certificate_chain, cert_size), SVI_NOT_SUPPORTED);
    // Move pointer past |certificate_chain|
    data_ptr += cert_size;

    SVI_THROW_IF(data_ptr != data + data_size, SVI_DECODING_ERROR);

    // Prepare for public key validation by verifying the attestation certificate and parsing data.
    if (!self->verify_pubkey_upon_call) {
      SVI_THROW(verify_and_parse_certificate_chain(self));
      SVI_THROW(deserialize_attestation(self));
    }

  SVI_CATCH()
  SVI_DONE(status)

  return status;
}

svi_rc
set_axis_communications_public_key(void *handle, const void *public_key, size_t public_key_size)
{
  if (!handle || !public_key || public_key_size == 0) return SVI_INVALID_PARAMETER;

  sv_vendor_axis_communications_t *self = (sv_vendor_axis_communications_t *)handle;
  EVP_PKEY *verify_key = NULL;

  // Mark |public_key_validation| as invalid if a different public_key is set. It is an invalid
  // operation. Note that it is not an error, only an invalid operation and will be communicated
  // through |sv_vendor_axis_supplemental_authenticity_t|.
  if (self->public_key && memcmp(public_key, self->public_key, public_key_size)) {
    self->supplemental_authenticity.public_key_validation = 0;
  }

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    if (!self->public_key) {
      self->public_key = calloc(1, public_key_size);
      SVI_THROW_IF(!self->public_key, SVI_MEMORY);
      memcpy(self->public_key, public_key, public_key_size);
      self->public_key_size = public_key_size;

      // Validate that the public key is of correct type and size.
      BIO *bp = BIO_new_mem_buf(self->public_key, (int)self->public_key_size);
      verify_key = PEM_read_bio_PUBKEY(bp, NULL, NULL, NULL);
      BIO_free(bp);
      SVI_THROW_IF(!verify_key, SVI_EXTERNAL_FAILURE);

      // Ensure it is a NIST P-256 key with correct curve.
      SVI_THROW_IF(EVP_PKEY_base_id(verify_key) != EVP_PKEY_EC, SVI_EXTERNAL_FAILURE);
      const EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(verify_key);
      SVI_THROW_IF(!ec_key, SVI_EXTERNAL_FAILURE);
      const EC_GROUP *ec_group = EC_KEY_get0_group(ec_key);
      SVI_THROW_IF(!ec_group, SVI_EXTERNAL_FAILURE);
      SVI_THROW_IF(EC_GROUP_get_curve_name(ec_group) != NID_X9_62_prime256v1, SVI_EXTERNAL_FAILURE);
    }

    if (!self->verify_pubkey_upon_call) {
      SVI_THROW(verify_axis_communications_public_key(self));
    }
  SVI_CATCH()
  SVI_DONE(status)

  EVP_PKEY_free(verify_key);

  return status;
}

void
verify_axis_communications_public_key_upon_request(void *handle)
{
  if (!handle) return;

  sv_vendor_axis_communications_t *self = (sv_vendor_axis_communications_t *)handle;
  self->verify_pubkey_upon_call = true;
}

// Definitions of public APIs in declared in sv_vendor_axis_communications.h.

SignedVideoReturnCode
sv_vendor_axis_communications_set_attestation_report(signed_video_t *sv,
    const void *attestation,
    uint8_t attestation_size,
    const char *certificate_chain)
{
  // Sanity check inputs. It is allowed to set either one of |attestation| and |certificate_chain|,
  // but a mismatch between |attestation| and |attestation_size| returns SV_INVALID_PARAMETER.
  if (!sv) return SV_INVALID_PARAMETER;
  if (!attestation && !certificate_chain) return SV_INVALID_PARAMETER;
  if ((attestation && attestation_size == 0) || (!attestation && attestation_size > 0)) {
    return SV_INVALID_PARAMETER;
  }
  if (!sv->vendor_handle) return SV_NOT_SUPPORTED;

  sv_vendor_axis_communications_t *self = (sv_vendor_axis_communications_t *)sv->vendor_handle;
  bool allocated_attestation = false;
  bool allocated_certificate_chain = false;
  // The user wants to set the |attestation|.
  if (attestation) {
    // If |attestation| already exists, return error.
    if (self->attestation) return SV_NOT_SUPPORTED;
    // Allocate memory and copy to |self|.
    self->attestation = malloc(attestation_size);
    allocated_attestation = true;
    if (!self->attestation) goto catch_error;
    memcpy(self->attestation, attestation, attestation_size);
    self->attestation_size = attestation_size;
  }

  // The user wants to set the |certificate_chain|.
  if (certificate_chain) {
    // If |certificate_chain| already exists, return error.
    if (self->certificate_chain) return SV_NOT_SUPPORTED;
    // Check if there is anything to copy.
    size_t certificate_chain_size = strlen(certificate_chain);
    if (certificate_chain_size == 0) goto catch_error;

    bool has_newline_at_end = false;
    if (certificate_chain[certificate_chain_size - 1] == '\n') {
      has_newline_at_end = true;
    }
    // Allocate memory for |certificate_chain| + null-terminated character and maybe extra '\n'.
    self->certificate_chain = calloc(1, certificate_chain_size + (has_newline_at_end ? 1 : 2));
    allocated_certificate_chain = true;
    if (!self->certificate_chain) goto catch_error;
    strcpy(self->certificate_chain, certificate_chain);
    if (!has_newline_at_end) {
      strcpy(self->certificate_chain + certificate_chain_size, "\n");
      DEBUG_LOG("Adding newline since certificate_chain did not end with it.");
    }
  }

  sv->vendor_encoders = axis_communications_encoders;
  sv->num_vendor_encoders = AXIS_COMMUNICATIONS_NUM_ENCODERS;

  return SV_OK;

catch_error:
  // Free all memory.
  if (allocated_attestation) {
    free(self->attestation);
    self->attestation = NULL;
    self->attestation_size = 0;
  }
  if (allocated_certificate_chain) {
    free(self->certificate_chain);
    self->certificate_chain = NULL;
  }

  return SV_MEMORY;
}

SignedVideoReturnCode
sv_vendor_axis_communications_get_supplemental_authenticity(const signed_video_t *sv,
    sv_vendor_axis_supplemental_authenticity_t *supplemental_authenticity)
{
  if (!sv) return SV_INVALID_PARAMETER;
  if (!sv->vendor_handle) return SV_NOT_SUPPORTED;

  // TODO: When multiple vendors are supported, select the Axis vendor.
  sv_vendor_axis_communications_t *self = (sv_vendor_axis_communications_t *)sv->vendor_handle;
  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    if (self->verify_pubkey_upon_call) {
      SVI_THROW(verify_and_parse_certificate_chain(self));
      SVI_THROW(deserialize_attestation(self));
      SVI_THROW(verify_axis_communications_public_key(self));
    }
    supplemental_authenticity->public_key_validation =
        self->supplemental_authenticity.public_key_validation;
    // Clear any |serial_number| data in |supplemental_authenticity|.
    char *serial_number = supplemental_authenticity->serial_number;
    memset(serial_number, 0, SV_VENDOR_AXIS_SER_NO_MAX_LENGTH);
    const char *serial_number_ptr = (const char *)self->supplemental_authenticity.serial_number;
    strcpy(serial_number, serial_number_ptr);
    // Return the status from verify_axis_communications_public_key(...).
    SVI_THROW(self->pubkey_verification_status);

  SVI_CATCH()
  SVI_DONE(status)

  return svi_rc_to_signed_video_rc(status);
}
