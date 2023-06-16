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

#include <assert.h>
#include <openssl/bio.h>  // BIO_*
#include <openssl/evp.h>  // EVP_*
#include <openssl/opensslv.h>  // OPENSSL_VERSION_*
#include <openssl/pem.h>  // PEM_*
#include <openssl/sha.h>  // SHA256
#include <openssl/x509.h>  // X509_*
#include <stdbool.h>
#include <stdlib.h>  // malloc, memcpy, calloc, free

#include "signed_video_internal.h"
#include "signed_video_tlv.h"
#include "sv_vendor_axis_communications_internal.h"

// List of TLV encoders to include in SEI.
#define AXIS_COMMUNICATIONS_NUM_ENCODERS 1
static const sv_tlv_tag_t axis_communications_encoders[AXIS_COMMUNICATIONS_NUM_ENCODERS] = {
    VENDOR_AXIS_COMMUNICATIONS_TAG,
};

#define NUM_UNTRUSTED_CERTIFICATES 2  // |certificate_chain| has 2 untrusted certificates.
#define CHIP_ID_SIZE 18
#define CHIP_ID_PREFIX_SIZE 4
#define AXIS_EDGE_VAULT_ATTESTATION_STR "Axis Edge Vault Attestation "
#define SERIAL_NUMBER_UNKNOWN "Unknown"
#define PUBLIC_KEY_UNCOMPRESSED_SIZE 65
#define PUBLIC_KEY_UNCOMPRESSED_PREFIX 0x04
#define BINARY_RAW_DATA_SIZE 40

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

#define TIMESTAMP_SIZE 12
#define STATIC_BYTES_SIZE 22  // Bytes in signed data with unknown meaning
#define SIGNED_DATA_SIZE \
  (HASH_DIGEST_SIZE + PUBLIC_KEY_UNCOMPRESSED_SIZE + CHIP_ID_SIZE + ATTRIBUTES_LENGTH + \
      TIMESTAMP_SIZE + STATIC_BYTES_SIZE)

#define OBJECT_ID_SIZE 4
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

  // Information needed for public key validation.
  EVP_MD_CTX *md_ctx;  // Message digest context for verifying the public key
  X509 *trusted_ca;  // The trusted Axis root CA in X509 form.
  uint8_t chip_id[CHIP_ID_SIZE];
  struct attestation_report attestation_report;

  // Public key to validate using |attestation| and |certificate_chain|
  const void *public_key;  // A pointer to the public key used for validation. Assumed to be a PEM.
  // Ownership is NOT transferred.
  size_t public_key_size;  // The size of the |public_key|.

  // Public key validation results
  sv_vendor_axis_supplemental_authenticity_t supplemental_authenticity;
} sv_vendor_axis_communications_t;

// Declarations of static functions.
static svi_rc
verify_certificate_chain(X509 *trusted_ca, STACK_OF(X509) * untrusted_certificates);
static svi_rc
verify_and_parse_certificate_chain(sv_vendor_axis_communications_t *self);
static svi_rc
deserialize_attestation(sv_vendor_axis_communications_t *self);
static svi_rc
verify_axis_communications_public_key(sv_vendor_axis_communications_t *self);
static size_t
get_untrusted_certificates_size(const sv_vendor_axis_communications_t *self);

// Definitions of static functions.

/* Verifies the untrusted certificate chain.
 *
 * Uses the |trusted_ca| to verify the first certificate in the chain. The last certificate verified
 * is the |attestation_certificate| which will be used to verify the transmitted public key. */
static svi_rc
verify_certificate_chain(X509 *trusted_ca, STACK_OF(X509) * untrusted_certificates)
{
  assert(trusted_ca && untrusted_certificates);

  X509_STORE *trust_store = NULL;
  X509_STORE_CTX *ctx = NULL;

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    trust_store = X509_STORE_new();
    SVI_THROW_IF(!trust_store, SVI_EXTERNAL_FAILURE);
    // Load trusted CA certificate
    SVI_THROW_IF(X509_STORE_add_cert(trust_store, trusted_ca) != 1, SVI_EXTERNAL_FAILURE);

    // Start a new context for certificate verification.
    ctx = X509_STORE_CTX_new();
    SVI_THROW_IF(!ctx, SVI_EXTERNAL_FAILURE);

    // The |attestation_certificate| is the first certificate in the stack, which is the final
    // certificate to verify.
    X509 *attestation_certificate = sk_X509_value(untrusted_certificates, 0);
    // Initialize the context with trusted CA, the final certificate to verify and the chain of
    // certificates.
    SVI_THROW_IF(
        X509_STORE_CTX_init(ctx, trust_store, attestation_certificate, untrusted_certificates) != 1,
        SVI_EXTERNAL_FAILURE);
    SVI_THROW_IF(X509_verify_cert(ctx) != 1, SVI_VENDOR);

  SVI_CATCH()
  SVI_DONE(status)

  X509_STORE_CTX_free(ctx);
  X509_STORE_free(trust_store);

  return status;
}

/* Puts the untrusted certificate chain in a stack of X509 certificates. This stack is then
 * verified against the trusted Axis root CA. Upon success, parses |chip_id|, |serial_number| and
 * gets the public key from the |attestation_certificate|. Further, a message digest context
 * |md_ctx| is created and initiated.
 *
 * If all goes well, ownership of |md_ctx| is transfered to |self|. Anything that does not follow
 * the expected format will return SVI_VENDOR.
 */
static svi_rc
verify_and_parse_certificate_chain(sv_vendor_axis_communications_t *self)
{
  if (!self || !self->certificate_chain) return SVI_INVALID_PARAMETER;

  EVP_MD_CTX *md_ctx = NULL;
  BIO *stackbio = NULL;
  STACK_OF(X509) *untrusted_certificates = NULL;
  int num_certificates = 0;
  ASN1_STRING *entry_data = NULL;
  unsigned char *common_name_str = NULL;
  unsigned char *serial_number_str = NULL;
  const uint8_t kChipIDPrefix[CHIP_ID_PREFIX_SIZE] = {0x04, 0x00, 0x50, 0x01};

  // Remove the old message digest context.
  EVP_MD_CTX_free(self->md_ctx);

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    // Create an empty stack of X509 certificates.
    untrusted_certificates = sk_X509_new_null();
    SVI_THROW_IF(!untrusted_certificates, SVI_EXTERNAL_FAILURE);
    sk_X509_zero(untrusted_certificates);
    // Put |certificate_chain| in a BIO.
    stackbio = BIO_new_mem_buf(self->certificate_chain, (int)strlen(self->certificate_chain));
    SVI_THROW_IF(!stackbio, SVI_EXTERNAL_FAILURE);

    // Turn |certificate_chain| into stack of X509, by looping through |certificate_chain| and
    // pushing them to |untrusted_certificates|. A hard coded maximum number of certificates
    // prevents from potential deadlock.
    // Get the first certificate from |stackbio|.
    X509 *certificate = PEM_read_bio_X509(stackbio, NULL, NULL, NULL);
    // The first certificate is the |attestation_certificate|. Keep a reference to it to extract
    // information from it.
    X509 *attestation_certificate = certificate;
    while (certificate && num_certificates < NUM_UNTRUSTED_CERTIFICATES + 1) {
      num_certificates = sk_X509_push(untrusted_certificates, certificate);
      // Get the next certificate.
      certificate = PEM_read_bio_X509(stackbio, NULL, NULL, NULL);
    }
    SVI_THROW_IF(num_certificates > NUM_UNTRUSTED_CERTIFICATES, SVI_VENDOR);

    SVI_THROW(verify_certificate_chain(self->trusted_ca, untrusted_certificates));

    // Extract |chip_id| from the |attestation_certificate|.
    X509_NAME *subject = X509_get_subject_name(attestation_certificate);
    int common_name_index = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
    SVI_THROW_IF(common_name_index < 0, SVI_VENDOR);
    // Found CN in certificate. Read that entry and convert to UTF8.
    entry_data = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subject, common_name_index));
    SVI_THROW_IF(ASN1_STRING_to_UTF8(&common_name_str, entry_data) <= 0, SVI_EXTERNAL_FAILURE);
    // Find the Chip ID string, which shows up right after "Axis Edge Vault Attestation ".
    char *chip_id_str = strstr((char *)common_name_str, AXIS_EDGE_VAULT_ATTESTATION_STR);
    SVI_THROW_IF(!chip_id_str, SVI_VENDOR);
    char *pos = chip_id_str + strlen(AXIS_EDGE_VAULT_ATTESTATION_STR);
    size_t chip_id_size = strlen(pos);
    // Note that chip id is displayed in hexadecimal form in the certificate, hence each byte
    // corresponds to two characters.
    SVI_THROW_IF(chip_id_size != CHIP_ID_SIZE * 2, SVI_VENDOR);
    for (int idx = 0; idx < CHIP_ID_SIZE; idx++, pos += 2) {
      sscanf(pos, "%2hhx", &self->chip_id[idx]);
    }
    // Check that the chip ID has correct prefix.
    SVI_THROW_IF(memcmp(self->chip_id, kChipIDPrefix, CHIP_ID_PREFIX_SIZE) != 0, SVI_VENDOR);

    // Extract |serial_number| from the |attestation_certificate|.
    int ser_no_index = X509_NAME_get_index_by_NID(subject, NID_serialNumber, -1);
    SVI_THROW_IF(ser_no_index < 0, SVI_VENDOR);
    // Found serial number in certificate. Read that entry and convert to UTF8.
    entry_data = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subject, ser_no_index));
    SVI_THROW_IF(ASN1_STRING_to_UTF8(&serial_number_str, entry_data) <= 0, SVI_EXTERNAL_FAILURE);
    // Copy only if necessary.
    if (strcmp(self->supplemental_authenticity.serial_number, (char *)serial_number_str)) {
      memset(self->supplemental_authenticity.serial_number, 0, SV_VENDOR_AXIS_SER_NO_MAX_LENGTH);
      strcpy(self->supplemental_authenticity.serial_number, (char *)serial_number_str);
    }

    // Get the public key from |attestation_certificate| and verify it.
    EVP_PKEY *attestation_pubkey = X509_get0_pubkey(attestation_certificate);
    SVI_THROW_IF(!attestation_pubkey, SVI_EXTERNAL_FAILURE);
    SVI_THROW_IF(EVP_PKEY_base_id(attestation_pubkey) != EVP_PKEY_EC, SVI_VENDOR);
    // Create a new message digest context and initiate it. This context will later be used to
    // verify the public key used when validating the video.
    md_ctx = EVP_MD_CTX_new();
    SVI_THROW_IF(!md_ctx, SVI_EXTERNAL_FAILURE);
    SVI_THROW_IF(EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, attestation_pubkey) < 1,
        SVI_EXTERNAL_FAILURE);

  SVI_CATCH()
  {
    // If no serial number can be found, copy "Unknown" to |serial_number|.
    memset(self->supplemental_authenticity.serial_number, 0, SV_VENDOR_AXIS_SER_NO_MAX_LENGTH);
    strcpy(self->supplemental_authenticity.serial_number, SERIAL_NUMBER_UNKNOWN);
    // Erase the context if present.
    EVP_MD_CTX_free(md_ctx);
    md_ctx = NULL;
  }
  SVI_DONE(status)

  // Transfer ownership.
  self->md_ctx = md_ctx;

  OPENSSL_free(common_name_str);
  OPENSSL_free(serial_number_str);
  sk_X509_pop_free(untrusted_certificates, X509_free);
  BIO_free(stackbio);

  return status;
}

/* Deserializes |attestation| into |attestation_report|.
 * The structure of |attestation| is:
 *   - header (2 bytes)
 *   - version (2 bytes)
 *   - object_id (4 bytes)
 *   - attestation_list_length (1 byte) NOTE: Struct only supports one list item
 *   - attestation_list
 *     - timestamp (12 bytes)
 *     - signature_size (2 bytes)
 *     - signature (|signature_size| bytes) */
static svi_rc
deserialize_attestation(sv_vendor_axis_communications_t *self)
{
  assert(self);

  if (!self->attestation) return SVI_VENDOR;
  // The |attestation_size| has to be at least 23 bytes to be deserializable.
  if (self->attestation_size < 24) return SVI_VENDOR;

  uint8_t *attestation_ptr = (uint8_t *)self->attestation;
  size_t signature_size = 0;

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
  // Make sure that there is no more data present after the signature.
  uint8_t *attestation_end = (uint8_t *)self->attestation + (size_t)self->attestation_size;
  if (attestation_ptr + signature_size != attestation_end) {
    return SVI_VENDOR;
  }
  self->attestation_report.attestation_list.signature_size = signature_size;
  // Copy signature (|signature_size| byte)
  memcpy(self->attestation_report.attestation_list.signature, attestation_ptr, signature_size);
  attestation_ptr += signature_size;

  return SVI_OK;
}

/* Verifies the transmitted public key, given the |attestation| and |certificate_chain|.
 *
 * This function should be called before using the transmitted public key.
 *
 * The procedure is to construct |signed_data|, following the same scheme as on camera, and then
 * verify the signature with it.
 * |signed_data| should be organized as
 *   - hash of binary raw data
 *   - public key in uncompressed Weierstrass form
 *   - chip id
 *   - attributes
 *   - timestamp
 */
static svi_rc
verify_axis_communications_public_key(sv_vendor_axis_communications_t *self)
{
  assert(self);

  BIO *bio = NULL;
  EVP_PKEY *pkey = NULL;
  uint8_t *public_key_uncompressed = NULL;
  size_t public_key_uncompressed_size = 0;
  uint8_t *signed_data = NULL;
  // Initiate verification to not feasible/error.
  int verified_signature = -1;

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    // If no message digest context exists, the |public_key| cannot be validated.
    SVI_THROW_IF(!self->md_ctx, SVI_VENDOR);
    SVI_THROW_IF(!self->public_key || self->public_key_size == 0, SVI_NOT_SUPPORTED);
    // Convert |public_key| to uncompressed Weierstrass form which will be part of |signed_data|.
    //   public_key -> BIO -> EVP_PKEY -> EC_KEY -> EC_KEY_key2buf
    bio = BIO_new_mem_buf(self->public_key, (int)self->public_key_size);
    SVI_THROW_IF(!bio, SVI_EXTERNAL_FAILURE);
    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    SVI_THROW_IF(!pkey, SVI_EXTERNAL_FAILURE);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    const EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
    public_key_uncompressed_size =
        EC_KEY_key2buf(ec_key, POINT_CONVERSION_UNCOMPRESSED, &public_key_uncompressed, NULL);
#else
    char gname[50];
    // int nid;
    EC_GROUP *group;
    EC_POINT *point = NULL;
    BIGNUM *prime = NULL;
    // int prime_len = -1;
    SVI_THROW_IF_WITH_MSG(EVP_PKEY_get_group_name(pkey, gname, sizeof(gname), NULL) != 1,
        SVI_EXTERNAL_FAILURE, "EVP_PKEY_get_group_name");
    // if (EVP_PKEY_get_group_name(pkey, gname, sizeof(gname), NULL) != 1)
    //   return -1;
    // nid = OBJ_txt2nid(gname);
    group = EC_GROUP_new_by_curve_name(OBJ_txt2nid(gname));
    // group = EC_GROUP_new_by_curve_name(nid);
    // prime = BN_new();
    // SVI_THROW_IF(!group || !prime, SVI_EXTERNAL_FAILURE);
    SVI_THROW_IF_WITH_MSG(!group, SVI_EXTERNAL_FAILURE, "!group");
    prime = BN_new();
    SVI_THROW_IF_WITH_MSG(!group || !prime, SVI_EXTERNAL_FAILURE, "!group || !prime");
    // if (!group || !prime)
    //   return -1;
    EC_GROUP_get_curve(group, prime, NULL, NULL, NULL);  // != 1) {
    point = EC_POINT_new(group);
    SVI_THROW_IF_WITH_MSG(EC_POINT_mul(group, point, prime, NULL, NULL, NULL) == 0,
        SVI_EXTERNAL_FAILURE, "EC_POINT_mul");
    // point = EC_POINT_bn2point(group, prime, NULL, NULL);
    // SVI_THROW_WITH_MSG(SVI_VENDOR, "OpenSSL 3.0 and newer not yet supported");
    SVI_THROW_IF_WITH_MSG(!point, SVI_EXTERNAL_FAILURE, "!point");
    public_key_uncompressed_size = EC_POINT_point2buf(
        group, point, POINT_CONVERSION_UNCOMPRESSED, &public_key_uncompressed, NULL);
    EC_GROUP_free(group);
    EC_POINT_free(point);
    BN_free(prime);
#endif
    // Check size and prefix of |public_key| after conversion.
    SVI_THROW_IF_WITH_MSG(public_key_uncompressed_size != PUBLIC_KEY_UNCOMPRESSED_SIZE, SVI_VENDOR,
        "public_key_uncompressed_size = %zu", public_key_uncompressed_size);
    SVI_THROW_IF(public_key_uncompressed[0] != PUBLIC_KEY_UNCOMPRESSED_PREFIX, SVI_VENDOR);

    // Construct the binary raw data which will be part of |signed_data|.
    uint8_t binary_raw_data[BINARY_RAW_DATA_SIZE] = {0x80, 0x22, 0x00, 0x00, 0x00, 0x00, 0x21, 0x41,
        0x04, 0xf0, 0x00, 0x00, 0x12, 0x45, 0x04, 0xf0, 0x00, 0x00, 0x12, 0x46, 0x01, 0x21, 0x47,
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00};
    // Add Object ID at positions 9-12.
    memcpy(&binary_raw_data[9], kAttributes, OBJECT_ID_SIZE);
    // Add Freshness at positions 24-39.
    memcpy(&binary_raw_data[24], kFreshness, FRESHNESS_LENGTH);
    // Hash |binary_raw_data|.
    uint8_t binary_raw_data_hash[HASH_DIGEST_SIZE] = {0};
    SHA256(binary_raw_data, BINARY_RAW_DATA_SIZE, binary_raw_data_hash);

    // Create and fill in |signed_data|.
    signed_data = calloc(1, SIGNED_DATA_SIZE);
    uint8_t *sd_ptr = signed_data;

    // Add hash of |binary_raw_data|.
    memcpy(sd_ptr, binary_raw_data_hash, HASH_DIGEST_SIZE);
    sd_ptr += HASH_DIGEST_SIZE;
    *sd_ptr++ = 0x41;
    *sd_ptr++ = 0x82;

    // Add public key in uncompressed Weierstrass form.
    *sd_ptr++ = (uint8_t)((PUBLIC_KEY_UNCOMPRESSED_SIZE >> 8) & 0x000000ff);
    *sd_ptr++ = (uint8_t)(PUBLIC_KEY_UNCOMPRESSED_SIZE & 0x000000ff);
    memcpy(sd_ptr, public_key_uncompressed, PUBLIC_KEY_UNCOMPRESSED_SIZE);
    sd_ptr += PUBLIC_KEY_UNCOMPRESSED_SIZE;

    // Add |chip_id|.
    *sd_ptr++ = 0x42;
    *sd_ptr++ = 0x82;
    *sd_ptr++ = 0x00;
    *sd_ptr++ = 0x12;
    memcpy(sd_ptr, self->chip_id, CHIP_ID_SIZE);
    sd_ptr += CHIP_ID_SIZE;

    // Add attributes.
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
    // Add timestamp.
    memcpy(sd_ptr, self->attestation_report.attestation_list.timestamp, TIMESTAMP_SIZE);
    sd_ptr += TIMESTAMP_SIZE;

    // Verify signature (which is present in the |attestation_report|) with |signed_data|.
    verified_signature = EVP_DigestVerify(self->md_ctx,
        self->attestation_report.attestation_list.signature,
        self->attestation_report.attestation_list.signature_size, signed_data, SIGNED_DATA_SIZE);
    SVI_THROW_IF(verified_signature < 0, SVI_EXTERNAL_FAILURE);

    // If verification fails (is 0) the result should never be overwritten with success (1) later.
    self->supplemental_authenticity.public_key_validation &= verified_signature;

  SVI_CATCH()
  SVI_DONE(status)

  free(signed_data);
  OPENSSL_free(public_key_uncompressed);
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
  strcpy(self->supplemental_authenticity.serial_number, SERIAL_NUMBER_UNKNOWN);

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
  if (!handle) return;

  sv_vendor_axis_communications_t *self = (sv_vendor_axis_communications_t *)handle;

  free(self->attestation);
  free(self->certificate_chain);
  X509_free(self->trusted_ca);
  free(self);
}

/* This function finds the beginning of the last certificate, which is the trusted public Axis root
 * CA certificate. The size of the other certificates is returned. If the last certificate differs
 * from what is expected, or if number of certificates is not equal to three, 0 is returned.
 *
 * This function is intended to be used on the signing side when encoding the handle, where the
 * |certificate_chain| includes the trusted Axis root CA. The purpose is to exclude it from the SEI
 * to reduce bitrate.
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

/* Encodes the handle data into the TLV tag VENDOR_AXIS_COMMUNICATIONS_TAG. */
size_t
encode_axis_communications_handle(void *handle, uint16_t *last_two_bytes, bool epb, uint8_t *data)
{
  if (!handle) return 0;

  sv_vendor_axis_communications_t *self = (sv_vendor_axis_communications_t *)handle;
  size_t data_size = 0;
  // Get the size of the untrusted certificates that will be added to the tag.
  size_t certificate_chain_encode_size = get_untrusted_certificates_size(self);
  const uint8_t version = 1;  // Increment when the change breaks the format

  // If there is no attestation or certificate chain, skip encoding, that is return 0.
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
  write_byte(last_two_bytes, &data_ptr, version, epb);
  // Write |attestation_size|.
  write_byte(last_two_bytes, &data_ptr, self->attestation_size, epb);
  // Write |attestation|.
  for (size_t jj = 0; jj < self->attestation_size; ++jj) {
    write_byte(last_two_bytes, &data_ptr, attestation[jj], epb);
  }
  // Write |certificate_chain|.
  write_byte_many(
      &data_ptr, self->certificate_chain, certificate_chain_encode_size, last_two_bytes, epb);

  return (data_ptr - data);
}

/* Decodes the TLV tag VENDOR_AXIS_COMMUNICATIONS_TAG to the handle data. */
svi_rc
decode_axis_communications_handle(void *handle, const uint8_t *data, size_t data_size)
{
  if (!handle) return SVI_INVALID_PARAMETER;

  sv_vendor_axis_communications_t *self = (sv_vendor_axis_communications_t *)handle;
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
      // Read |attestation|.
      memcpy(self->attestation, data_ptr, attestation_size);
      self->attestation_size = attestation_size;
    }
    // Check if the received |attestation| differ from the present one. If so, return
    // SVI_NOT_SUPPORTED, since a change in attestation is not allowed.
    SVI_THROW_IF(attestation_size != self->attestation_size, SVI_NOT_SUPPORTED);
    SVI_THROW_IF(memcmp(data_ptr, self->attestation, attestation_size), SVI_NOT_SUPPORTED);
    // Move pointer past |attestation|.
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
    // Compare incoming certificate chain against present and throw an error if they differ.
    SVI_THROW_IF(memcmp(data_ptr, self->certificate_chain, cert_size), SVI_NOT_SUPPORTED);
    // Move pointer past |certificate_chain|.
    data_ptr += cert_size;

    SVI_THROW_IF(data_ptr != data + data_size, SVI_DECODING_ERROR);
  SVI_CATCH()
  SVI_DONE(status)

  return status;
}

svi_rc
set_axis_communications_public_key(void *handle,
    const void *public_key,
    size_t public_key_size,
    bool public_key_has_changed)
{
  if (!handle || !public_key || public_key_size == 0) return SVI_INVALID_PARAMETER;

  sv_vendor_axis_communications_t *self = (sv_vendor_axis_communications_t *)handle;
  EVP_PKEY *pkey = NULL;
  BIO *bp = NULL;
  // char gname[50];
  // int nid;
  // EC_GROUP *group;
  // BIGNUM *prime = NULL;

  // If the Public key previously has been validated unsuccessful, skip checking type and size.
  if (self->supplemental_authenticity.public_key_validation == 0) {
    return SVI_OK;
  }

  // Mark |public_key_validation| as invalid if the |public_key_has_changed|. It is an invalid
  // operation. Note that it is not an error, only an invalid operation and will be communicated
  // through |supplemental_authenticity|.
  if (public_key_has_changed && self->public_key) {
    self->supplemental_authenticity.public_key_validation = 0;
  }

  int public_key_validation = self->supplemental_authenticity.public_key_validation;
  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    // Validate that the public key is of correct type and size.
    bp = BIO_new_mem_buf(public_key, (int)public_key_size);
    SVI_THROW_IF(!bp, SVI_EXTERNAL_FAILURE);
    pkey = PEM_read_bio_PUBKEY(bp, NULL, NULL, NULL);
    SVI_THROW_IF(!pkey, SVI_EXTERNAL_FAILURE);
    // Ensure it is a NIST P-256 key with correct curve.
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
      public_key_validation = 0;
    } else {
#if OPENSSL_VERSION_NUMBER < 0x30000000L
      const EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
      SVI_THROW_IF(!ec_key, SVI_EXTERNAL_FAILURE);
      const EC_GROUP *ec_group = EC_KEY_get0_group(ec_key);
      SVI_THROW_IF(!ec_group, SVI_EXTERNAL_FAILURE);
      if (EC_GROUP_get_curve_name(ec_group) != NID_X9_62_prime256v1) {
        public_key_validation = 0;
      }
#else
      // OpenSSL 3.0 and newer not yet supported. Mark Public key as not valid.
      // public_key_validation = 0;
      char gname[50];
      // int nid;
      EC_GROUP *group;
      BIGNUM *prime = NULL;
      // int prime_len = -1;
      SVI_THROW_IF_WITH_MSG(EVP_PKEY_get_group_name(pkey, gname, sizeof(gname), NULL) != 1,
          SVI_EXTERNAL_FAILURE, "EVP_PKEY_get_group_name");
      // if (EVP_PKEY_get_group_name(pkey, gname, sizeof(gname), NULL) != 1)
      //   return -1;
      // nid = OBJ_txt2nid(gname);
      group = EC_GROUP_new_by_curve_name(OBJ_txt2nid(gname));
      // group = EC_GROUP_new_by_curve_name(nid);
      prime = BN_new();
      SVI_THROW_IF_WITH_MSG(!group || !prime, SVI_EXTERNAL_FAILURE, "!group || !prime");
      // if (!group || !prime)
      //   return -1;
      if (EC_GROUP_get_curve(group, prime, NULL, NULL, NULL) != 1) {
        public_key_validation = 0;
      }
      // prime_len = BN_num_bytes(prime);
      EC_GROUP_free(group);
      BN_free(prime);
      // return prime_len;
#endif
    }

    // The Public key is of correct type and size.
    self->public_key = public_key;
    self->public_key_size = public_key_size;
  SVI_CATCH()
  {
    self->public_key = NULL;
    self->public_key_size = 0;
  }
  SVI_DONE(status)

  // EC_GROUP_free(group);
  // BN_free(prime);
  BIO_free(bp);
  EVP_PKEY_free(pkey);

  self->supplemental_authenticity.public_key_validation = public_key_validation;

  return status;
}

svi_rc
get_axis_communications_supplemental_authenticity(void *handle,
    sv_vendor_axis_supplemental_authenticity_t **supplemental_authenticity)
{
  if (!handle || !supplemental_authenticity) return SVI_INVALID_PARAMETER;

  sv_vendor_axis_communications_t *self = (sv_vendor_axis_communications_t *)handle;

  // TODO: Fill in the skeleton below step by step.
  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    SVI_THROW(verify_and_parse_certificate_chain(self));
    SVI_THROW(deserialize_attestation(self));
    SVI_THROW(verify_axis_communications_public_key(self));
    // Set public key validation information.

  SVI_CATCH()
  SVI_DONE(status)

  // If anything did not fulfill the verification requirements a SVI_VENDOR error is thrown. Set the
  // |supplemental_authenticity| and change status to SVI_OK, since it is a valid behavior.
  if (status == SVI_VENDOR) {
    self->supplemental_authenticity.public_key_validation = 0;
    memset(self->supplemental_authenticity.serial_number, 0, SV_VENDOR_AXIS_SER_NO_MAX_LENGTH);
    strcpy(self->supplemental_authenticity.serial_number, "Unknown");
    status = SVI_OK;
  }

  *supplemental_authenticity = &self->supplemental_authenticity;

  return status;
}

// Definitions of public APIs declared in sv_vendor_axis_communications.h.

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
