// go:build !cgo
//  +build !cgo

/*
 * Cryptdatum is a C library that implements the Cryptdatum format. It provides
 * functions to parse, verify, and create Cryptdatum headers, as well as to
 * encode and decode Cryptdatum data payloads.
 *
 * The Cryptdatum format is a binary data format that is designed to be secure,
 * efficient, and extensible. It uses a 64-byte header to store metadata about
 * the data payload, such as the version of the format, the time when the data
 * was created, and the features used by the datum.
 *
 * The header is followed by the data payload, which can be compressed, encrypted,
 * or signed. The data payload can be of any size, and can contain any type of
 * data, such as text, binary, or multimedia.
 *
 * The Cryptdatum library is easy to use, and has a simple API. It is written in
 * pure C, and has no external dependencies. It can be used in any C project,
 * on any platform, with minimal setup.
 *
 * To start using the Cryptdatum library, include the "cryptdatum.h" header file
 * in your C source code, and link with the "cryptdatum" library. Then, call
 * the library functions as needed to parse, verify, create, encode, and decode
 * Cryptdatum data.
 *
 * For more information about the Cryptdatum format, see the specification at
 * https://example.com/cryptdatum-spec.
 */

#include "cryptdatum.h"
#include <string.h>
#include <stdbool.h>
#include <endian.h>

#define magic_date 1652155382000000001

const uint8_t empty[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

int verify_header(const uint8_t *data)
{
  // Check for valid header size
  if (data == NULL) {
    return false;
  }

  // check magic and delimiter
  if (memcmp(data, CRYPTDATUM_MAGIC, 8) != 0 || memcmp(data + 72, CRYPTDATUM_DELIMITER, 8) != 0) {
    return false;
  }

  // check version is >= 1
  if (le16toh(*((uint16_t *)(data + 8))) < 1) {
    return false;
  }

  // break here if DatumDraft is set
  uint64_t flags = le64toh(*((uint64_t *)(data + 10)));
  if (flags & DATUM_DRAFT || flags & DATUM_COMPROMISED) {
    return true;
  }

  // It it was not a draft it must have timestamp
  if (le64toh(*((uint64_t *)(data + 18))) < magic_date) {
    return false;
  }

  // DatumOPC is set then counter value must be gte 1
  if (flags & DATUM_OPC) {
    if (le32toh(*((uint32_t *)(data + 26))) < 1) {
      return false;
    }
  }

  // DatumChecksum Checksum must be set
  if (flags & DATUM_CHECKSUM && memcmp(data + 30, empty, 8) == 0) {
    return false;
  }

  // DatumEmpty and DatumDraft
  if (flags & DATUM_EMPTY) {
    // Size field must be set
    if (le64toh(*((uint64_t *)(data + 38))) < 1) {
      return false;
    }

    // DatumCompressed compression algorithm must be set
    if (flags & DATUM_COMPRESSED && le16toh(*((uint16_t *)(data + 46))) < 1) {
      return false;
    }

    // DatumEncrypted encryption algorithm must be set
    if (flags & DATUM_ENCRYPTED && le16toh(*((uint16_t *)(data + 48))) < 1) {
      return false;
    }

    // DatumExtractable payl;oad can be extracted then filename must be set
    if (flags & DATUM_EXTRACTABLE && memcmp(data + 50, empty, 8) == 0) {
      return false;
    }
  }

  // DatumSigned then Signature Type must be also set
  // however value of the signature Size may depend on Signature Type
  if (flags & DATUM_SIGNED && le16toh(*((uint16_t *)(data + 58))) < 1) {
    return false;
  }

  return true;
}
