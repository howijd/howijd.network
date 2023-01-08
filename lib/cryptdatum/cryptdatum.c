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
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define _MAGIC_DATE 1652155382000000001

const uint8_t empty[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

int has_header(const uint8_t *data)
{
  // Check for valid header size
  if (data == NULL) {
    return false;
  }
   // check magic and delimiter
  return (memcmp(data, CDT_MAGIC, 8) == 0 && memcmp(data + 72, CDT_DELIMITER, 8) == 0);
}

int has_valid_header(const uint8_t *data)
{
  if (has_header(data) != 1) {
    return false;
  }

  // check version is >= 1
  if (le16toh(*((uint16_t *)(data + 8))) < 1) {
    return false;
  }

  // break here if DatumDraft is set
  uint64_t flags = le64toh(*((uint64_t *)(data + 10)));
  if (flags & CDT_DATUM_DRAFT || flags & CDT_DATUM_COMPROMISED) {
    return true;
  }

  // It it was not a draft it must have timestamp
  if (le64toh(*((uint64_t *)(data + 18))) < _MAGIC_DATE) {
    return false;
  }

  // DatumOPC is set then counter value must be gte 1
  if (flags & CDT_DATUM_OPC) {
    if (le32toh(*((uint32_t *)(data + 26))) < 1) {
      return false;
    }
  }

  // DatumChecksum Checksum must be set
  if (flags & CDT_DATUM_CHECKSUM && memcmp(data + 30, empty, 8) == 0) {
    return false;
  }

  // DatumEmpty and DatumDraft
  if (flags & CDT_DATUM_EMPTY) {
    // Size field must be set
    if (le64toh(*((uint64_t *)(data + 38))) < 1) {
      return false;
    }

    // DatumCompressed compression algorithm must be set
    if (flags & CDT_DATUM_COMPRESSED && le16toh(*((uint16_t *)(data + 46))) < 1) {
      return false;
    }

    // DatumEncrypted encryption algorithm must be set
    if (flags & CDT_DATUM_ENCRYPTED && le16toh(*((uint16_t *)(data + 48))) < 1) {
      return false;
    }

    // DatumExtractable payl;oad can be extracted then filename must be set
    if (flags & CDT_DATUM_EXTRACTABLE && memcmp(data + 50, empty, 8) == 0) {
      return false;
    }
  }

  // DatumSigned then Signature Type must be also set
  // however value of the signature Size may depend on Signature Type
  if (flags & CDT_DATUM_SIGNED && le16toh(*((uint16_t *)(data + 58))) < 1) {
    return false;
  }

  return true;
}

cdt_error_t decode_header(cdt_reader_fn read, void* source, cdt_header_t* header)
{
  // Allocate a buffer to hold the header
  uint8_t *headerb = malloc(CDT_HEADER_SIZE);
  size_t bytes_read = read(headerb, 1, CDT_HEADER_SIZE, source);
  if (bytes_read < CDT_HEADER_SIZE) {
    free(headerb);
    return CDT_ERROR_IO;
  }

  if (has_header(headerb) != 1) {
    return CDT_ERROR_NO_HEADER;
  }

  // Parse the header
  memcpy(header->_magic, headerb, 8);
  header->version = le16toh(*((uint16_t*)(headerb + 8)));
  header->flags = le64toh(*((uint64_t*)(headerb + 10)));
  header->timestamp = le64toh(*((uint64_t*)(headerb + 18)));
  header->opc = le32toh(*((uint32_t*)(headerb + 26)));
  header->checksum = le64toh(*((uint64_t*)(headerb + 30)));
  header->size = le64toh(*((uint64_t*)(headerb + 38)));
  header->compression_alg = le16toh(*((uint16_t*)(headerb + 46)));
  header->encryption_alg = le16toh(*((uint16_t*)(headerb + 48)));
  header->signature_type = le16toh(*((uint16_t*)(headerb + 50)));
  header->signature_size = le32toh(*((uint32_t*)(headerb + 52)));
  memcpy(header->file_ext, headerb + 56, 8);
  // Read the file_ext field directly into the file_ext field in the cdt_header_t struct
  read(header->file_ext, 1, 8, source);
  // Make sure the file_ext field is null-terminated
  header->file_ext[8] = '\0';
  memcpy(header->custom, headerb + 64, 8);
  memcpy(header->_delimiter, headerb + 72, 8);
  free(headerb);
  return CDT_ERROR_NONE;
}

size_t cdt_fread(uint8_t *buffer, size_t size, size_t nmemb, void* fp)
{
  // Check if the fp argument is a valid file pointer
  if (!fp || (uintptr_t)fp % __alignof__(FILE*) != 0 ||
    offsetof(FILE, _flags) != 0 || ((FILE*)fp)->_flags == 0) {
    return 0; // invalid file pointer
  }
  return fread(buffer, size, nmemb, fp);
}
