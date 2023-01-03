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
#include <stddef.h> // for size_t
#include <string.h>

int verify_header(const uint8_t *data)
{
  // Check for valid header size
  if (data == NULL)
  {
    return 0;
  }
  static const uint8_t magic[] = CRYPTDATUM_MAGIC;
  static const uint8_t delimiter[] = CRYPTDATUM_DELIMITER;

  if (memcmp(data, magic, sizeof(magic)) != 0)
  {
    return 0;
  }

  if (memcmp(data + CRYPTDATUM_HEADER_SIZE - sizeof(delimiter), delimiter, sizeof(delimiter)) != 0)
  {
    return 0;
  }
  return 1;
}
