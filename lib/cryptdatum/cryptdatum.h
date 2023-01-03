//go:build !cgo
// +build !cgo

/**
 * @file cryptdatum.h
 * @brief Cryptdatum library header file
 *
 * This file contains the declarations for the Cryptdatum library,
 * which provides functions for reading and writing Cryptdatum data
 * structures.
 *
 * @author Marko Kungla
 * @copyright Copyright (c) 2022, The howijd.network Authors
 *
 * @see https://github.com/howijd
 */
#ifndef CRYPTDATUM_H
#define CRYPTDATUM_H

#include <stdint.h>

/**
 * @brief Current version of the Cryptdatum format
 *
 * This constant defines the current version of the Cryptdatum format.
 * Implementations of the Cryptdatum library should set this value to 1
 * to indicate support for the current version of the format.
 */
#define CRYPTDATUM_VERSION 1

/**
 * @brief Minimum version of the Cryptdatum format
 *
 * This constant defines the minimum version of the Cryptdatum format this
 * implementations of the Cryptdatum library supports.
 */
#define CRYPTDATUM_MIN_VERSION 1

/**
 * @brief Magic number for Cryptdatum headers
 *
 * This constant defines the magic number that is used to identify Cryptdatum
 * headers. If the magic number field in a Cryptdatum header does not match
 * this value, the header should be considered invalid.
 */
#define CRYPTDATUM_MAGIC                           \
  {                                                \
    0xA7, 0xF6, 0xE5, 0xD4, 0xC3, 0xB2, 0xA1, 0xE1 \
  }
static const uint8_t magic[] = CRYPTDATUM_MAGIC;

/**
 * @brief Delimiter for Cryptdatum headers
 *
 * This constant defines the delimiter that is used to mark the end of a
 * Cryptdatum header. If the delimiter field in a Cryptdatum header does not
 * match this value, the header should be considered invalid.
 */
#define CRYPTDATUM_DELIMITER                       \
  {                                                \
    0xC8, 0xB7, 0xA6, 0xE5, 0xD4, 0xC3, 0xB2, 0xF1 \
  }

static const uint8_t delimiter[] = CRYPTDATUM_DELIMITER;

/**
 * @brief Size of a Cryptdatum header in bytes
 *
 * This constant defines the size of a Cryptdatum header in bytes. It can be
 * used by implementations of the Cryptdatum library to allocate sufficient
 * memory for a Cryptdatum header, or to check the size of a Cryptdatum header
 * that has been read from a stream.
 */
#define CRYPTDATUM_HEADER_SIZE 64

/**
 * @brief Cryptdatum header structure
 *
 * The Cryptdatum header contains metadata about the data payload,
 * including the version, timestamp, and size.
 */
typedef struct
{
  uint8_t magic[8];              /**< Magic number */
  uint16_t version;              /**< Version number */
  uint64_t timestamp;            /**< Timestamp (nanoseconds) */
  uint16_t opc;                  /**< Operation counter */
  uint64_t checksum;             /**< Checksum */
  uint64_t flags;                /**< Flags */
  uint64_t size;                 /**< Total size (including header and signature) */
  uint32_t signature_size;       /**< Signature size */
  uint8_t compression_algorithm; /**< Compression algorithm */
  uint8_t encryption_algorithm;  /**< Encryption algorithm */
  uint8_t signature_type;        /**< Signature type */
  uint8_t reserved[5];           /**< Reserved */
  uint8_t delimiter[8];          /**< Delimiter */
} cryptdatum_header;

/**
 * @brief Verify a Cryptdatum header
 *
 * This function verifies a Cryptdatum header to ensure that it is valid.
 * It checks the magic number, delimiter, and other fields in the header
 * to ensure that they match the expected values.
 *
 * @param data Pointer to the start of the Cryptdatum header
 * @return 1 if the header is valid, 0 if it is invalid
 */
int verify_header(const uint8_t *data);

#endif // CRYPTDATUM_H
