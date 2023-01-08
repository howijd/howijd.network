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

#include <stddef.h> // size_t
#include <stdint.h> // uint8_t
#include <endian.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Size of a Cryptdatum header in bytes
 *
 * This constant defines the size of a Cryptdatum header in bytes. It can be
 * used by implementations of the Cryptdatum library to allocate sufficient
 * memory for a Cryptdatum header, or to check the size of a Cryptdatum header
 * that has been read from a stream.
 */
static const size_t CDT_HEADER_SIZE = 80;

/**
 * @brief Current version of the Cryptdatum format
 *
 * This constant defines the current version of the Cryptdatum format.
 * Implementations of the Cryptdatum library should set this value to 1
 * to indicate support for the current version of the format.
 */
static const uint8_t CDT_VERSION = 1;

/**
 * @brief Minimum version of the Cryptdatum format
 *
 * This constant defines the minimum version of the Cryptdatum format this
 * implementations of the Cryptdatum library supports.
 */
#define CDT_MIN_VERSION = 1

/**
 * @brief Magic number for Cryptdatum headers
 *
 * This constant defines the magic number that is used to identify Cryptdatum
 * headers. If the magic number field in a Cryptdatum header does not match
 * this value, the header should be considered invalid.
 */
static const uint8_t CDT_MAGIC[] = {
  0xA7, 0xF6, 0xE5, 0xD4, 0xC3, 0xB2, 0xA1, 0xE1
};

/**
 * @brief Delimiter for Cryptdatum headers
 *
 * This constant defines the delimiter that is used to mark the end of a
 * Cryptdatum header. If the delimiter field in a Cryptdatum header does not
 * match this value, the header should be considered invalid.
 */
static const uint8_t CDT_DELIMITER[] = {
  0xC8, 0xB7, 0xA6, 0xE5, 0xD4, 0xC3, 0xB2, 0xF1
};

typedef enum uint64_t{
  CTD_DATUM_INVALID = (1 << 0),
  CDT_DATUM_DRAFT = (1 << 1),
  CDT_DATUM_EMPTY = (1 << 2),
  CDT_DATUM_CHECKSUM = (1 << 3),
  CDT_DATUM_OPC = (1 << 4),
  CDT_DATUM_COMPRESSED = (1 << 5),
  CDT_DATUM_ENCRYPTED = (1 << 6),
  CDT_DATUM_EXTRACTABLE = (1 << 7),
  CDT_DATUM_SIGNED = (1 << 8),
  CDT_DATUM_STREAMABLE = (1 << 9),
  CDT_DATUM_CUSTOM = (1 << 10),
  CDT_DATUM_COMPROMISED = (1 << 11)
} cdt_datum_flags_t;

#define _cdt_create_errors(error) \
        error(CDT_ERROR_NONE)   \
        error(CDT_ERROR)  \
        error(CDT_ERROR_IO)   \
        error(CDT_ERROR_EOF)  \
        error(CDT_ERROR_NO_HEADER)  \
        error(CDT_ERROR_INVALID_HEADER)  \

#define _cdt_generate_enum_value(ENUM) ENUM,
#define _cdt_generate_enum_string(STRING) #STRING,

typedef enum {
  _cdt_create_errors(_cdt_generate_enum_value)
} cdt_error_t;

static const char *CDT_ERR_STR[] = {
  _cdt_create_errors(_cdt_generate_enum_string)
};

/**
 * @brief Cryptdatum header structure
 *
 * The Cryptdatum header contains metadata about the data payload,
 * including the version, timestamp, and size.
 */
typedef struct
{
  uint8_t _magic[8];                 /**< Magic number */
  uint16_t version;                 /**< Version number */
  cdt_datum_flags_t flags;          /**< Flags */
  uint64_t timestamp;               /**< Timestamp (nanoseconds) */
  uint32_t opc;                     /**< Operation counter */
  uint64_t checksum;                /**< Checksum */
  size_t size;                      /**< Total size (including header and signature) */
  uint16_t compression_alg;        /**< Compression algorithm */
  uint16_t encryption_alg;         /**< Encryption algorithm */
  uint16_t signature_type;          /**< Signature type */
  uint32_t signature_size;          /**< Signature size */
  char file_ext[9];                 /**< File Extension  */
  uint8_t custom[8];                /**< Custom */
  uint8_t _delimiter[8];             /**< Delimiter */
} cdt_header_t;

/**
 * @brief Check if the provided data contains a Cryptdatum header.
 *
 * This function checks if the provided data contains a Cryptdatum header. It looks for specific
 * header fields and checks their alignment, but does not perform any further validations. If the
 * data is likely to be Cryptdatum, the function returns true. Otherwise, it returns false.
 * If you want to verify the integrity of the header as well, use the has_valid_header function
 * or use decode_header and perform the validation yourself.
 *
 * The data argument should contain the entire Cryptdatum data, as a byte slice. The function will
 * read the first HeaderSize bytes of the slice to check for the presence of a header.
 *
 * @param data Pointer to the start of the Cryptdatum header
 * @return 1 if the header is valid, 0 if it is invalid
 */
int has_header(const uint8_t *data);

/**
 * @brief Check if the provided data contains a valid Cryptdatum header.
 *
 * This function checks if the provided data contains a valid Cryptdatum header. It verifies the
 * integrity of the header by checking the magic number, delimiter, and other fields. If the header
 * is valid, the function returns true. Otherwise, it returns false.
 *
 * The data argument can contain any data as a byte slice, but should be at least CDT_HEADER_SIZE in length
 * and start with the header. The function will read the first HeaderSize bytes of the slice to
 * validate the header. If the data slice is smaller than CDT_HEADER_SIZE bytes, the function will
 * return false, as the header is considered incomplete.
 *
 * @param data Pointer to the start of the Cryptdatum header
 * @return 1 if the header is valid, 0 if it is invalid
 */
int has_valid_header(const uint8_t *data);

/**
 * @brief Function pointer type for a reader function that reads a byte array from a data source.
 *
 * The reader function should take a `void*` as an argument and return a pointer to an array of
 * `uint8_t` representing the bytes of data read from the source.
 */
typedef size_t (*cdt_reader_fn)(uint8_t *data, size_t size, size_t nmemb, void* stream);

/**
 * @brief Decodes the header information of a Cryptdatum data without decoding the entire data.
 * Caller is responsible to close the source e.g FILE
 *
 * @param[in] r Function pointer to a reader function that reads a byte array from the data source.
 * @param[in] source Pointer to the data source e.g FILE.
 * @param[out] header Pointer to a struct to receive the decoded header information.
 * @return An error code indicating the result of the operation.
 */
cdt_error_t decode_header(cdt_reader_fn read, void* source, cdt_header_t* header);

/**
 * @brief Reader implementation to read cryptdatum from file source.
 *
 * @param[out] buffer Pointer to the buffer to store the read data.
 * @param[in] size Size of each element in the buffer.
 * @param[in] nmemb Number of elements to read.
 * @param[in] fp Pointer to the file to read from.
 * @return The number of elements read, or 0 if an error occurred.
 */
size_t cdt_fread(uint8_t *buffer, size_t size, size_t nmemb, void* fp);

#ifdef __cplusplus
}
#endif

#endif // CRYPTDATUM_H
