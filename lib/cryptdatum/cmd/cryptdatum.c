// go:build !cgo
//  +build !cgo

#include "../cryptdatum.h"
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define _SIZE_BUF_LEN 100

const char* bool_str(bool value) {
  return value ? "true" : "false";
}

bool VERBOSE = false;

void pretty_size(uint64_t size, char* buf, size_t buf_len) {
  const char* units[] = {"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"};
  int i = 0;

  snprintf(buf, buf_len, "%" PRIu64 " %s", size, units[i]);
}

void print_header(cdt_header_t* header) {
  // TIMESTAMP
  char created[_SIZE_BUF_LEN];
  struct tm tm;
  time_t t = (time_t)(header->timestamp / 1000000000);
  gmtime_r(&t, &tm);
  strftime(created, sizeof(created), "%Y-%m-%dT%H:%M:%S", &tm);
  snprintf(created + strlen(created), sizeof(created) - strlen(created), ".%09ldZ", header->timestamp % 1000000000);
  // SIZE
  char datumsize[_SIZE_BUF_LEN];
  pretty_size(header->size, datumsize, _SIZE_BUF_LEN);

  printf("+--------------+------------+-----------------------------+-------------------+---------------------------------+\n");
  printf("| CRYPTDATUM   | SIZE: %34s | CREATED:%43s |\n", datumsize, created);
  printf("+--------------+------------+-----------------------------+-------------------+---------------------------------+\n");
  printf("| Field        | Size (B)   | Description                 | Type              | Value                           |\n");
  printf("+--------------+------------+-----------------------------+-------------------+---------------------------------+\n");
  printf("| Version      | 2          | Version number              | uint16            | %-31u |\n", header->version);
  printf("| Flags        | 8          | Flags                       | uint64            | %-31"PRIu64 " |\n", header->flags);
  printf("| Timestamp    | 8          | Timestamp                   | uint64            | %-31"PRIu64 " |\n", header->timestamp);
  printf("| OPC          | 4          | Operation Counter           | uint32            | %-31u |\n", header->opc);
  printf("| Checksum     | 8          | Checksum                    | uint64            | %-31"PRIu64 " |\n", header->checksum);
  printf("| Size         | 8          | Total size                  | uint64            | %-31"PRIu64 " |\n", header->size);
  printf("| Comp. Alg.   | 2          | Compression algorithm       | uint16            | %-31u |\n", header->compression_alg);
  printf("| Encrypt. Alg | 2          | Encryption algorithm        | uint16            | %-31u |\n", header->encryption_alg);
  printf("| Sign. Type   | 2          | Signature type              | uint16            | %-31u |\n", header->signature_type);
  printf("| Sign. Size   | 4          | Signature size              | uint32            | %-31u |\n", header->signature_size);
  printf("| File Ext.    | 8          | File extension              | char[8]           | %-31s |\n", header->file_ext);
  printf("| Custom       | 8          | Custom                      | uint8[8]          | %03hhu %03hhu %03hhu %03hhu %03hhu %03hhu %03hhu %03hhu |\n",
    header->custom[0], header->custom[1], header->custom[2], header->custom[3],
    header->custom[4], header->custom[5], header->custom[6], header->custom[7]);
  printf("+--------------+------------+----------------------------+--------------------+---------------------------------+\n");
  printf("| FLAGS                                                                                                         |\n");
  printf("+------------+--------+-------------+--------+--------------+--------+------------------------------------------+\n");
  printf("| Invalid    | %-6s | OPC         | %-6s | Signed       | %-6s |                                          |\n",
    bool_str(header->flags & CTD_DATUM_INVALID), bool_str(header->flags & CDT_DATUM_OPC), bool_str(header->flags & CDT_DATUM_SIGNED));
  printf("| Draft      | %-6s | Compressed  | %-6s | Streamable   | %-6s |                                          |\n",
    bool_str(header->flags & CDT_DATUM_DRAFT), bool_str(header->flags & CDT_DATUM_COMPRESSED), bool_str(header->flags & CDT_DATUM_STREAMABLE));
  printf("| Empty      | %-6s | Encrypted   | %-6s | Custom       | %-6s |                                          |\n",
    bool_str(header->flags & CDT_DATUM_EMPTY), bool_str(header->flags & CDT_DATUM_ENCRYPTED), bool_str(header->flags & CDT_DATUM_CUSTOM));
  printf("| Checksum   | %-6s | Extractable | %-6s | Compromised  | %-6s |                                          |\n",
    bool_str(header->flags & CDT_DATUM_CHECKSUM), bool_str(header->flags & CDT_DATUM_EXTRACTABLE), bool_str(header->flags & CDT_DATUM_COMPROMISED));
  printf("+------------+--------+-------------+--------+--------------+--------+------------------------------------------+\n");
}

int _cmd_file_has_header(char *filename)
{
  FILE *f = fopen(filename, "r");
  if (!f) {
    fprintf(stderr, "%s(%d): failed to open file\n", CDT_ERR_STR[CDT_ERROR_IO], CDT_ERROR_IO);
    return 1;
  }
  // Allocate a buffer to hold the header
  uint8_t *headerb = malloc(CDT_HEADER_SIZE);
  if (!headerb) {
    fprintf(stderr, "%s(%d): failed to allocate memory\n", CDT_ERR_STR[CDT_ERROR_IO], CDT_ERROR_IO);
    fclose(f);
    return 1;
  }
  // Read the header into the buffer
  size_t bytes_read = fread(headerb, 1, CDT_HEADER_SIZE, f);
  fclose(f);

  // Check header
  int exitcode = 0;
  if (bytes_read < CDT_HEADER_SIZE || has_header(headerb) != 1) {
    if (VERBOSE) fprintf(stderr, "%s(%d)\n", CDT_ERR_STR[CDT_ERROR_NO_HEADER], CDT_ERROR_NO_HEADER);
    exitcode = 1;
  }
  free(headerb);
  return exitcode;
}

int _cmd_file_has_valid_header(char *filename)
{
  FILE *f = fopen(filename, "r");
  if (!f) {
    fprintf(stderr, "%s(%d): failed to open file\n", CDT_ERR_STR[CDT_ERROR_IO], CDT_ERROR_IO);
    return 1;
  }
  // Allocate a buffer to hold the header
  uint8_t *headerb = malloc(CDT_HEADER_SIZE);
  if (!headerb) {
    fprintf(stderr, "%s(%d): failed to allocate memory\n", CDT_ERR_STR[CDT_ERROR_IO], CDT_ERROR_IO);
    fclose(f);
    return 1;
  }
  // Read the header into the buffer
  size_t bytes_read = fread(headerb, 1, CDT_HEADER_SIZE, f);
  fclose(f);

  int exitcode = 0;

  // Check that we read the full header
  if (bytes_read < CDT_HEADER_SIZE || has_header(headerb) != 1) {
    if (VERBOSE) fprintf(stderr, "%s(%d)\n", CDT_ERR_STR[CDT_ERROR_NO_HEADER], CDT_ERROR_NO_HEADER);
    exitcode = 1;
  }
  if (exitcode == 0 && has_valid_header(headerb) != 1) {
    if (VERBOSE) fprintf(stderr, "%s(%d)\n", CDT_ERR_STR[CDT_ERROR_INVALID_HEADER], CDT_ERROR_INVALID_HEADER);
    exitcode = 1;
  }

  free(headerb);
  return exitcode;
}


int _cmd_file_info(char *filename)
{
  FILE *fp = fopen(filename, "r");
  if (!fp) {
    fprintf(stderr, "%s(%d): failed to open file\n", CDT_ERR_STR[CDT_ERROR_IO], CDT_ERROR_IO);
    return 1;
  }
  cdt_header_t header;
  cdt_error_t err = decode_header(cdt_fread, fp, &header);
  if (err != CDT_ERROR_NONE) {
    fprintf(stderr, "%s(%d): failed to decode header\n", CDT_ERR_STR[err], err);
    fclose(fp);
    return 1;
  }
  fclose(fp);

  print_header(&header);
  return 0;
}

int main(int argc, char *argv[])
{
  int opt;
  while ((opt = getopt(argc, argv, "v")) != -1) {
    switch (opt) {
      case 'v': VERBOSE = true; break;
      default:
        abort ();
    }
  }

  if (argc < 2) {
    fprintf(stderr, "%s(%d): no subcommand provided\n", CDT_ERR_STR[CDT_ERROR], CDT_ERROR);
    return 1;
  }

  if (strcmp(argv[optind], "file-has-header") == 0) {
    return _cmd_file_has_header(argv[optind+1]);
  } else if (strcmp(argv[optind], "file-has-valid-header") == 0) {
    return _cmd_file_has_valid_header(argv[optind+1]);
  } else if (strcmp(argv[optind], "file-info") == 0) {
    return _cmd_file_info(argv[optind+1]);
  } else {
    fprintf(stderr, "%s(%d): unknown subcommand '%s'\n", CDT_ERR_STR[CDT_ERROR], CDT_ERROR, argv[1]);
    return 1;
  }
  return 0;
}

