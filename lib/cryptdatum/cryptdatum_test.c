// go:build !cgo
//  +build !cgo

#include "cryptdatum.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>

void test_verify_header_magic()
{
  // Test invalid magic number
  uint8_t header[CDT_HEADER_SIZE];
  memset(header, 0xFF, sizeof(header));

  uint16_t version_n = htobe16(1);
  uint64_t datum_draft_n = htobe64(CDT_DATUM_DRAFT);
  memcpy(header + 8, &version_n, 2);
  memcpy(header + 10, &datum_draft_n, 8);

  memcpy(header + CDT_HEADER_SIZE - 8, CDT_DELIMITER, 8);
  assert(verify_header(header) == 0);
}

void test_verify_header_too_small_data()
{
  uint8_t header[CDT_HEADER_SIZE-1];
  memcpy(header, CDT_MAGIC, 8);

  uint16_t version_n = htobe16(1);
  uint64_t datum_draft_n = htobe64(CDT_DATUM_DRAFT);
  memcpy(header + 8, &version_n, 2);
  memcpy(header + 10, &datum_draft_n, 8);

  memcpy(header + CDT_HEADER_SIZE-9, CDT_DELIMITER, 8);
  assert(verify_header(header) == 0);
}

void test_verify_header_delimiter()
{
    // Test invalid delimiter
  uint8_t header[CDT_HEADER_SIZE];
  memcpy(header, CDT_MAGIC, 8);

  uint16_t version_n = htobe16(1);
  uint64_t datum_draft_n = htobe64(CDT_DATUM_DRAFT);
  memcpy(header + 8, &version_n, 2);
  memcpy(header + 10, &datum_draft_n, 8);

  memcpy(header + CDT_HEADER_SIZE - 8, CDT_MAGIC, 8);
  assert(verify_header(header) == 0);
}

void test_verify_header_spec_V1()
{
  FILE *f = fopen("testdata/v1/valid-header.cdt", "r");
  if (!f) {
    fprintf(stderr, "error: failed to open file\n");
    return;
  }
  // Allocate a buffer to hold the header
  uint8_t *header = malloc(CDT_HEADER_SIZE);
  if (!header) {
    fprintf(stderr, "error: failed to allocate memory\n");
    fclose(f);
    return;
  }
  // Read the header into the buffer
  size_t bytes_read = fread(header, 1, CDT_HEADER_SIZE, f);
  fclose(f);
  int result = verify_header(header);
  free(header);
  assert(result == 1);
}

int main(int argc, char *argv[])
{
  test_verify_header_magic();
  test_verify_header_too_small_data();
  test_verify_header_delimiter();
  test_verify_header_spec_V1();
  return 0;
}
