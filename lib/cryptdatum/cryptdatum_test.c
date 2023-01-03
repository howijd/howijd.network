// go:build !cgo
//  +build !cgo

#include "cryptdatum.h"
#include <assert.h>
#include <string.h>


void test_verify_header_magic()
{
  // Test valid header
  uint8_t valid_header[CRYPTDATUM_HEADER_SIZE] = {0};
  memcpy(valid_header, magic, sizeof(magic));
  memcpy(valid_header + CRYPTDATUM_HEADER_SIZE - sizeof(delimiter), delimiter, sizeof(delimiter));
  assert(verify_header(valid_header) == 1);

  // Test invalid magic number
  uint8_t invalid_magic_header[CRYPTDATUM_HEADER_SIZE] = {0};
  memset(invalid_magic_header, 0xFF, sizeof(invalid_magic_header));
  memcpy(invalid_magic_header + CRYPTDATUM_HEADER_SIZE - sizeof(delimiter), delimiter, sizeof(delimiter));
  assert(verify_header(invalid_magic_header) == 0);
}

void test_verify_header_too_small_data()
{
  uint8_t valid_header[CRYPTDATUM_HEADER_SIZE-1] = {0};
  memcpy(valid_header, magic, sizeof(magic));
  memcpy(valid_header + CRYPTDATUM_HEADER_SIZE-1 - sizeof(delimiter), delimiter, sizeof(delimiter));
  assert(verify_header(valid_header) == 0);
}

void test_verify_header_delimiter()
{
    // Test invalid delimiter
  uint8_t valid_header[CRYPTDATUM_HEADER_SIZE] = {0};
  memcpy(valid_header, magic, sizeof(magic));
  memcpy(valid_header + CRYPTDATUM_HEADER_SIZE - sizeof(magic), magic, sizeof(magic));
  assert(verify_header(valid_header) == 0);
}

int main(int argc, char **argv)
{
  test_verify_header_magic();
  test_verify_header_delimiter();
  test_verify_header_too_small_data();
  return 0;
}
