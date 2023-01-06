// go:build !cgo
//  +build !cgo

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../cryptdatum.h"

int _cmd_verify(char *file)
{
  FILE *f = fopen(file, "r");
  if (!f) {
    fprintf(stderr, "error: failed to open file\n");
    return 1;
  }
  // Allocate a buffer to hold the header
  uint8_t *header = malloc(CRYPTDATUM_HEADER_SIZE);
  if (!header) {
    fprintf(stderr, "error: failed to allocate memory\n");
    fclose(f);
    return 1;
  }
  // Read the header into the buffer
  size_t bytes_read = fread(header, 1, CRYPTDATUM_HEADER_SIZE, f);
  fclose(f);
  // Check that we read the full header
  if (bytes_read < CRYPTDATUM_HEADER_SIZE) {
    free(header);
    return 1;
  }
  // Verify the header
  int result = verify_header(header) == 0;
  free(header);
  return result;
}


int main(int argc, char *argv[])
{
  if (argc < 2) {
    printf("error: no subcommand provided.\n");
    return 1;
  }

  if (strcmp(argv[1], "verify") == 0) {
    return _cmd_verify(argv[2]);
  } else {
    printf("error: unknown subcommand '%s'\n", argv[1]);
    return 1;
  }
  return 0;
}

