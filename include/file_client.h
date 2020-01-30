#ifndef __FILE_CLIENT_H__
#define __FILE_CLIENT_H__

#include "csapp.h"
#include "common.h"
#include "uECC.h"
#include "sha256.h"
#include "blowfish.h"

void print_help(char *command);

void vli_print(uint8_t *vli, unsigned int size);

char **parse_request(char *line, char *delim);

#endif
