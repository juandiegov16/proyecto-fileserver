#ifndef __FILE_SERVER_H__
#define __FILE_SERVER_H__

#include "csapp.h"
#include "common.h"
#include "uECC.h"
#include "sha256.h"
#include "blowfish.h"
#include <syslog.h>
#include <sys/resource.h>

void print_help(char *command);

void atender_cliente(int connfd);

char **parse_request(char *line, char *delim);

void daemonize();

void recoger_hijos(int signal);

void vli_print(uint8_t *vli, unsigned int size);

#endif
