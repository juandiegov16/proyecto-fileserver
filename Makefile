CC = gcc
CFLAGS = -Wall -c -I$(INCLUDE) $^ -o $@
OFLAGS = -Wall -I$(INCLUDE) $^ -o $@ -lpthread

INCLUDE = include
SRC_DIR = src
OBJ_DIR = obj
LDIR = lib

NAME = crypto
SLIB = $(LDIR)/lib$(NAME).a
CSAPP = $(OBJ_DIR)/csapp.o
SERVER = file_server
CLIENT = file_client

I_FILES = $(wildcard $(INCLUDE)/*.h)
SRC_FILES = $(wildcard $(SRC_DIR)/*.c)
OBJ_FILES = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRC_FILES))
EXE_FILES =  $(SERVER) $(CLIENT)

.PHONY: all debug sanitize clean dir help
all: $(SLIB) $(OBJ_FILES) $(SERVER) $(CLIENT)

$(SLIB): $(OBJ_DIR)/blowfish.o $(OBJ_DIR)/uECC.o $(OBJ_DIR)/sha256.o
	ar rcs $(SLIB) $^

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS)

$(SERVER): $(OBJ_DIR)/file_server.o $(SLIB) $(CSAPP)
	$(CC) $(OFLAGS) $(DFLAGS)

$(CLIENT): $(OBJ_DIR)/file_client.o $(SLIB) $(CSAPP)
	$(CC) $(OFLAGS) $(DFLAGS)

## debug: Compila usando la opción -g para facilitar la depuración con gdb.
debug: DFLAGS = -g
debug: clean all

## sanitize: Compila habilitando la herramienta AddressSanitizer para facilitar la depuración en tiempo de ejecución.
sanitize: DFLAGS = -fsanitize=address,undefined
sanitize: clean all

## clean: Limpia archivos autogenerados
clean:
	rm -rf $(EXE_FILES) $(OBJ_FILES) $(SLIB)

## dir: Muestra contenido del proyecto en formato largo
dir:
	ls -lhR

help : Makefile
	@sed -n 's/^##//p' $<
