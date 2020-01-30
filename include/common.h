/* Tamaño clave pública Diffie-Hellman: 64 bytes */
#define DH_PUBLIC_KEY_SIZE 64

/* Tamaño clave privada Diffie-Hellman: 32 bytes */
#define DH_PRIVATE_KEY_SIZE 32

/* Tamaño secreto compartido Diffie-Hellman: 32 bytes */
#define DH_SECRET_SIZE 32

/* Tamaño clave Blowfish: 32 bytes (256 bits)*/
#define BLOWFISH_KEY_SIZE 32

/**
 * Closes the socket, prints error on STDERR and exits.
 *
 * @param connfd Socket file descriptor.
 */
void connection_error(int connfd);

void print_hex(const unsigned char* data, size_t size);
