#include "file_client.h"
#include <stdbool.h>
#include <getopt.h>
#include <limits.h>

bool hflag = false;

void print_help(char *command)
{
  printf("%s connects to a remote file_server service and allows the user to upload and download files from the server.\n\n", command);
  printf("Usage:\n");
  printf(" %s <ip> <port>\n", command);
  printf(" %s -h\n", command);
  printf("Options:\n");
  printf(" -h\t\t\tHelp, show this message.\n");
}

void vli_print(uint8_t *vli, unsigned int size)
{
  for(unsigned i=0; i<size; ++i) {
    printf("%02X ", (unsigned)vli[i]);
  }
}

void connection_error(int connfd)
{
  fprintf(stderr, "Connection error: %s\n", strerror(errno));
  close(connfd);
  exit(-1);
}

//Imprime cadena de bytes en formato hexadecimal
void print_hex(const unsigned char* data, size_t size)
{
  int i;
  for(i = 0; i < size; ++i)
  printf("%02x",(unsigned char) data[i]);
}

char **parse_request(char *line, char *delim)
{
  char *token;
  char *line_copy;
  int i, num_tokens = 0;
  char **request_tokens = NULL;
  char *saveptr = NULL;

  line_copy = (char *) Malloc(strlen(line) + 1);
  strcpy(line_copy, line);

  /* Obtiene un conteo del número de argumentos */
  token = strtok_r(line_copy, delim, &saveptr);
  /* recorre todos los tokens */
  while( token != NULL ) {
    token = strtok_r(NULL, delim, &saveptr);
    num_tokens++;
  }
  Free(line_copy);

  /* Crea request_tokens en el heap, extrae y copia los argumentos */
  if(num_tokens > 0){

    /* Crea el arreglo request_tokens */
    request_tokens = (char **) Malloc((num_tokens + 1) * sizeof(char **));

    /* obtiene el primer token */
    token = strtok_r(line, delim, &saveptr);
    /* recorre todos los tokens */
    for(i = 0; i < num_tokens; i++){
      request_tokens[i] = (char *) Malloc(strlen(token)+1);
      strcpy(request_tokens[i], token);
      token = strtok_r(NULL, delim, &saveptr);
    }
    request_tokens[i] = NULL;
  }

  return request_tokens;
}

int main(int argc, char **argv)
{
  int opt;

  //Socket
  int clientfd;
  //Direcciones y puertos
  char *hostname, *port;

  //Lectura desde consola
  char *linea_consola;
  char read_buffer[MAXLINE + 1] = {0};
  char start_message[MAXLINE] = {0};
  char ready_message[MAXLINE] = {0};
  char filename[MAXLINE] = {0};
  size_t max = MAXLINE;
  ssize_t n, l = 0;
  char **request_tokens;

  //Variables para encriptado/desencriptado
  //Diffie-Hellman
  uECC_Curve secp160r1 = uECC_secp160r1();
  uint8_t public_key[DH_PUBLIC_KEY_SIZE] = {0};
  uint8_t private_key[DH_PRIVATE_KEY_SIZE] = {0};
  uint8_t received_public_key[DH_PUBLIC_KEY_SIZE] = {0};
  uint8_t shared_secret[DH_SECRET_SIZE] = {0};

  //SHA-256
  SHA256_CTX ctx;
  BYTE hashed_secret[SHA256_BLOCK_SIZE];

  //Blowfish
  BLOWFISH_KEY key;

  ssize_t bytesRead = 0;
  unsigned long filesize;
  struct stat sbuf;

  while ((opt = getopt (argc, argv, "h")) != -1)
  {
    switch(opt)
    {
      case 'h':
      hflag = true;
      print_help(argv[0]);
      return 0;

      case '?':
      fprintf(stderr, "Invalid option.\n");
      return 0;
      break;

      default:
      fprintf(stderr, "Usage:\n");
      fprintf(stderr, " %s <ip> <port>\n", argv[0]);
      fprintf(stderr, " %s -h\n", argv[0]);
      return -1;
    }
  }

  if (argc != 3 && hflag == false) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, " %s <ip> <port>\n", argv[0]);
    fprintf(stderr, " %s -h\n", argv[0]);
    exit(0);
  }else{
    hostname = argv[1];
    port = argv[2];
  }

  //Valida el puerto
  int port_n = atoi(port);
  if(port_n <= 0 || port_n > USHRT_MAX){
    fprintf(stderr, "Port %s is invalid. Enter a number between 1 and %d.\n", port, USHRT_MAX);
    return -1;
  }
  clientfd = open_clientfd(hostname, port);
  if(clientfd < 0)
  connection_error(clientfd);

  printf("\nConnected successfully to %s on port %s.\n\n", hostname, port);

  //Manda mensaje "START\n"
  strcpy(start_message, "START\n");
  write(clientfd, start_message, strlen(start_message));

  //Crea par de claves DH
  uECC_make_key(public_key,private_key,secp160r1);

  //IMPRESIONES DE PRUEBA de las claves generadas
  printf("Public key = ");
  vli_print(public_key, DH_PUBLIC_KEY_SIZE);
  printf("\n");
  printf("Private key = ");
  vli_print(private_key, DH_PRIVATE_KEY_SIZE);
  printf("\n");

  //Recibe la clave pública del servidor
  recv(clientfd, received_public_key, DH_PUBLIC_KEY_SIZE, 0);

  //Envía clave pública propia al servidor
  send(clientfd, public_key, DH_PUBLIC_KEY_SIZE, 0);

  //Valida clave pública del servidor
  if((uECC_valid_public_key(received_public_key, secp160r1)) == 0)
  {
    printf("Received public key is not valid. Disconnecting...\n");
    close(clientfd);
    exit(0);
  }else{
    //Crea secreto compartido
    uECC_shared_secret(received_public_key, private_key, shared_secret, secp160r1);

    // IMPRESIONES DE PRUEBA
    printf("Shared secret = ");
    vli_print(shared_secret, DH_SECRET_SIZE);
    printf("\n");

    //Procedimiento SHA-256
    sha256_init(&ctx);
    sha256_update(&ctx, shared_secret, DH_SECRET_SIZE);
    sha256_final(&ctx, hashed_secret);

    //Imprime el hash en SHA-256 del secreto compartido
    printf("Hashed secret: \n");
    print_hex(hashed_secret, DH_SECRET_SIZE);
    printf("\n");

    //Procedimiento inicial Blowfish
    blowfish_key_setup(hashed_secret, &key, BLOWFISH_KEY_SIZE);

    printf("\nEncryption ready.\n\n");
  }

  printf("\n> ");
  l = getline(&linea_consola, &max, stdin);
  while(l > 0){
    if(strncmp(linea_consola, "LIST", 4) == 0)
    {
      n = write(clientfd, linea_consola, l); //Envia al servidor
      if(n<=0)
      break;
    }
    else if(strncmp(linea_consola, "BYE", 3) == 0)
    {
      n = write(clientfd, linea_consola, l); //Envia al servidor
      if(n<=0)
      break;
    }
    else if(strncmp(linea_consola, "PUT", 3) == 0)
    {
      linea_consola[l - 1] = '\0';
      request_tokens = parse_request(linea_consola, " ");
      if(request_tokens[1]!= NULL)
      {
        strcpy(filename, "cliente/");
        strcat(filename, request_tokens[1]);

        if(stat(filename, &sbuf)< 0)
        {
          printf("Archivo no existe.\n");
          continue;
        }else{
          char temp[MAXLINE] = {0};
          char tam[MAXLINE] = {0};
          filesize = sbuf.st_size;
          sprintf(tam, "%lu", filesize);

          strcpy(temp, "PUT ");
          strcat(temp, request_tokens[1]);
          strcat(temp, " ");
          strcat(temp, tam);
          strcat(temp, "\n");
          printf("Sent request: %s", temp);
          n = write(clientfd, temp, MAXLINE); //Envia al servidor
          if(n<=0)
          break;
        }
      }
      else{
        printf("Invalid request.\n");
        break;
      }
    }
    else if(strncmp(linea_consola, "GET", 3) == 0)
    {
      n = write(clientfd, linea_consola, l); //Envia al servidor
      if(n<=0)
      break;
      linea_consola[n - 1] = '\0';
      request_tokens = parse_request(linea_consola, " ");

      if(request_tokens[1]!= NULL)
      {
        strcpy(filename, "cliente/");
        strcat(filename, request_tokens[1]);
        printf("%s\n", filename);
      }
    }
    else{
      n = write(clientfd, linea_consola, l); //Envia al servidor
      if(n<=0)
      break;
    }
    /* Obtiene respuesta del servidor
    * Insiste hasta vaciar el socket
    */
    bool continuar = false;
    do{
      //Usa recv con MSG_DONTWAIT para no bloquear al leer el socket
      n = recv(clientfd, read_buffer, MAXLINE, MSG_DONTWAIT);

      if(strcmp(read_buffer, "BYE\n") == 0){
        printf("Disconnecting...\n");
        Free(linea_consola);
        Close(clientfd);
        exit(0);
      }

      //Si recibe tamaño de archivo como respuesta a solicitud GET
      if(atoi(read_buffer) && ((atoi(read_buffer))>0)){

        //Guarda tamaño del archivo solicitado
        filesize = atoi(read_buffer);
        strcpy(ready_message, "READY\n");

        //Envía mensaje READY
        Write(clientfd, ready_message, strlen(ready_message));

        int fd1 = open(filename, O_WRONLY | O_CREAT | O_TRUNC, S_IWUSR | S_IRUSR);
        if( fd1 < 0){
          perror("Couldn't open file\n");
          exit(-1);
        }

        int mult8 = ((filesize %  8 == 0)) ? filesize : ((int)(filesize/8)) * 8 + 8;
        char *buf_file = (char *)calloc(mult8, sizeof(char));
        int i = 0;
        long int *salida = buf_file;

        while(i < mult8)
        {
          char entrada[BLOWFISH_BLOCK_SIZE] ={0};
          read(clientfd, entrada, BLOWFISH_BLOCK_SIZE);
          blowfish_decrypt(entrada, salida, &key);
          salida++;
          i += 8;
        }

        bytesRead = write(fd1, buf_file, filesize);
        close(fd1);
        free(buf_file);
        printf("\nDONE. %d bytes downloaded.\n", atoi(read_buffer));
        memset(read_buffer,0,MAXLINE + 1); //Encerar el buffer
      }

      //Si recibe READY como respuesta a solicitud PUT
      if(strcmp(read_buffer, "READY\n") == 0)
      {
        printf("%s", read_buffer);
        printf("Sending file %s...\n", request_tokens[1]);

        int fd2 = open(filename, O_RDONLY, S_IRUSR);
        if( fd2 < 0){
          perror("Couldn't open file.\n");
        }

        int mult8 = ((filesize %  8 == 0)) ? filesize : ((int)(filesize/8)) * 8 + 8;
        char *buf_file = (char *)calloc(mult8, sizeof(char));
        bytesRead = read(fd2, buf_file, filesize);
        int i = 0;
        long int *entrada = buf_file;

        while(i < mult8)
        {
          char salida[BLOWFISH_BLOCK_SIZE] ={0};
          blowfish_encrypt(entrada, salida, &key);
          write(clientfd, salida, BLOWFISH_BLOCK_SIZE);
          entrada++;
          i += 8;
        }
        close(fd2);
        free(buf_file);
        memset(read_buffer,0,MAXLINE + 1);
        printf("File uploaded.\n");
      }

      if(n < 0){
        if(errno == EAGAIN) //Vuelve a intentar
        continuar = true;
        else
        continuar = false;
      }else if(n == MAXLINE) //Socket lleno, volver a leer
      {
        continuar = true;
      }
      else if(n == 0)
      {
        continuar = false;
      }
      else{
        //n < MAXLINE, se asume que son los últimos caracteres en el socket
        char c = read_buffer[n - 1]; //Busca '\0' para detectar fin
        if(c == '\0')
        continuar = false;
        else
        continuar = true;
      }

      printf("%s", read_buffer);
      memset(read_buffer,0,MAXLINE + 1); //Encerar el buffer
    }while(continuar);

    printf("\n> ");
    l = getline(&linea_consola, &max, stdin);
  }
  printf("Disconnecting...\n");
  free(linea_consola);
  close(clientfd);
}
