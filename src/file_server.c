#include "file_server.h"
#include <stdbool.h>
#include <getopt.h>
#include <limits.h>

bool dflag = false; //-d option, Daemon mode.
void *thread(void *vargp);
sem_t mutex;

int main(int argc, char **argv)
{
  int opt;
  //Sockets
  int listenfd, *connfd, index;
  unsigned int clientlen;
  //Direcciones y puertos
  struct sockaddr_in clientaddr;
  char *port;
  pthread_t tid;


  while ((opt = getopt (argc, argv, "hd")) != -1)
  {
    switch(opt)
    {
      case 'h':
      print_help(argv[0]);
      return 0;

      case 'd':
      dflag = true;
      break;

      case '?':
      fprintf(stderr, "Invalid option.\n");
      return 0;

      default:
      fprintf(stderr, "Usage:\n");
      fprintf(stderr, " %s [-d] <port>\n", argv[0]);
      fprintf(stderr, " %s -h\n", argv[0]);
      return -1;
    }
  }

  if (argc < 2)
  {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, " %s [-d] <port>\n", argv[0]);
    fprintf(stderr, " %s -h\n", argv[0]);
    exit(0);
  }
  port = argv[1];

  //Valida el puerto
  int port_n = atoi(port);
  if(port_n <= 0 || port_n > USHRT_MAX){
    fprintf(stderr, "Port %s is invalid. Enter a number between 1 and %d.\n", port, USHRT_MAX);
    return -1;
  }

  if(dflag == true)
  {
    for (index = optind; index < argc; index++)
    {
      port = argv[index];
    }
    printf("Listening on port %s as a daemon...\n", port);
    daemonize();
  }


  signal(SIGCHLD, recoger_hijos);

  listenfd = Open_listenfd(port);

  if(listenfd < 0)
  connection_error(listenfd);

  printf("\nServer listening on port %s...\n\n", port);
  Sem_init(&mutex, 0, 1);

  while (1)
  {
    clientlen = sizeof(clientaddr);
    connfd = Malloc(sizeof(int));
    *connfd = Accept(listenfd, (struct sockaddr *)&clientaddr, &clientlen);
    Pthread_create(&tid, NULL, thread, connfd);
  }
}

void print_help(char *command)
{
  printf("%s uses Blowfish encryption to upload and download files to a server from connected clients.\n\n", command);
  printf("Usage:\n");
  printf(" %s [-d] <port>\n", command);
  printf(" %s -h\n", command);
  printf("Options:\n");
  printf(" -h\t\t\tHelp, show this message.\n");
  printf(" -d\t\t\tActivate Daemon mode.\n");
}

void connection_error(int connfd)
{
  fprintf(stderr, "Connection error: %s\n", strerror(errno));
  Close(connfd);
  exit(-1);
}

void atender_cliente(int connfd)
{
  int n;
  int status;
  char buf[MAXLINE] ={0};
  char response[MAXLINE] = {0};
  char start_message[MAXLINE] = {0};
  char ready_incoming[MAXLINE] = {0};
  char filename[MAXLINE] = {0};
  char **request_tokens;
  char *list_arg[4] = {"ls", "-lh", "./servidor",  0};
  pid_t pid;

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

  //Recibe mensaje "START"
  Read(connfd, start_message, MAXLINE);

  if(strcmp(start_message, "START\n") == 0){
    //Crea par de claves DH
    uECC_make_key(public_key,private_key,secp160r1);

    //IMPRESIONES DE PRUEBA de las claves generadas
    printf("Public key = ");
    vli_print(public_key, DH_PUBLIC_KEY_SIZE);
    printf("\n");
    printf("Private key = ");
    vli_print(private_key, DH_PRIVATE_KEY_SIZE);
    printf("\n");


    //Envía clave pública al cliente
    P(&mutex);
    send(connfd, public_key, DH_PUBLIC_KEY_SIZE, 0);
    V(&mutex);

    //Recibe la clave pública del cliente
    P(&mutex);
    recv(connfd, received_public_key, DH_PUBLIC_KEY_SIZE, 0);
    V(&mutex);

    //Valida clave pública del cliente
    if((uECC_valid_public_key(received_public_key, secp160r1)) == 0)
    {
      printf("Received public key is not valid.\n");
      return;
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

      // IMPRESIONES DE PRUEBA
      //Imprime el hash en SHA-256 del secreto compartido
      printf("Hashed secret: \n");
      print_hex(hashed_secret, DH_SECRET_SIZE);
      printf("\n");

      //Procedimiento inicial Blowfish
      blowfish_key_setup(hashed_secret, &key, BLOWFISH_KEY_SIZE);

      printf("\nEncryption ready.\n");
    }

  }
  else{
    printf("START command not received.\n");
    return;
  }

  while(1)
  {
    n = Read(connfd, buf, MAXLINE);

    printf("\nServer received: %s", buf);

    //Remueve el salto de linea antes de extraer los tokens
    buf[n - 1] = '\0';
    //Crea request_tokens con los argumentos en buf, asume separación por espacio
    request_tokens = parse_request(buf, " ");

    if(request_tokens)
    {
      //Detecta "BYE" y desconecta al cliente
      if(strcmp(request_tokens[0], "BYE") == 0)
      {
        strcpy(response, "BYE\n");
        P(&mutex);
        Write(connfd, response, strlen(response) + 1);
        V(&mutex);
        return;
      }
      else if(strcmp(request_tokens[0], "LIST") == 0)
      {
        if((pid = fork()) == 0){
          Dup2(connfd, 1); //Redirecciona STDOUT al socket
          Dup2(connfd, 2); //Redirecciona STDERR al socket
          if(execvp(list_arg[0], list_arg) < 0){
            fprintf(stderr, "Comando desconocido.\n");
            exit(1);
          }
        }
        //Espera a que el proceso hijo termine su ejecución
        waitpid(pid, &status, 0);

        if(!WIFEXITED(status))
        {
          P(&mutex);
          Write(connfd, "ERROR\n",7);
          V(&mutex);
        }
        else
        {
          P(&mutex);
          Write(connfd, "\0", 1); //Envia caracter null para notificar fin
          V(&mutex);
        }
      }
      else if(strcmp(request_tokens[0], "GET") == 0)
      {
        if(request_tokens[1] != NULL)
        {
          //Si archivo solicitado no existe, escribe "0\n"
          strcpy(filename, "servidor/");
          strcat(filename, request_tokens[1]);
          if (stat(filename, &sbuf)<0)
          {
            strcpy(response, "0\n");
            P(&mutex);
            Write(connfd, response, strlen(response) + 1);
            V(&mutex);
          }else
          {
            //Si archivo solicitado existe, responde con su tamaño en bytes
            unsigned long filesize = sbuf.st_size;
            sprintf(response, "%lu\n", filesize);
            Write(connfd, response, strlen(response) + 1);

            //Asegura recepción de mensaje "READY\n" para transmitir
            Read(connfd, ready_incoming, MAXLINE);
            if (strcmp(ready_incoming, "READY\n") == 0)
            {
              printf("%s", ready_incoming);
              printf("Sending file %s...\n", filename);

              int fd1 = open(filename, O_RDONLY, S_IRUSR);
              if( fd1 < 0){
                perror("Couldn't open file.\n");
              }

              int mult8 = ((filesize %  8 == 0)) ? filesize : ((int)(filesize/8)) * 8 + 8;
              char *buf_file = (char *)calloc(mult8, sizeof(char));
              bytesRead = read(fd1, buf_file, filesize);
              int i = 0;

              long int *entrada = buf_file;
              while(i < mult8)
              {
                char salida[BLOWFISH_BLOCK_SIZE] ={0};
                blowfish_encrypt(entrada, salida, &key);
                write(connfd, salida, BLOWFISH_BLOCK_SIZE);
                entrada++;
                i += 8;
              }
              close(fd1);
              free(buf_file);
              printf("File sent.\n");
            }

          }
        }
        else
        {
          strcpy(response, "Badly formulated request.\nUsage: GET <file name>\n");
          Write(connfd, response, strlen(response) + 1);

        }
      }
      else if(strcmp(request_tokens[0], "PUT") == 0)
      {
        if(request_tokens[1] != NULL)
        {
          //Guarda tamaño del archivo que el cliente quiere subir
          filesize = atol(request_tokens[2]);
          strcpy(response, "READY\n");

          /*Envía mensaje READY como confirmación de haber
           recibido solicitud PUT válida*/
          n = Write(connfd, response, strlen(response));
          if(n<=0)
          break;

          strcpy(filename, "servidor/");
          strcat(filename, request_tokens[1]);
          printf("Receiving %s\n", request_tokens[1]);

          int fd2 = open(filename, O_WRONLY | O_CREAT | O_TRUNC, S_IWUSR | S_IRUSR);
          if( fd2 < 0){
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
            read(connfd, entrada, BLOWFISH_BLOCK_SIZE);
            blowfish_decrypt(entrada, salida, &key);
            salida++;
            i += 8;
          }

          bytesRead = write(fd2, buf_file, filesize);
          close(fd2);
          free(buf_file);
          printf("File %s received. Size: %ld Bytes\n",request_tokens[1],filesize);
        }else
        {
          strcpy(response, "Badly formulated request.\nUsage: PUT <file name>\n");
          Write(connfd, response, strlen(response) + 1);
        }
      }
      else
      {
        strcpy(response, "Unknown command...\n");
        P(&mutex);
        Write(connfd, response, strlen(response) + 1);
        V(&mutex);
      }
      /*Libera request_tokens y su contenido
      para evitar fugas de memoria. */
      for(int i = 0; request_tokens[i]; i++)
      {
        Free(request_tokens[i]);
      }
      Free(request_tokens);
    }
    else
    {
      strcpy(buf, "Empty command...\n");
      P(&mutex);
      Write(connfd, buf, strlen(buf) + 1);
      V(&mutex);
    }
    memset(buf, 0, MAXLINE);
    memset(response,0,MAXLINE);
  }
}

void *thread(void *vargp)
{
  int connfd = *((int *)vargp);
  pthread_detach(pthread_self());
  Free(vargp);
  atender_cliente(connfd);
  Close(connfd);
  return NULL;
}

void daemonize()
{
  int					i, fd0, fd1, fd2;
  pid_t				pid;
  struct rlimit		rl;
  struct sigaction	sa;

  /*
  * Clear file creation mask.
  */
  umask(0);

  /*
  * Get maximum number of file descriptors.
  */
  if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
  fprintf(stderr,"can't get file limit");


  /*
  * Become a session leader to lose controlling TTY.
  */
  if ((pid = fork()) < 0)
  fprintf(stderr,"can't fork");
  else if (pid != 0) /* parent */
  exit(0);
  setsid();

  /*
  * Ensure future opens won't allocate controlling TTYs.
  */
  sa.sa_handler = SIG_IGN;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  if (sigaction(SIGHUP, &sa, NULL) < 0)
  fprintf(stderr,"can't get ignore SIGHUP");
  if ((pid = fork()) < 0)
  fprintf(stderr,"can't fork");
  else if (pid != 0) /* parent */
  exit(0);

  /*
  * Close all open file descriptors.
  */
  if (rl.rlim_max == RLIM_INFINITY)
  rl.rlim_max = 1024;
  for (i = 0; i < rl.rlim_max; i++)
  Close(i);

  /*
  * Attach file descriptors 0, 1, and 2 to /dev/null.
  */
  fd0 = open("/dev/null", O_RDWR);
  fd1 = dup(0);
  fd2 = dup(0);

  /*
  * Initialize the log file.
  */
  if (fd0 != 0 || fd1 != 1 || fd2 != 2) {
    syslog(LOG_ERR, "unexpected file descriptors %d %d %d",
    fd0, fd1, fd2);
    exit(1);
  }
}

void recoger_hijos(int signal){
  while(waitpid(-1, 0, WNOHANG) >0)
  ;

  return;
}

void vli_print(uint8_t *vli, unsigned int size) {
  for(unsigned i=0; i<size; ++i) {
    printf("%02X ", (unsigned)vli[i]);
  }
}

//Imprime cadena de bytes en formato hexadecimal
void print_hex(const unsigned char* data, size_t size)
{
  int i;
  for(i = 0; i < size; ++i)
  printf("%02x",(unsigned char) data[i]);
}

/**
* Función que crea request_tokens separando una cadena de caracteres en
* "tokens" delimitados por la cadena de caracteres delim.
*
* @param linea Cadena de caracteres a separar en tokens.
* @param delim Cadena de caracteres a usar como delimitador.
*
* @return Puntero a request_tokens en el heap, es necesario liberar esto después de uso.
*	Retorna NULL si linea está vacía.
*/
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
