# proyecto-final-fileserver-cunalata-vallejo

## Instrucciones de compilación
Para compilar el programa:
```
$ make
```
Para compilar facilitando la depuración con gdb (hace *clean*, recompila y limpia la terminal mediante *clear*):
```
$ make debug
```
Para compilar habilitando la herramienta *AddressSanitizer*, facilita la depuración en tiempo de ejecución.
```
$ make sanitize
```

### Características
Muestra un mensaje de ayuda con los posibles argumentos de *make*:
```
$ make help
```
Para limpiar archivos autogenerados:
```
$ make clean
```

Para mostrar contenido del proyecto en formato largo:
```
$ make dir
```

## Estructura de directorios
* Cabeceras: *include*
* Archivos obj temporales: *obj*
* Código fuente: *src*
* Librerías : *lib*
* Carpeta archivos cliente: *cliente*
* Carpeta archivos servidor: *servidor*

Estas últimas dos carpetas contienen archivos que pueden ser utilizados para probar las funcionalidades. *cliente* contiene además los archivos descargados del servidor de prueba 200.10.150.122 @ 8080.

## Funcionamiento del proyecto
* Los ejecutables se encuentran en la carpeta raíz del repositorio, de modo que será posible correrlos mediante `./file_server` y `./file_client`. Esto implica, por supuesto, que _no_ estarán dentro de un directorio `bin`.

### file_server

```
./file_server [-d] <port>
./file_server -h
```

### file_client
```
./file_client <ip> <port>
./file_client -h
```

### Solicitudes cliente
* `GET <nombre archivo>` (archivo se guarda en la carpeta *cliente*)
* `PUT <nombre archivo>` (archivo se guarda en la carpeta *servidor*)
  * **Implementado de tal manera que no es requerido escribir manualmente el tamaño del archivo**. Tras comprobar su existencia, el cliente obtiene su tamaño y arma un string del estilo `PUT <nombre archivo> <tamaño archivo>`
* `BYE` (cierra la conexión)
* `LIST` (muestra al cliente un listado de archivos del servidor que están disponibles para descargar)


## Distribución de trabajo
Amplía descripciones del trabajo y commits correspondientes según autor.

### Carlos Cunalata
* Funcionalidad daemon servidor
* Implementación comando LIST
* Bugfixes y refactorización
* Limpieza Makefile
* Subida/descarga de archivos

### Juan Diego Vallejo
* Setup inicial del repositorio (gitignore, README, directorios, versiones iniciales de los .c, Makefile)
* Creación/compilación librería *libcrypto.a* y enlazado con ejecutables
* Comportamiento básico cliente/servidor (basado en echo server) + mensajes de ayuda (todo esto con `getopt`)
* Funcionalidad daemon servidor
* Procesamiento texto solicitudes BYE, LIST, PUT, GET
* Funcionalidad multi-hilo
* Intercambio claves Diffie-Hellman, generación secreto compartido
* Procedimiento SHA-256 y generación clave Blowfish
* Encriptado/desencriptado en subida/descarga de archivos
* Documentación, correciones finales

## Metodología
* Se ha acordado dividir el proyecto en fases debido a su complejidad, las cuales se mostrarán en una checklist para ir tachando tras completar cada ítem.
* Cada fase se trabajará en una rama, la cual se hará *merge* con master tras comprobar su correcto funcionamiento.

### Fase 1 (rama master)
- [x] Setup inicial repositorio
- [x] Makefile
- [x] *libcrypto.a* + enlazado estático
  - [x] Consecución archivos de código fuente y cabeceras relevantes
  - [x] Modificaciones al Makefile
- [x] Getopt + mensajes ayuda
- [x] Comportamiento básico cliente/servidor (basado en echo server)

> Terminada: 07/01/2020

### Fase 2 (rama fase2)
- [x] Funcionalidad daemon del servidor
- [x ] Procesamiento texto solicitudes cliente // Mensajes (READY, etc.)
  - [x] GET *filename*
  - [x] PUT *filename*
  - [x] BYE
- [x] Subida/descarga archivos

> Terminada (a excepción subida/descarga): 21/01/2020
> Subida/descarga terminada el 29/01/2020


### Fase 3 (rama fase3)
- [x] Intercambio inicial claves pública Diffie-Hellman
- [x] Generación secreto compartido
- [x] Procedimiento SHA-256 para generación clave final Blowfish de 256 bits
  - [x] Verificar claves únicas por conexión

> Terminada: 26/01/2020  

### Fase 4 (rama fase4)
- [x] Encriptado Blowfish
  - [x] Asegurar envío en bloques encriptados de 8 bytes (rellenar con ceros de ser necesario)
  - [x] Asegurar que el servidor espere el mensaje "READY" para transmitir

### Fase 5
- [x] Descargar archivos del servidor de prueba ![](https://i.imgur.com/ZubcL30.png) (*hecho en fase4*)
- [x] Funcionalidad multi-hilo del servidor (*hecho en fase2*)

> Terminada: 29/01/2020

### Fase opcional (rama faseOP)

- [ ] Registro de eventos mediante la librería *syslog* (no fue implementado)
- [x] Comando **LIST** para el cliente, donde se solicita listado de archivos en el servidor (*hecho en fase2*)

> LIST implementado: 19/01/2020


## Notas adicionales
* **Makefile** emplea wildcards
* Archivos **.gitignore** fueron incluidos en *lib* y *obj* como dummies para que Git las detecte (si están vacías, puede dar problemas)
* En el **Makefile** no se usa la bandera `-static` para compilar los ejecutables, GCC asume enlazado estático al detectar *libcrypto.a*. Usar `-static` lanza advertencias ya que en el mismo comando también se requiere el uso de `-lpthread` para compilar *csapp.o*.
