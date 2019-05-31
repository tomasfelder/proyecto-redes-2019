#include <netdb.h>

#define PORT 53 /*%< Puerto se servidor DNS por defecto */

extern const char* ERRORS[]; /*%< Nombre de errores que devuelve mensaje DNS */

char* originalQueryName; /*%< Nombre de consulta original */

int globalQueryType; /*% Tipo de consulta original */

int recursive; /*%< Flag que indica consulta recursiva en 1 y no recursiva en 0 */

char* server; /*%< Servidor al que se le esta haciendo la consulta en direccion IPv4 */

int port; /*%< Puerto de servidor DNS */

unsigned char message[512]; /*%< Buffer del mensaje DNS */

unsigned char* qname; /*%< Nombre del dominio de consulta DNS */

int status; /*%< Status de respueta del mensaje DNS */

unsigned char* response; /*%< Puntero que reocrre el buffer del mensaje de respuesta DNS */

long micros; /*%< Microsegundos que tarda el mensaje DNS */

int sizeOfAnswer; /*%< Tamano de la respuesta de mensaje DNS */

int printIP; /*%< Flag para saber si imprimir los IP de una consulta */

int root; /*%< Flag para saber si se esta haciendo una consulta a los servidores raiz en metodo iterativo */

/*
 * ---------------------------------------------------------------------------------------------------------
 * ---------------------------------- Estructuras para mensajes DNS. ---------------------------------------
 * ---------------------------------------------------------------------------------------------------------
 */
struct DNS_HEADER
{
    unsigned short id; /*%< query identification number */
 
	unsigned	rd :1;		/*%< recursion desired */
	unsigned	tc :1;		/*%< truncated message */
	unsigned	aa :1;		/*%< authoritive answer */
	unsigned	opcode :4;	/*%< purpose of message */
	unsigned	qr :1;		/*%< response flag */
 
	unsigned	rcode :4;	/*%< response code */
	unsigned	cd: 1;		/*%< checking disabled by resolver */
	unsigned	ad: 1;		/*%< authentic data from named */
	unsigned	unused :1;	/*%< unused bits (MBZ as of 4.9.3a3) */
	unsigned	ra :1;		/*%< recursion available */
 
	unsigned	qdcount :16;	/*%< number of question entries */
	unsigned	ancount :16;	/*%< number of answer entries */
	unsigned	nscount :16;	/*%< number of authority entries */
	unsigned	arcount :16;	/*%< number of resource entries */
};

struct QUESTION {
	unsigned short qtype;
	unsigned short qclass;
};

struct RESOURCE_RECORD_METADATA
{
    unsigned short type;
    unsigned short _class;
    int ttl;
    unsigned short data_len;
};

struct RESOURCE_RECORD
{
    unsigned char *name;
    struct RESOURCE_RECORD_METADATA *resource;
    unsigned char *rdata;
};

struct SOA
{
	unsigned int serial;
	int refresh;
	int retry;
	int expire;
	unsigned int minimum;
};

/*
 * ---------------------------------------------------------------------------------------------------------
 * ------------------------------ Funciones y procedimientos -----------------------------------------------
 * ---------------------------------------------------------------------------------------------------------
 */

/*
 * Procedimiento:  initializeDnsQuery 
 * --------------------
 * Inicializa la Consulta DNS. Depende de si ha solicitado una consulta recursiva comun
 * o una consulta iterativa mediante el parametro -t
 *
 */
extern void initializeDnsQuery();

/*
 * Funcion:  resolveQuery 
 * --------------------
 * Funcion de alto nivel que resuelve una consulta DNS usando los metodos para preparar
 * el Header del mensaje DNS, mandarlo al socket y recibir la respuesta, y luego mostrar
 * el resultado por pantalla.
 *  
 * Datos de entrada 
 * --------------------
 * queryName: Nombre del dominio a realizar la consulta.
 * queryType: Tipo de consulta DNS a realizarse
 *
 * Datos de salida 
 * --------------------
 *  returns: Si se esta ejecutando una consulta iterativa y encontro la respuesta final
 * 			 devuelve 1. En cualquier otro caso devuelve 0. 
 */
int resolveQuery(char* queryName, unsigned short queryType);

/*
 * Procedimiento:  resolveIterative 
 * --------------------
 * Procedimiento de alto nivel que resuelve una consulta DNS de tipo iterativa y mostrando
 * la ejecucion por salida estandar. En primera oportunidad obtiene los servidores raiz
 * a los que se ira haciendo la consulta para ir obteniendo los autoritativos correspondientes.
 * Se entra en un ciclo que termina al momento de encontrar una respuesta final con answer == 1.
 *
 * Datos de entrada 
 * --------------------
 * queryName: Nombre del dominio a realizar la consulta.
 * queryType: Tipo de consulta DNS a realizarse
 *
 */
void resolveIterative(char* queryName, unsigned short queryType);

/*
 * Funcion:  prepareDnsHeader 
 * --------------------
 * Funcion que prepara los parametros necesarios para inicializar una consulta DNS.
 * Los parametros variables seran el tipo de consulta, el nombre de dominio a buscar,
 * el servidor y el puerto.
 *  
 * Datos de entrada 
 * --------------------
 * queryName: Nombre del dominio a realizar la consulta.
 * queryType: Tipo de consulta DNS a realizarse
 *
 * Datos de salida 
 * --------------------
 *  returns: Devuelve el tamaño del header 
 */
int prepareDnsHeader(char* queryName, unsigned short queryType);

/*
 * Procedimiento:  changeDomainFormat 
 * --------------------
 * Procedimiento que se encarga de cambiar el nombre del dominio a consultar
 * para que este en el formato esperado por el servidor DNS. El nombre de dominio
 * se representa como una secuencia de etiquetas. Esta se representa por :
 * - Tamaño de etiqueta: Un byte que describe el largo de la etiqueta (justo antes del .) En rango [0..63].
 * - Los bytes en char de la etiqueta. Tamaño maximo de 63 bytes
 * Ejemplo de dominio y formato:
 * 	regularDomain: 'cs.uns.edu.ar'
 * 	dnsDomain: '2cs3uns3edu2ar0'
 *
 * Datos de entrada 
 * --------------------
 * regularDomain: Nombre del dominio a realizar la consulta.
 * dnsDomain: Puntero a char donde se encontrara el nombre en el formato correcto.
 * 
 * Datos de salida 
 * --------------------
 * dnsDomain: Puntero a char donde se encuentra el nombre en el formato correcto. 
 */
void changeDomainFormat(char * regularDomain, unsigned char * dnsDomain);

/*
 * Procedimiento:  sendAndReceiveFromSocket 
 * --------------------
 * Procedimiento que se encarga de enviar el mensaje DNS haciendo uso de la libreria socket.
 * Envia el mensaje correspondiente que se encuentra en un buffer y espera por su resolucion
 * para asignarlo al mismo buffer, reemplazando la informacion anterior. Si la consulta no se
 * resuelve en un tiempo especificado como timeout, se abortara la ejecucion mostrando un error. 
 *
 * Datos de entrada 
 * --------------------
 * sizeOfMessage: Tamaño del header DNS
 */
void sendAndReceiveFromSocket(int sizeOfHeader);

/*
 * Funcion:  parseResponse 
 * --------------------
 * Funcion que se encargara de obtener desde el mensaje de respuesta DNS si es que se
 * produjo algun error y la cantidad de answers, additionals y authorities correspondientes
 * a la consulta realizada. Tambien especifica los arreglos con la cantidad de respuestas de cada tipo
 * y por ultimo llamara al metodo correspondiente dependiendo de si se trata de una consulta recursiva 
 * o una iterativa y dividiendo en el caso de que se esten obteniendo los servidores raiz o no.
 *  
 * Datos de entrada 
 * --------------------
 * sizeOfHeader: Tamaño del Header de respuesta DNS
 *
 * Datos de salida 
 * --------------------
 *  returns: Si se esta ejecutando una consulta iterativa y encontro la respuesta final
 * 			 devuelve 1. En cualquier otro caso devuelve 0. 
 */
int parseResponse(int sizeOfHeader);

/*
 * Funcion:  parseRootServersAnswers 
 * --------------------
 * Funcion que se encargara de recorrer el buffer con la respuesta DNS para obtener la
 * informacion de respuesta de la consulta por los servidores raiz. Se lee y se realiza lo necesario
 * con cada uno de los 3 tipos distintos de registros (answers, additionals y authorities) dependiendo
 * de la cantidad  de los mismos. Se anula la impresion de direcciones IP para emular la salida del
 * dig +trace. Si obtiene additionals asume que alli se encontraran las direcciones ip de los servidores
 * raiz para actualizar el proximo servidor a buscar. Si la consulta no devuelve addtionals obtendra el IP
 * del servidor raiz de manera recursiva directa a traves del namserver del mismo. Desactiva el flag root para
 * avisar que ya se cumplio esa consulta.
 *  
 * Datos de entrada 
 * --------------------
 * answers: Arreglo de RESORUCE_RECORDS para guardar answers
 * additionals: Arreglo de RESORUCE_RECORDS para guardar additionals
 * authorities: Arreglo de RESORUCE_RECORDS para guardar authorities
 * answersCount: Cantidad de answers en el mensaje
 * additionalRecordsCount: Cantidad de additionals en el mensaje
 * authoritativeCount: Cantidad de authoritatives en el mensaje
 *
 * Datos de salida 
 * --------------------
 *  returns: Si se esta ejecutando una consulta iterativa y encontro la respuesta final
 * 			 devuelve 1. En cualquier otro caso devuelve 0. 
 */
int parseRootServersAnswers(struct RESOURCE_RECORD answers[],struct RESOURCE_RECORD additionals[],struct RESOURCE_RECORD authorities[],int answersCount, int additionalRecordsCount, int authoritativeCount);

/*
 * Funcion:  parseRecursiveMethod 
 * --------------------
 * Funcion que se encargara de recorrer el buffer con la respuesta DNS para obtener la
 * informacion de respuesta de la consulta. Primero se muestra por salida estandar el header
 * de respuesta emulando el comando dig. Se indica si hubo algun error, con el codigo de status
 * en el heeader. Luego se lee y se uestra lo obtenido de cada uno de los 3 tipos distintos de
 * registros (answers,  additionals y authorities) dependiendo de la cantidad de los mismos.
 * Para finalizar se escribe la informacion del mensaje igual al comando dig.
 * 
 * Datos de entrada 
 * --------------------
 * answers: Arreglo de RESORUCE_RECORDS para guardar answers
 * additionals: Arreglo de RESORUCE_RECORDS para guardar additionals
 * authorities: Arreglo de RESORUCE_RECORDS para guardar authorities
 * answersCount: Cantidad de answers en el mensaje
 * additionalRecordsCount: Cantidad de additionals en el mensaje
 * authoritativeCount: Cantidad de authoritatives en el mensaje
 * questionsCount: Cantidad de questions en el mensaje
 *
 * Datos de salida 
 * --------------------
 *  returns: Devuelve 0 siempre al no necesitarte un flag de terminacion en la consulta recursiva. 
 */
int parseRecursiveMethod(struct RESOURCE_RECORD answers[],struct RESOURCE_RECORD additionals[],struct RESOURCE_RECORD authorities[],int answersCount, int additionalRecordsCount, int authoritativeCount, int questionsCount);

/*
 * Funcion:  parseIterativeMethod 
 * --------------------
 * Funcion que se encargara de recorrer el buffer con la respuesta DNS para obtener la
 * informacion de la consulta realizada. Se lee y se realiza lo necesario
 * con cada uno de los 3 tipos distintos de registros (answers, additionals y authorities) dependiendo
 * de la cantidad  de los mismos. Se anula la impresion de direcciones IP para emular la salida del
 * dig +trace. Si obtiene additionals asume que alli se encontraran las direcciones ip de los servidores
 * para actualizar el proximo servidor a buscar. Si la consulta no devuelve addtionals obtendra el IP
 * del servidor de manera recursiva directa a traves del namserver del mismo. El metodo devuelve 1 cuando
 * obtiene answers o si obtuvo un authority de tipo SOA que indica que no se obtuvo la respuesta buscada.
 *  
 * Datos de entrada 
 * --------------------
 * answers: Arreglo de RESORUCE_RECORDS para guardar answers
 * additionals: Arreglo de RESORUCE_RECORDS para guardar additionals
 * authorities: Arreglo de RESORUCE_RECORDS para guardar authorities
 * answersCount: Cantidad de answers en el mensaje
 * additionalRecordsCount: Cantidad de additionals en el mensaje
 * authoritativeCount: Cantidad de authoritatives en el mensaje
 *
 * Datos de salida 
 * --------------------
 *  returns: Si se  encontro la respuesta final devuelve 1. En cualquier otro caso devuelve 0. 
 */
int parseIterativeMethod(struct RESOURCE_RECORD answers[],struct RESOURCE_RECORD additionals[],struct RESOURCE_RECORD authorities[],int answersCount, int additionalRecordsCount, int authoritativeCount);

/*
 * Procedimiento:  getIPFromNameServer 
 * --------------------
 * Procedimiento que se encarga de obtener el IP de un dominio usando la funcion
 * gethostbyname para luego actualizar el server a consultar con ese IP obtenido.
 *
 * Datos de entrada 
 * --------------------
 * hostname: Nombre del servidor a consultar.
 */
void getIPFromNameServer(char * hostname);

/*
 * Funcion:  updateServer 
 * --------------------
 * Funcion que se encargara de recorrer los records pasados por parametro para
 * obtener el IPv4 del proximo server a consultar en la consulta iterativa. Realiza
 * un ciclo que termina de manera brusca al encontrar la primera direccion IPv4.
 *  
 * Datos de entrada 
 * --------------------
 * resourceRecords: Arreglo de RESORUCE_RECORDS donde se encuentran las direccions IP.
 * resourceRecordsCount: Cantidad de RESORUCE_RECORDS.
 *
 * Datos de salida 
 * --------------------
 *  returns: Devuelve 0 solo para cortar la ejecucion del procedimiento.
 */
int updateServer(struct RESOURCE_RECORD resourceRecords[],int resourceRecordsCount);

/*
 * Procedimiento:  readResourceRecords 
 * --------------------
 * Procedimiento que recorre el buffer de respuesta para ir actualizando los RESOURCE_RECORDS
 * con la informacion obtenida. Recorre con un ciclo for la cantidad que hay. Obtiene del buffer
 * de respuesta el nombre, el tipo de respuesta para saber que se encuentra en el RDATA y el 
 * RDATA correspondiente. Para cada tipo de respuesta llamara al procedimiento que se encargue de 
 * parsear de la manera adecuada. Si obtiene un tipo no reconocido por el programa, lo saltea.
 *  
 * Datos de entrada 
 * --------------------
 * resourceRecords: Arreglo de RESORUCE_RECORDS.
 * resourceRecordsCount: Cantidad de RESORUCE_RECORDS.
 *
 * Datos de salida 
 * --------------------
 *  resourceRecords: Se encontraran con la informacion actualizada.
 */
void readResourceRecords(struct RESOURCE_RECORD resourceRecords[],int resourceRecordsCount);

/*
 * Procedimiento:  readAnswerName 
 * --------------------
 * Procedimiento que recorre el buffer de respuesta para obtener un nombre de dominio. El
 * formato obtenido es el mismo que el especificado en changeDomainFormat con las etiquetas
 * y el numero de etiquetas. Este procedimiento obtendra los distintos bytes y guardandolos,
 * pero diferenciando el caso donde se encuentre una direccion de offset. Esto se debe a que 
 * el mensaje obtenido puede tener nombres repetidos que llegaran una sola vez en una direccion
 * y se podran recorrer con el offset propiamente dicho. Esto esta especificado en el [RFC 1035].
 * El puntero de 16 bits se especifica con los primeros dos bits en 1, por eso se pregunta por 192,
 * 1100 0000 en binario. Para obtener la direccion donde se encuentra el nombre a seguir escribiendo
 * se calcula el offset indicando que el puntero actual es el inicio del buffer + el offset calculado.
 * El procedimiento termina cuando se leyo un 0, indicando fin de etiqueta y luego se convierte en
 * el formato de direcciones con . entendido por el usuario.
 *  
 * Datos de entrada 
 * --------------------
 * response: Puntero actual de respuesta.
 * message: Puntero al inicio del buffer de respuesta.
 * nextPart: Puntero a entero para actualizar buffer de respuesta.
 * domainName: Puntero a char donde se guardara el nombre de dominio.
 *
 * Datos de salida 
 * --------------------
 * nextPart: Puntero a entero con la cantidad de bytes movidos para actualizar buffer de respuesta.
 * domainName: Puntero a char donde se encuenrta el nombre de dominio.
 */
void readAnswerName(unsigned char* response,unsigned char* message, int* nextPart,unsigned char * domainName);

/*
 * Procedimiento:  readIPv4Address 
 * --------------------
 * Procedimiento que recorre el buffer de respuesta para obtener una direccion IPv4 del registro
 * RDATA segun especificacion [RFC 1035].
 *  
 * Datos de entrada 
 * --------------------
 * resourceDataLength: Largo del registro.
 * rdata: Puntero a char.
 *
 * Datos de salida 
 * --------------------
 * rdata: Puntero a char con la informacion guardada.
 */
void readIPv4Address(int resourceDataLength,unsigned char* rdata);

/*
 * Procedimiento:  printIPv4Address 
 * --------------------
 * Procedimiento que recorre el RESOURCE_RECORD para imprimir una direccion IPv4 del registro
 * RDATA segun especificacion [RFC 1035].
 *  
 * Datos de entrada 
 * --------------------
 * resoruce: Puntero a registro con la informacion a imprimir.
 */
void printIPv4Address(struct RESOURCE_RECORD * resoruce);

/*
 * Procedimiento:  readIPv6Address 
 * --------------------
 * Procedimiento que recorre el buffer de respuesta para obtener una direccion IPv6 del registro
 * RDATA. (ACTUALMENTE SOLO ACTUALIZA EL BUFFER, NO IMPLEMENTADA LA LECTURA IPv6)
 *  
 * Datos de entrada 
 * --------------------
 * resourceDataLength: Largo del registro.
 * rdata: Puntero a char.
 *
 */
void readIPv6Address(int resourceDataLength,unsigned char* rdata);

/*
 * Procedimiento:  readSOAFormat 
 * --------------------
 * Procedimiento que recorre el buffer de respuesta para obtener un SOA del registro
 * RDATA segun especificacion [RFC 1035]. Solo imprime la informacion sin guardar en variable.
 *  
 * Datos de entrada 
 * --------------------
 * resourceDataLength: Largo del registro.
 * rdata: Puntero a char.
 *
 */
void readSOAFormat(int resourceDataLength,unsigned char* rdata);

/*
 * Procedimiento:  readMXFormat 
 * --------------------
 * Procedimiento que recorre el buffer de respuesta para obtener una respuesta MX del registro
 * RDATA segun especificacion [RFC 1035].
 *  
 * Datos de entrada 
 * --------------------
 * rdata: Puntero a char.
 *
 * Datos de salida 
 * --------------------
 * rdata: Puntero a char con la informacion guardada.
 */
void readMXFormat(unsigned char* rdata);

/*
 * Procedimiento:  printMXFormat 
 * --------------------
 * Procedimiento que recorre el RESOURCE_RECORD para imprimir una respuesta MX del registro
 * RDATA segun especificacion [RFC 1035].
 *  
 * Datos de entrada 
 * --------------------
 * resoruce: Puntero a registro con la informacion a imprimir.
 */
void printMXFormat(struct RESOURCE_RECORD * resoruce);

/*
 * Procedimiento:  readAndPrintNSFormat 
 * --------------------
 * Procedimiento que recorre el buffer de respuesta para obtener una respuesta NS del registro
 * RDATA e imprimirla por pantalla segun especificacion [RFC 1035].
 *  
 * Datos de entrada 
 * --------------------
 * resoruce: Puntero a registro RESOURCE_RECORD.
 *
 * Datos de salida 
 * --------------------
 * resoruce: Puntero a registro RESOURCE_RECORD.
 */
void readAndPrintNSFormat(struct RESOURCE_RECORD * resoruce);

/*
 * Procedimiento:  readAndPrintCNAMEFormat 
 * --------------------
 * Procedimiento que recorre el buffer de respuesta para obtener una respuesta CNAME del registro
 * RDATA e imprimirla por pantalla segun especificacion [RFC 1035].
 *  
 * Datos de entrada 
 * --------------------
 * resoruce: Puntero a registro RESOURCE_RECORD.
 *
 * Datos de salida 
 * --------------------
 * resoruce: Puntero a registro RESOURCE_RECORD.
 */
void readAndPrintCNAMEFormat(struct RESOURCE_RECORD * resoruce);

/*
 * Procedimiento:  printLocalTime 
 * --------------------
 * Procedimiento que imprime la hora local del equipo.
 */
void printLocalTime();

/*
 * Funcion:  convert 
 * --------------------
 * Funcion que convierte un entero no signado de 8 bits a caracter
 *
 * Datos de entrada 
 * --------------------
 * a: puntero a un entero no signado de 8 bits
 *
 * Datos de salida 
 * --------------------
 * returns: puntero a char
 */
char* convert(uint8_t *a);

/*
 * Procedimiento:  readLOCFormat 
 * --------------------
 * Procedimiento que recorre el buffer de respuesta para obtener la informacion de locacion del registro RDATA segun especificacion [RFC 1876].
 * Luego la parsea e imprime por la salida estandar. 
 * Algoritmo basado en la funcion loc_ntoa implementada en el RFC 1876.
 *
 * Datos de entrada 
 * --------------------
 * binary: Puntero a un char no signado. Apunta al primer elemento del registro RDATA.
 * resource: Puntero a registro RESOURCE_RECORD.
 */
void readLOCFormat(const unsigned char *binary,struct RESOURCE_RECORD * resource);

/*
 * Funcion:  precsize_ntoa 
 * --------------------
 * Funcion que convierte los primeros 4 bits y los ultimos 4 bits de prec en dos numeros del 0 al 9. Los ultimos 4 bits representan la potencia de 10 a la que se debe
 * multiplicar el primer numero. Retorna el resultado en formato de string. Ej: [01010100] -> [0101] = 5 , [0100] = 4 -> 5*(10^4). 
 * Funcion implementada del RFC 1876.
 * 
 * Datos de entrada 
 * --------------------
 * prec: entero no signado de 8 bits.
 *
 * Datos de salida 
 * --------------------
 * returns: puntero a char con el resultado.
 */
const char* precsize_ntoa(u_int8_t prec);


