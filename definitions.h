#ifndef HEADERS
#define HEADERS

#define PORT 53 
#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h>
#include <sys/time.h>
#include <time.h>
#include <stdint.h>
#include <arpa/nameser.h>
#include <netdb.h>

extern const char* ERRORS[];

char* originalQueryName;
int globalQueryType;
int recursive;
char* server;
int port;
unsigned char message[512];
unsigned char* qname;
int status;
unsigned char* response;
long micros;
int sizeOfAnswer,printIP,root;

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
 * 
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
int parseRootServersAnswers(struct RESOURCE_RECORD answers[],struct RESOURCE_RECORD additionals[],struct RESOURCE_RECORD authorities[],int answersCount, int additionalRecordsCount, int authoritativeCount, int questionsCount);

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


void getIPFromNameServer(char * hostname);
int updateServer(struct RESOURCE_RECORD resourceRecords[],int resourceRecordsCount);
void readResourceRecords(struct RESOURCE_RECORD resourceRecords[],int resourceRecordsCount);
void readAnswerName(unsigned char* response,unsigned char* message, int* nextPart,unsigned char * domainName);
void readIPv4Address(int resourceDataLength,unsigned char* rdata);
void printIPv4Address(struct RESOURCE_RECORD * answers);
void readIPv6Address(int resourceDataLength,unsigned char* rdata);
void readSOAFormat(int resourceDataLength,unsigned char* rdata);
void readMXFormat(unsigned char* rdata);
void printMXFormat(struct RESOURCE_RECORD * answers);
void readNSFormat(struct RESOURCE_RECORD * answers);
void readCNAMEFormat(struct RESOURCE_RECORD * answers);
void printLocalTime();
char* convert(uint8_t *a);
void readLOCFormat(const unsigned char *binary,struct RESOURCE_RECORD * answers);
const char *precsize_ntoa(u_int8_t prec);

#endif
