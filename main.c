/* 
	Archivo       : main.c
	Descripción   : Puerta principal del programa dnsquery que realiza consulta a servidores DNS emulando al comando dig

	Actualización : 30.05.2019 | Felder, Tomas Ariel - Suburu, Ignacio
	Autor         : Felder, Tomas Ariel - Suburu, Ignacio
	Materia       : Redes de Computadoras - Ingenieria en Sistemas de Informacion - Universidad Nacional del Sur

	Modo de uso	  : ./ dnsquery consulta [@servidor[:puerto]] [q-type] [q-opt] [-h]
	Compilación   : gcc -o dnsquery preapreDnsQuery.c main.c manipulateRData.c parsingMethods.c 
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <regex.h>
#include <arpa/nameser.h>
#include "definitions.h"

char dns_servers[1][100];

char portNumber[10];

/*
 * Funcion:  match 
 * --------------------
 * Funcion que compara un string con la expresion regular recibida.
 *  
 * Datos de entrada 
 * --------------------
 * string: Puntero a char. Corresponde al string que se desea evaluar.
 * pattern: Puntero a char. Corresponde a la expresion regular a comparar.
 *
 * Datos de salida 
 * --------------------
 * returns: 1 en caso de que el string cumpla con la expresion regular ecpecificada en pattern, 0 en caso contrario.
 */
int match(const char *string, char *pattern);

/*
 * Funcion:  pantallaHelp 
 * --------------------
 * Funcion que recorre el arreglo de parametros recibido en busca de "-h".
 *  
 * Datos de entrada 
 * --------------------
 * argc: entero que representa la cantidad de elemenos en el arreglo.
 * argv: arreglo de strings donde se encuentran los parametros.
 *
 * Datos de salida 
 * --------------------
 * returns: 1 en caso de que el parametro sea encontrado, 0 en caso contrario.
 */
int pantallaHelp(int argc, char *argv[]);

/*
 * Procedimiento: get_query_type 
 * --------------------
 * Procedimiento que recorre el arreglo en busca de los parámetros: “-a”, “-mx” y “-loc”, 
 * excluyentes entre sí.  En caso de encontrar alguno de los parámetros setea la variable 
 * global del tipo de consulta con el número correspondiente. En caso de haber ambigüedades 
 * (2 o más parámetros diferentes) o ninguno de estos parámetros,  setea la variable 
 * global con el tipo de consulta por defecto (“-a” -> T_A -> 1).
 *
 * Datos de entrada 
 * --------------------
 * argc: entero que representa la cantidad de elemenos en el arreglo.
 * argv: arreglo de strings donde se encuentran los parametros.
 *
 */
void get_query_type(int argc, char *argv[]);

/*
 * Procedimiento: get_query 
 * --------------------
 * Procedimiento que recorre el arreglo en busca de la consulta brindada al comando. 
 * Si encuentra una secuencia de caracteres que no comiencen con ‘@’, ‘:’ ni ‘-’, 
 * entonces setea la variable global con la secuencia encontrada. 
 * En caso contrario deja la variable global vacía.
 *
 * Datos de entrada 
 * --------------------
 * argc: entero que representa la cantidad de elemenos en el arreglo.
 * argv: arreglo de strings donde se encuentran los parametros.
 *
 */
void get_query(int argc, char *argv[]);

/*
 * Procedimiento: get_r_or_t
 * --------------------
 * Procedimiento que Recorre el arreglo en busca de los parámetros “-r” y “-t”, 
 * correspondientes a consultas recursivas e iterativas respectivamente. 
 * En caso de encontrar “-t” setea la variable global en 1. 
 * En cualquier otro caso setea la variable global con el valor por defecto 0, 
 * correspondiente a una consulta recursiva.
 *
 * Datos de entrada 
 * --------------------
 * argc: entero que representa la cantidad de elemenos en el arreglo.
 * argv: arreglo de strings donde se encuentran los parametros.
 *
 */
void get_r_or_t(int argc, char *argv[]);

/*
 * Procedimiento: get_server_port
 * --------------------
 * Procedimiento que Recorre el arreglo en busca de una secuencia de caracteres 
 * comenzada con ‘@’. Si la encuentra, setea la variable global del servidor al 
 * que se le hará la consulta con la cadena de caracteres que le sigue hasta 
 * encontrar ‘:’ o ‘\0’. En el primer caso continuará la lectura del parámetro 
 * y setea la variable global correspondiente al puerto con los caracteres que siguen. 
 * En caso contrario el puerto obtendrá el valor por defecto 53. Si no se encuentran 
 * parámetros comenzados con ‘@’, se setea el servidor de consulta con el servidor DNS local.
 *
 * Datos de entrada 
 * --------------------
 * argc: entero que representa la cantidad de elemenos en el arreglo.
 * argv: arreglo de strings donde se encuentran los parametros.
 *
 */
void get_server_port(int argc, char *argv[]);

/*
 * Procedimiento: get_dns_servers
 * --------------------
 * Procedimiento que accede al archivo “/etc/resolv.conf” para obtener el servidor DNS local 
 * y lo setea a la variable global correspondiente al servidor que se le suministrará la consulta.
 *
 */
void get_dns_servers();

/*
 * Procedimiento: get_dns_servers
 * --------------------
 * Procedimiento que imprime por la salida estándar el texto de ayuda para la utilización del comando.
 *
 */
void printHelp();

int main(int argc, char * argv[])
{
	server = malloc(sizeof(15));
	if (argc == 1)
	{
		fprintf(stderr, "No ha ingresado ninguna consulta\n");
		exit(-1);
	}
	else
	{
		if (pantallaHelp(argc, argv))
			printHelp();
		else
		{
			
			if (argc >= 2)
			{
				get_query(argc,argv);
				if (strcmp(originalQueryName, "") == 0){
					fprintf(stderr,"No ha ingresado ninguna consulta\n");
					exit(-1);
				}
				get_query_type(argc,argv);
				get_server_port(argc,argv);			
				get_r_or_t(argc,argv);
				initializeDnsQuery();
			}
		}
	}

	exit(0);
}

int match(const char *string, char *pattern)
{
	regex_t ex;
	int reti;
	char msgbuf[100];

	/* Compilar la expresión regular */
	reti = regcomp(&ex, pattern, REG_EXTENDED);
	if( reti ) { fprintf(stderr, "No se pudo compilar la expressión regular.\n"); exit(1); }

	/* Ejecutar la expresión regular */
	reti = regexec(&ex, string, 0, NULL, 0);

	if (!reti)
		return (1); // match
	else if( reti == REG_NOMATCH )
		return (0); // no match
	else
	{
		regerror(reti, &ex, msgbuf, sizeof(msgbuf));
		fprintf(stderr, "Hubo un error al ejecutar regexec: %s\n", msgbuf);
		exit(1);
	}

	regfree(&ex);
	return 0;
}

void get_query_type(int argc, char *argv[])
{
	int i;
	globalQueryType = -1;
	for (i=1;i<argc;i++){
		
		if (match(argv[i], "^-a$")) 
			globalQueryType = T_A;
		else
			if ((match(argv[i], "^-mx$")) && (globalQueryType == -1))
				globalQueryType = T_MX;
				else if ((match(argv[i], "^-loc$")) && (globalQueryType == -1))
						globalQueryType = T_LOC;
		
	}
	if (globalQueryType == -1)
		globalQueryType = T_A;
}

int pantallaHelp(int argc,char *argv[])
{
	int i;
	for (i=1;i<argc;i++){
		
		if (match(argv[i], "^-h$"))
			return 1;
		}
	return 0;
}

void get_r_or_t(int argc, char *argv[])
{
	recursive = -1;
	int i;
	for (i=1;i<argc;i++){
		
		if (match(argv[i], "^-r$")) 
			recursive = 1;
		else
			if (match(argv[i], "^-t$") && recursive == -1)
				recursive = 0;
	}
	if (recursive == -1)
		recursive = 1;
}

void get_query(int argc, char *argv[])
{
	originalQueryName = "";
	int i;
	for (i=1;i<argc;i++){
		
		if (match(argv[i], "^[^@:-].*$")) 
			originalQueryName = argv[i];
	}
}
 void get_server_port(int argc, char *argv[])
 {
	
	int i;
	for (i=1;i<argc;i++){
		if (match(argv[i], "^@.+$")) {
			int j;
			int s = 0;			
			
			for (j=1; (argv[i][j] != '\0') && (argv[i][j] != ':') ;j++) {
				server[s]=argv[i][j];
				s++;
			}
			server[s] = '\0';
			struct in_addr addr;
		 
			if(!inet_aton(server, &addr)) {
				 getIPFromNameServer(server);
			}
			s = 0;
			
			if (argv[i][j] == ':'){
				j++;
				
				int x;
				for (x = j;(argv[i][x] != '\0'); x++){
					portNumber[s]=argv[i][x];
					s++;
				}
				portNumber[s] = '\0';
			}
				
		}
		
	}
	if (strcmp(server, "") == 0)
		get_dns_servers();
	if (strcmp(portNumber, "") == 0)
		 strcpy(portNumber , "53");
	port = atoi(portNumber);
 }
 
 void get_dns_servers()
{
    FILE *fp;
    char line[200] , *p;
    if((fp = fopen("/etc/resolv.conf" , "r")) == NULL)
    {
        printf("Error al abrir el archivo /etc/resolv.conf \n");
    }
     
    while(fgets(line , 200 , fp))
    {
        if(line[0] == '#')
        {
            continue;
        }
        if(strncmp(line , "nameserver" , 10) == 0)
        {
            p = strtok(line , " ");
            p = strtok(NULL , " ");
            //p contiene la ip DNS
        }
    }
    strcpy(server , p);
    int i = 0;
    while(server[i] != '\n')
		i++;
	server[i] = '\0';
}

void printHelp(){
	char* mystr =
											"\nUSO: dnsquery consulta [@servidor[:puerto]] [q-type] [q-opt] [-h]\n"
											"	Where:	consulta	Nombre de dominio simbolico\n"
											"		servidor	Servidor DNS al cual se suministrara la consulta.(Por defecto: DNS local)\n"
											"		puerto		Puerto del servidor DNS al cual se suministrara la consulta.(Por defecto: 53)\n"
											"		q-type	uno de los siguientes:\n"
											"			-a		Retorna el IP asociado a la consulta.\n"
											"			-mx		Retorna servidor a cargo de la recepción de correo electrónico del dominio indicado en la consulta.\n"
											"			-loc	Retorna información relativa a la ubicación geográfica del dominio indicado en la consulta.\n"
											"			(Por defecto: -a)\n"
											"		q-opt	uno de los siguientes:\n"
											"			-r		Consulta recursiva\n"
											"			-t		Consulta iterativa.\n"
											"			(Por defecto: -r)\n"
											"		-h	Pantalla de ayuda.\n";
											printf(mystr);
}


