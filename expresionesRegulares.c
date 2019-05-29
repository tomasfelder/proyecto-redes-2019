/* 
	Archivo       : ejemplo7.c
	Descripción   : Programa que permite cambiar sólo los permisos de usuario de un archivo determinado en Linux.

	Actualización : 20101012 Leonardo de - Matteis
	Autor         : ?
	Materia       : Sistemas Operativos

	Modo de uso	  : cambiar_permisos_usuario <archivo> <permisos>
	Compilación   : gcc -o cambiar_permisos_usuario ejemplo7.c
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

int match(const char *string, char *pattern);
int pantallaHelp(int argc, char *argv[]);
void get_query_type(int argc, char *argv[]);
void get_query(int argc, char *argv[]);
void get_r_or_t(int argc, char *argv[]);
void get_server_port(int argc, char *argv[]);
void get_dns_servers();
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
											"			-mx		Retorna el IP asociado a la consulta.\n"
											"			-loc	Retorna el IP asociado a la consulta.\n"
											"			(Por defecto: -a)\n"
											"		q-opt	uno de los siguientes:\n"
											"			-r		Consulta recursiva\n"
											"			-t		Consulta iterativa.\n"
											"			(Por defecto: -r)\n"
											"		-h	Pantalla de ayuda.\n";
											printf(mystr);
}


