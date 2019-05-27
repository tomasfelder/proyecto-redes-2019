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
#include <sys/types.h>
#include <sys/stat.h>
#include <regex.h>
#include <arpa/nameser.h>

char dns_servers[1][100];

int query_type;
char * query;
int r_or_t;
char server[15];
char port[10];

int match(const char *string, char *pattern);
int pantallaHelp(int argc, char *argv[]);
void get_query_type(int argc, char *argv[]);
void get_query(int argc, char *argv[]);
void get_r_or_t(int argc, char *argv[]);
void get_server_port(int argc, char *argv[]);
void get_dns_servers();

int main(int argc, char * argv[])
{

	if (argc == 1)
	{
		fprintf(stderr, "Falta la consulta\n");
		exit(-1);
	}
	else
	{
		if (pantallaHelp(argc, argv))
			printf("\nayuda\n");
		else
		{
			
			if (argc >= 2)
			{
				get_query(argc,argv);
				if (strcmp(query, "") == 0){
					fprintf(stderr,"No ha ingresado ninguna consulta\n");
					exit(-1);
				}
				get_query_type(argc,argv);
				get_server_port(argc,argv);			
				get_r_or_t(argc,argv);
				
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
	query_type = -1;
	for (i=1;i<argc;i++){
		
		if (match(argv[i], "^-a$")) 
			query_type = T_A;
		else
			if ((match(argv[i], "^-mx$")) && (query_type == -1))
				query_type = T_MX;
				else if ((match(argv[i], "^-loc$")) && (query_type == -1))
						query_type = T_LOC;
		
	}
	if (query_type == -1)
		query_type = T_A;
	printf("\nQuery type: %i\n",query_type);
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
	r_or_t = -1;
	int i;
	for (i=1;i<argc;i++){
		
		if (match(argv[i], "^-r$")) 
			r_or_t = 0;
		else
			if (match(argv[i], "^-t$") && r_or_t == -1)
				r_or_t = 1;
	}
	if (r_or_t == -1)
		r_or_t = 0;
	printf("\nr or t: %i\n",r_or_t);
}

void get_query(int argc, char *argv[])
{
	query = "";
	int i;
	for (i=1;i<argc;i++){
		
		if (match(argv[i], "^[^@^-].*$")) 
			query = argv[i];
	}
	printf("\nQuery: %s\n",query);
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
	
			s = 0;
			
			if (argv[i][j] == ':'){
				j++;
				
				int x;
				for (x = j;(argv[i][x] != '\0'); x++){
					port[s]=argv[i][x];
					s++;
				}
			}
				
		}
		
	}
	if (strcmp(server, "") == 0)
		get_dns_servers();
	printf("\nServer: %s\n",server);
	printf("\nPort: %s\n",port);
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
    
}


