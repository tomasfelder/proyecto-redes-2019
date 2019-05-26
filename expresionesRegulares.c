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
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <regex.h>

extern  int errno;


char *permisos[] = {"...", "..x", ".w.", ".wx", "r..", "r.x", "rw.", "rwx"};

char * query_type;
char * query;
char * i_or_t;
char server[15];
char port[10];


void validar_argumentos(int argc, char *argv[]);
int match(const char *string, char *pattern);
int pantallaHelp(int argc, char *argv[]);
void get_query_type(int argc, char *argv[]);
void get_query(int argc, char *argv[]);
void get_r_or_t(int argc, char *argv[]);
void get_server_port(int argc, char *argv[]);

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
				get_server_port(argc,argv);
				get_query_type(argc,argv);
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
	query_type = "";
	for (i=1;i<argc;i++){
		
		if (match(argv[i], "^-a$")) 
			query_type = "T_A";
		else
			if ((match(argv[i], "^-mx$")) && (strcmp(query_type, "") == 0))
				query_type = "T_MX";
				else if ((match(argv[i], "^-loc$")) && (strcmp(query_type, "") == 0))
						query_type = "T_LOC";
		
	}
	printf("\nQuery type: %s\n",query_type);
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
	i_or_t = "";
	int i;
	for (i=1;i<argc;i++){
		
		if (match(argv[i], "^-r$")) 
			i_or_t = "r";
		else
			if (match(argv[i], "^-t$") && strcmp(i_or_t, "") == 0)
				i_or_t = "t";
	}
	printf("\nI or T: %s\n",i_or_t);
}

void get_query(int argc, char *argv[])
{
	query = "";
	int i;
	for (i=1;i<argc;i++){
		
		if (match(argv[i], "^[^@].*[.].*$")) 
			query = argv[i];
	}
	printf("\nQuery: %s\n",query);
}
 void get_server_port(int argc, char *argv[])
 {
	//port = "";
	//server = "";
	int i;
	for (i=1;i<argc;i++){
		if (match(argv[i], "^@.+$")) {
			int j;
			int s = 0;
			
			
			for (j=1; (argv[i][j] != '\0') && (argv[i][j] != ':') ;j++) { //j<strlen(argv[i])
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
	printf("\nServer: %s\n",server);
	printf("\nPort: %s\n",port);
 }

