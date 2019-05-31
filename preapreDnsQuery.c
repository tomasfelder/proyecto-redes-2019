/* 
	Archivo       : dnsquery.c
	Descripción   : Implementacion de metodos para realizar consulta de dominios (Emulacion comando dig)

	Actualización : 30.05.2019 | Felder, Tomas Ariel - Suburu, Ignacio
	Autor         : Felder, Tomas Ariel - Suburu, Ignacio
	Materia       : Redes de Computadoras - Ingenieria en Sistemas de Informacion - Universidad Nacional del Sur
	
*/

#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h>
#include <sys/time.h>
#include <arpa/nameser.h>
#include "definitions.h"

void initializeDnsQuery(){
	
	printIP = 1;
	
	if(recursive)
		resolveQuery(originalQueryName,globalQueryType);
	else{
		printf("; <<>> DnsQuery <<>> %s +trace\n",originalQueryName);
		printf(";; global options: +cmd\n");
		resolveIterative(originalQueryName,globalQueryType);
	}
}

void resolveIterative(char* queryName, unsigned short queryType){
	int answer = 0;
	root = 1;
	resolveQuery(".",T_NS);
	while(answer != 1){
		answer = resolveQuery(queryName,queryType);
	}
}

int resolveQuery(char* queryName, unsigned short queryType){
	int sizeOfHeader = prepareDnsHeader(queryName,queryType);
	sendAndReceiveFromSocket(sizeOfHeader);
	return parseResponse(sizeOfHeader);
}

int prepareDnsHeader(char* queryName, unsigned short queryType){
	
	struct DNS_HEADER *dns = NULL;
    struct QUESTION *question = NULL;
    
    dns = (struct DNS_HEADER *)&message;
 
    dns->id = (unsigned short) htons(getpid());
    dns->qr = 0;
    dns->opcode = 0; 
    dns->aa = 0;
    dns->tc = 0;
    dns->rd = recursive;
    dns->ra = 0;
    dns->unused = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->qdcount = htons(1);
    dns->ancount = 0;
    dns->nscount = 0;
    dns->arcount = 0;
    
    qname =(unsigned char*)&message[sizeof(struct DNS_HEADER)];
    changeDomainFormat(queryName,qname);
    question = (struct QUESTION*)&message[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)];
    question->qtype = htons( queryType );
    question->qclass = htons(1);
    
    return sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION);
}

void changeDomainFormat(char * regularDomain, unsigned char * dnsDomain){
	int domainLength = strlen(regularDomain);
	char * part = regularDomain;
	int count = 0;
	int i;
	for(i = 0;i <= domainLength ; i++){
		if(*regularDomain == '.' || i == domainLength){
			int j;
			*dnsDomain++ = count + 0;
			for(j = 0;j<count;j++){
				*dnsDomain++ = *part++;
			}
			part++;
			count = 0;
		}
		else {
			count++;
			
		}
		regularDomain++;
	}
	*dnsDomain++ = 0;
	*dnsDomain = '\0';
}

void sendAndReceiveFromSocket(int sizeOfMessage){
	int i;
	
	int sockfd;
	
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0) {
		perror("Socket creation failed");
		exit(EXIT_FAILURE);
	}
	
	struct sockaddr_in servaddr; 
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);
	servaddr.sin_addr.s_addr = inet_addr(server);
	
	struct timeval start, end, timeout;
	timeout.tv_sec = 10;
    timeout.tv_usec = 0;

	if (setsockopt (sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
        fprintf(stderr, "setsockopt failed\n");

    if (setsockopt (sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
        fprintf(stderr, "setsockopt failed\n");
	
	gettimeofday(&start, NULL);

	if( sendto(sockfd,(char*)message,sizeOfMessage,0,(struct sockaddr*)&servaddr,sizeof(servaddr)) < 0)
    {
        perror("Send timeout expired\n");
		exit(EXIT_FAILURE);
    }
    
    i = sizeof servaddr;
    if((sizeOfAnswer = recvfrom (sockfd,(char*)message , 512 , 0 , (struct sockaddr*)&servaddr , (socklen_t*)&i )) < 0)
    {
        perror("Recive timeout expired\n");
        exit(EXIT_FAILURE);
    }
    
    gettimeofday(&end, NULL);
    long seconds = (end.tv_sec - start.tv_sec);
    micros = ((seconds * 1000000) + end.tv_usec) - (start.tv_usec);
    
}
