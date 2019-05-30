#include <stdio.h> 
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h> 
#include <time.h>
#include <arpa/nameser.h>
#include "definitions.h"

const char* ERRORS[] = { "NOERROR", "FORMERR","SERVFAIL","NXDOMAIN","NOTIMP","REFUSED","YXDOMAIN","YXRRSET","NXRRSET","NOTAUTH","NOTZONE" };


int parseResponse(int sizeOfHeader){
	
    struct DNS_HEADER *dns = (struct DNS_HEADER*) message;
    response = &message[sizeOfHeader];
    
    status = dns->rcode;
	
	int questionsCount = ntohs(dns->qdcount);
	int answersCount = ntohs(dns->ancount);
	int authoritativeCount = ntohs(dns->nscount);
	int additionalRecordsCount = ntohs(dns->arcount);
	struct RESOURCE_RECORD answers[answersCount],additionals[additionalRecordsCount],authorities[authoritativeCount];
	
	if(recursive)
		return parseRecursiveMethod(answers,additionals,authorities,answersCount,additionalRecordsCount,authoritativeCount,questionsCount);
	if(!recursive && root)
		return parseRootServersAnswers(answers,additionals,authorities,answersCount,additionalRecordsCount,authoritativeCount);
	if(!recursive && !root)
		return parseIterativeMethod(answers,additionals,authorities,answersCount,additionalRecordsCount,authoritativeCount);
	return 0;
	
}

int parseRecursiveMethod(struct RESOURCE_RECORD answers[],struct RESOURCE_RECORD additionals[],struct RESOURCE_RECORD authorities[],int answersCount, int additionalRecordsCount, int authoritativeCount, int questionsCount){
	printf("\n; <<>> DnsQuery <<>> %s \n",originalQueryName);
	printf(";; global options: +cmd\n");
    printf(";; Got answer:\n");
	printf(";; ->>HEADER<<- opcode: QUERY, status: %s, id: %u\n",ERRORS[status],getpid());
	printf(";; flags: qr rd ra; QUERY: %i, ANSWER: %i, AUTHORITY: %i, ADDITIONAL: %i\n\n",questionsCount,answersCount,authoritativeCount,additionalRecordsCount);
	printf(";; QUESTION SECTION:\n");
	switch(globalQueryType){
		case T_A:
			printf(";%s			IN	A\n",originalQueryName);
			break;
		case T_MX:
			printf(";%s			IN	MX\n",originalQueryName);
			break;
		case T_LOC:
			printf(";%s			IN	LOC\n",originalQueryName);
			break;
	}
    
    if(answersCount>0){
		printf("\n;; ANSWER SECTION:\n");
		readResourceRecords(answers,answersCount);
	}
	if(authoritativeCount>0){
		printf("\n;; AUTHORITY SECTION:\n");
		readResourceRecords(authorities,authoritativeCount);
	}
	
	if(additionalRecordsCount>0){
		printf("\n;; ADDITIONAL SECTION:\n");
		readResourceRecords(additionals,additionalRecordsCount);
	}

	printf("\n");
	printf(";; Query time: %ld msec\n",micros/1000);
	printf(";; SERVER: %s#53(%s)\n",server,server);
	printLocalTime();
	printf(";; MSG SIZE  rcvd: %i\n\n",sizeOfAnswer);
	
	return 0;
}

int parseIterativeMethod(struct RESOURCE_RECORD answers[],struct RESOURCE_RECORD additionals[],struct RESOURCE_RECORD authorities[],int answersCount, int additionalRecordsCount, int authoritativeCount){
	
    readResourceRecords(answers,answersCount);
	readResourceRecords(authorities,authoritativeCount);

	printIP = 0;
	readResourceRecords(additionals,additionalRecordsCount);
	printf(";; Received %i bytes from %s#%i(%s) in %ld ms\n\n",sizeOfAnswer,server,port,server,micros/1000);
	
	if(answersCount){
		return 1;
	}
		
	if(!additionalRecordsCount && !answersCount && authoritativeCount){
		if(ntohs(authorities[0].resource->type) == T_SOA)
			return 1;
		else
			getIPFromNameServer((char *)authorities[0].rdata);
	}
	else{
		updateServer(additionals,additionalRecordsCount);
	}
	
	printIP = 1;
	return 0;
}

int parseRootServersAnswers(struct RESOURCE_RECORD answers[],struct RESOURCE_RECORD additionals[],struct RESOURCE_RECORD authorities[],int answersCount, int additionalRecordsCount, int authoritativeCount){
    readResourceRecords(answers,answersCount);
	readResourceRecords(authorities,authoritativeCount);
	
	printIP = 0;
	readResourceRecords(additionals,additionalRecordsCount);
	printf(";;Received %i bytes from %s#%i(%s) in %ld ms\n\n",sizeOfAnswer,server,port,server,micros/1000);
	root = 0;
	if(!additionalRecordsCount && answersCount){
		getIPFromNameServer((char *)answers[0].rdata);
	}
	else{
		if(authoritativeCount){
			getIPFromNameServer((char *)authorities[0].rdata);
		}
		else{
			updateServer(additionals,additionalRecordsCount);
		}
	}
	
	printIP = 1;
	return 0;
}

int updateServer(struct RESOURCE_RECORD resourceRecords[],int resourceRecordsCount){
	int v;
	for(v = 0 ; v < resourceRecordsCount ; v++){
		if(ntohs(resourceRecords[v].resource->type)==T_A){
			sprintf(server,"%i.%i.%i.%i",resourceRecords[v].rdata[0],resourceRecords[v].rdata[1],resourceRecords[v].rdata[2],resourceRecords[v].rdata[3]);
			return 0;
		}
	}
	return 0;
}

void readResourceRecords(struct RESOURCE_RECORD resourceRecords[],int resourceRecordsCount){
		int i;
		for(i = 0 ; i < resourceRecordsCount ; i++){
			
			int nextPart = 0;
			resourceRecords[i].name = (unsigned char*)malloc(256);
			readAnswerName(response,message,&nextPart,resourceRecords[i].name);
			
			response = response + nextPart;
			resourceRecords[i].resource = (struct RESOURCE_RECORD_METADATA*)(response);
			response = response + sizeof(struct RESOURCE_RECORD_METADATA) - 2;
			
			int resourceDataLength = ntohs(resourceRecords[i].resource->data_len);
			
			int type = ntohs(resourceRecords[i].resource->type);
			
			switch(type)
			{
			case T_A:
				resourceRecords[i].rdata = (unsigned char*)malloc(resourceDataLength);
				readIPv4Address(resourceDataLength,resourceRecords[i].rdata);
				if(printIP)
					printIPv4Address(&resourceRecords[i]);
				break;
			case T_NS:
				resourceRecords[i].rdata = (unsigned char*)malloc(256);
				readAndPrintNSFormat(&resourceRecords[i]);
				break;
			case T_CNAME:
				resourceRecords[i].rdata = (unsigned char*)malloc(256);
				readAndPrintCNAMEFormat(&resourceRecords[i]);
				break;
			case T_SOA:
				resourceRecords[i].rdata = (unsigned char*)malloc(256);
				readSOAFormat(resourceDataLength,resourceRecords[i].rdata);
				break;
			case T_MX:
				resourceRecords[i].rdata = (unsigned char*)malloc(256);
				readMXFormat(resourceRecords[i].rdata);
				printMXFormat(&resourceRecords[i]);
				break;
			case T_AAAA:
				resourceRecords[i].rdata = (unsigned char*)malloc(resourceDataLength);
				readIPv6Address(resourceDataLength,resourceRecords[i].rdata);
				break;
			case T_LOC:
				readLOCFormat(response,&resourceRecords[i]);
				response = response + resourceDataLength;
				break;
			default:
				response = response + resourceDataLength;
				break;
			}
		}	
}

void readAnswerName(unsigned char* response,unsigned char* message, int* nextPart,unsigned char * domainName){
	
    unsigned int jumped=0,offset;
    int i , j, number, count;
 
    *nextPart = 1;
    count = 0;
 
    while(*response!=0)
    {
        if(*response>=192)
        {
            offset = (*response)*256 + *(response+1) - 49152;
            response = message + offset - 1;
            jumped = 1;
        }
        else
        {
            domainName[count++] = *response;
        }
 
        response++;
 
        if(jumped==0)
        {
            *nextPart = *nextPart + 1;
        }
    }
    domainName[count] = '\0';
    if(jumped==1)
    {
        *nextPart = *nextPart + 1;
    }
	int domainNameLength = strlen((char *) domainName);
    for(i=0 ; i<domainNameLength ; i++) 
    {
        number=domainName[i];
        for(j=0 ; j < number ; j++) 
        {
            domainName[i] = domainName[i+1];
            i=i+1;
        }
        domainName[i] ='.';
    }
}

void getIPFromNameServer(char * hostname){
	struct hostent* host = gethostbyname(hostname);
	if(host == NULL){
		printf("Not a valid server name\n");
		exit(EXIT_FAILURE);
	}
	struct in_addr *addr = (struct in_addr *)host->h_addr;
	sprintf(server,inet_ntoa(*addr));
}
