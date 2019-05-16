
#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h>
#include "definitions.h" 

unsigned char message[512];
unsigned char* qname;
unsigned char* response;

int main(int argc, char **argv)
{
	int sizeOfHeader = prepareDnsHeader();
    sendAndReceiveFromSocket(sizeOfHeader);
    parseAnswer(sizeOfHeader);
	return 0;
}

int prepareDnsHeader(){
	struct DNS_HEADER *dns = NULL;
    struct QUESTION *question = NULL;
    
    dns = (struct DNS_HEADER *)&message;
 
    dns->id = (unsigned short) htons(getpid());
    dns->qr = 0; //This is a query
    dns->opcode = 0; //This is a standard query
    dns->aa = 0; //Not Authoritative
    dns->tc = 0; //This message is not truncated
    dns->rd = 1; //Recursion Desired
    dns->ra = 0; //Recursion not available! hey we dont have it (lol)
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1); //we have only 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;
    
    qname =(unsigned char*)&message[sizeof(struct DNS_HEADER)];
    changeDomainFormat("cs.uns.edu.ar",qname);
    question = (struct QUESTION*)&message[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)];
    question->qtype = htons( T_A );
    question->qclass = htons(1);
    
    return sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION);
}

void sendAndReceiveFromSocket(int sizeOfMessage){
	int i;
	
	int sockfd; 
    struct sockaddr_in servaddr; 
	
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0) {
		perror("Socket creation failed");
		exit(EXIT_FAILURE);
	}
	
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(PORT);
	servaddr.sin_addr.s_addr = inet_addr("192.168.140.2");
	
	if( sendto(sockfd,(char*)message,sizeOfMessage,0,(struct sockaddr*)&servaddr,sizeof(servaddr)) < 0)
    {
        perror("sendto failed");
    }
     
    //Receive the answer
    i = sizeof servaddr;
    if(recvfrom (sockfd,(char*)message , 512 , 0 , (struct sockaddr*)&servaddr , (socklen_t*)&i ) < 0)
    {
        perror("recvfrom failed");
    }
}

void parseAnswer(int sizeOfHeader){
	
	int i;
    
    struct DNS_HEADER *dns = (struct DNS_HEADER*) message;
    response = &message[sizeOfHeader];
	
	int questionsCount = ntohs(dns->q_count);
	int answersCount = ntohs(dns->ans_count);
	int authoritativeCount = ntohs(dns->auth_count);
	int additionalRecordsCount = ntohs(dns->add_count);
    printf("\n;; Got answer:\n");
	printf(";; ->>HEADER<<- opcode: QUERY, status: NOERROR\n");
	printf(";; flags: qr rd ra; QUERY: %i, ANSWER: %i, AUTHORITY: %i, ADDITIONAL: %i\n\n",questionsCount,answersCount,authoritativeCount,additionalRecordsCount);
	printf(";; QUESTION SECTION:\n");
	printf(";%s			IN	A\n",qname);
    
    struct RESOURCE_RECORD answers[answersCount];
    
    int nextPart = 0;
    for(i = 0 ; i < answersCount ; i++){
		answers[i].name = readAnswerName(response,message,&nextPart);
		
		response = response + nextPart;
		
		answers[i].resource = (struct RESOURCE_RECORD_METADATA*)(response);
        response = response + sizeof(struct RESOURCE_RECORD_METADATA);
		
		int resourceDataLength = ntohs(answers[i].resource->data_len);
		answers[i].rdata = (unsigned char*)malloc(resourceDataLength);
		
        if(ntohs(answers[i].resource->type) == T_A) //if its an ipv4 address
        {
			readIPv4Address(resourceDataLength,answers[i].rdata);
        }
        else
        {
			if(ntohs(answers[i].resource->type) == T_MX){
				readMXFormat();
			}
        }
	}
	printf("\n;; ANSWER SECTION:\n");
	for(i = 0 ; i < answersCount ; i++){

		printf("%s		5	IN	A	",answers[i].name);
 
        if( ntohs(answers[i].resource->type) == T_A) //IPv4 address
        {
            int j;
            for(j=0 ; j< ntohs(answers[i].resource->data_len) ; j++)
            {
				printf("%i.",answers[i].rdata[j]);
            }
            printf("\n\n");
        }
	}
}

unsigned char * readAnswerName(unsigned char* response,unsigned char* message, int* nextPart){
	
    unsigned char *domainName;
    unsigned int jumped=0,offset;
    int i , j, number, count;
 
    *nextPart = 1;
    count = 0;
    domainName = (unsigned char*)malloc(256);
 
    while(*response!=0)
    {
        if(*response>=192)
        {
            offset = (*response)*256 + *(response+1) - 49152; //49152 = 11000000 00000000 ;)
            response = message + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else
        {
            domainName[count++] = *response;
        }
 
        response++;
 
        if(jumped==0)
        {
            *nextPart = *nextPart + 1; //if we havent jumped to another location then we can count up
        }
    }
    domainName[count] = '\0'; //string complete
    if(jumped==1)
    {
        *nextPart = *nextPart + 1; //number of steps we actually moved forward in the packet
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
    domainName[i-1]='\0'; //remove the last dot
    return domainName;
}

void readIPv4Address(int resourceDataLength,unsigned char* rdata){
	int j;
    for(j=0 ; j<resourceDataLength ; j++)
    {
		rdata[j]=response[j-2];
    }
	rdata[resourceDataLength] = '\0';
	response = response + resourceDataLength;
}

void readMXFormat(int resourceDataLength,unsigned char* rdata){
	rdata = rdata + sizeof(short);
	printf("%s\n",rdata);
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
