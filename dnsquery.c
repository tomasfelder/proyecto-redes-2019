
#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 

#define PORT 53 
#define MAXLINE 1024

//Types of DNS resource records :)
 
#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server 

struct DNS_HEADER
{
    unsigned short id; // identification number
 
    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag
 
    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available
 
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

struct QUESTION {
	unsigned short qtype;
	unsigned short qclass;
};

struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};

struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};


void changeDomainFormat(char * regularDomain, unsigned char * dnsDomain);
unsigned char* readAnswerName(unsigned char *,unsigned char*,int *);

int main(int argc, char **argv)
{
	unsigned char message[512],*response;
	struct DNS_HEADER *dns = NULL;
    struct QUESTION *question = NULL;
    int i;
    
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
    
    
    unsigned char* qname =(unsigned char*)&message[sizeof(struct DNS_HEADER)];
    changeDomainFormat("google.com",qname);
    question = (struct QUESTION*)&message[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)];
    question->qtype = htons( T_A );
    question->qclass = htons(1);
	
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
	
	printf("\nSending Packet...\n");
	if( sendto(sockfd,(char*)message,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&servaddr,sizeof(servaddr)) < 0)
    {
        perror("sendto failed");
    }
    printf("Done");
     
    //Receive the answer
    i = sizeof servaddr;
    printf("\nReceiving answer...");
    if(recvfrom (sockfd,(char*)message , 512 , 0 , (struct sockaddr*)&servaddr , (socklen_t*)&i ) < 0)
    {
        perror("recvfrom failed");
    }
    printf("Done");
    
    dns = (struct DNS_HEADER*) message;
    response = &message[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];
	
	int answersCount = ntohs(dns->ans_count);
    printf("\nThe response contains : ");
    printf("\n %d Questions.",ntohs(dns->q_count));
    printf("\n %d Answers.",answersCount);
    printf("\n %d Authoritative Servers.",ntohs(dns->auth_count));
    printf("\n %d Additional records.\n\n",ntohs(dns->add_count));
    
    struct RES_RECORD answers[answersCount];
    
    int nextPart = 0;
    for(i = 0 ; i < answersCount ; i++){
		answers[i].name = readAnswerName(response,message,&nextPart);
		printf("%i\n",nextPart);
		
		response = response + nextPart;
		
		answers[i].resource = (struct R_DATA*)(response);
        response = response + sizeof(struct R_DATA);
 
        if(ntohs(answers[i].resource->type) == 1) //if its an ipv4 address
        {
            answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));
			int j;
            for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
            {
                answers[i].rdata[j]=response[j];
            }
 
            answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
 
            response = response + ntohs(answers[i].resource->data_len);
        }
        else
        {
            //answers[i].rdata = ReadName(reader,buf,&stop);
            //reader = reader + stop;
        }
        
	}
	printf("\nAnswer Records : %d \n" , ntohs(dns->ans_count) );
	for(i = 0 ; i < answersCount ; i++){
		printf("Name : %s ",answers[i].name);
 
        if( ntohs(answers[i].resource->type) == T_A) //IPv4 address
        {
            long *p;
            p=(long*)answers[i].rdata;
            servaddr.sin_addr.s_addr=(*p); //working without ntohl
            printf("has IPv4 address : %s\n",inet_ntoa(servaddr.sin_addr));
        }
	}
	
	return 0;
	
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
