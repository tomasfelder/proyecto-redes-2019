
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

void changeDomainFormat(char * regularDomain, unsigned char * dnsDomain);

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
    changeDomainFormat("www.google.com",qname);
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
 
    printf("\nThe response contains : ");
    printf("\n %d Questions.",ntohs(dns->q_count));
    printf("\n %d Answers.",ntohs(dns->ans_count));
    printf("\n %d Authoritative Servers.",ntohs(dns->auth_count));
    printf("\n %d Additional records.\n\n",ntohs(dns->add_count));
    
	return 0;
	
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
