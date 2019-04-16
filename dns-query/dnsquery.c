
#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 

#define PORT     53 
#define MAXLINE 1024

//Types of DNS resource records :)
 
#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server 

struct DNS_HEADER {
    unsigned short id; //A 16 bit identifier assigned by the program that generates any kind of query
    
	unsigned char qr :1; // A one bit field that specifies whether this message is a query (0), or a response (1).
	unsigned char opcode :4; //A four bit field that specifies kind of query in this message
	unsigned char aa :1; //Authoritative Answer - this bit is valid in responses,  authority for the domain name in question section
	unsigned char tc :1; // TrunCation - specifies that this message was truncated due to length greater than that permitted on the transmission channel
    unsigned char rd :1; // If RD is set, it directs the name server to pursue the query recursively. Recursive query support is optional.
    unsigned char ra :1; // Recursion Available - this be is set or cleared in a response, and denotes whether recursive query support is available in the name server.
    unsigned char z :1; // Reserved for future use.  Must be zero in all queries and responses.
    unsigned char rcode :4; // Response code - this 4 bit field is set as part of responses.  The values have the following

    unsigned short qdcount; // an unsigned 16 bit integer specifying the number of entries in the question section.
    unsigned short ancount; // an unsigned 16 bit integer specifying the number of resource records in the answer section.
    unsigned short nscount; // an unsigned 16 bit integer specifying the number of name server resource records in the authority records section.
    unsigned short arcount; // an unsigned 16 bit integer specifying the number of resource records in the additional records section.
};

struct QUESTION {
	char* qname;
	unsigned char qtype :2;
	unsigned char qclass :2;
};

int main(int argc, char **argv)
{
	unsigned char message[512];
	struct DNS_HEADER *dns = &message;
	dns->id = (unsigned short) htons(getpid());
    dns->qr = 0;
    dns->opcode = 0;
    dns->aa = 0;
    dns->tc = 0;
    dns->rd = 1;
    dns->ra = 0;
    dns->z = 0;
    dns->rcode = 0;
    dns->qdcount = htons(1);
    dns->ancount = 0;
    dns->nscount = 0;
    dns->arcount = 0;
    
    struct QUESTION *question = &message[sizeof(struct DNS_HEADER)];
    question->qtype = htons( T_A );
    question->qclass = htons(1);
	
	int sockfd; 
    struct sockaddr_in servaddr; 
	
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0) {
		perror("Socket creation failed");
		exit(EXIT_FAILURE);
	}
	
	memset(&servaddr,0,sizeof(servaddr));
	
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(PORT);
	servaddr.sin_addr.s_addr = inet_addr("192.168.242.2");
	
	printf("\nSending Packet...\n");
    if( sendto(sockfd,(char*)message,sizeof(struct DNS_HEADER) + sizeof(question),0,(struct sockaddr*)&servaddr,sizeof(servaddr)) < 0)
    {
        perror("sendto failed");
    }
    printf("Done\n");
    
    int n, len;
    n = recvfrom(sockfd, (char *)message, 512,  
                MSG_WAITALL, (struct sockaddr *) &servaddr, 
                &len);
    if (n < 0)
		perror("recvfrom failed");
	printf("Done\n");
	printf("%s",message);
	return 0;
	
}

