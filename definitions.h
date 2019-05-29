#ifndef HEADERS
#define HEADERS

#define PORT 53 
#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h>
#include <sys/time.h>
#include <time.h>
#include <stdint.h>
#include <arpa/nameser.h>
#include <netdb.h>

extern const char* ERRORS[];

char* originalQueryName;
int globalQueryType;
int recursive;
char* server;
int port;
unsigned char message[512];
unsigned char* qname;
int status;
unsigned char* response;
long micros;
int sizeOfAnswer,printIP,root;

struct DNS_HEADER
{
    unsigned short id; /*%< query identification number */
 
	unsigned	rd :1;		/*%< recursion desired */
	unsigned	tc :1;		/*%< truncated message */
	unsigned	aa :1;		/*%< authoritive answer */
	unsigned	opcode :4;	/*%< purpose of message */
	unsigned	qr :1;		/*%< response flag */
 
	unsigned	rcode :4;	/*%< response code */
	unsigned	cd: 1;		/*%< checking disabled by resolver */
	unsigned	ad: 1;		/*%< authentic data from named */
	unsigned	unused :1;	/*%< unused bits (MBZ as of 4.9.3a3) */
	unsigned	ra :1;		/*%< recursion available */
 
	unsigned	qdcount :16;	/*%< number of question entries */
	unsigned	ancount :16;	/*%< number of answer entries */
	unsigned	nscount :16;	/*%< number of authority entries */
	unsigned	arcount :16;	/*%< number of resource entries */
};

struct QUESTION {
	unsigned short qtype;
	unsigned short qclass;
};

struct RESOURCE_RECORD_METADATA
{
    unsigned short type;
    unsigned short _class;
    int ttl;
    unsigned short data_len;
};

struct RESOURCE_RECORD
{
    unsigned char *name;
    struct RESOURCE_RECORD_METADATA *resource;
    unsigned char *rdata;
};

struct SOA
{
	unsigned int serial;
	int refresh;
	int retry;
	int expire;
	unsigned int minimum;
};

extern void initializeDnsQuery();
int resolveQuery(char* queryName, unsigned short queryType);
void resolveIterative(char* queryName, unsigned short queryType);
int prepareDnsHeader(char* queryName, unsigned short queryType);
void changeDomainFormat(char * regularDomain, unsigned char * dnsDomain);
void sendAndReceiveFromSocket(int sizeOfMessage);
int parseResponse(int sizeOfHeader);
int parseRootServersAnswers(struct RESOURCE_RECORD answers[],struct RESOURCE_RECORD additionals[],struct RESOURCE_RECORD authorities[],int answersCount, int additionalRecordsCount, int authoritativeCount, int questionsCount);
int parseRecursiveMethod(struct RESOURCE_RECORD answers[],struct RESOURCE_RECORD additionals[],struct RESOURCE_RECORD authorities[],int answersCount, int additionalRecordsCount, int authoritativeCount, int questionsCount);
int parseIterativeMethod(struct RESOURCE_RECORD answers[],struct RESOURCE_RECORD additionals[],struct RESOURCE_RECORD authorities[],int answersCount, int additionalRecordsCount, int authoritativeCount, int questionsCount);
void getIPFromNameServer(char * hostname);
int updateServer(struct RESOURCE_RECORD resourceRecords[],int resourceRecordsCount);
void readResourceRecords(struct RESOURCE_RECORD resourceRecords[],int resourceRecordsCount);
void readAnswerName(unsigned char* response,unsigned char* message, int* nextPart,unsigned char * domainName);
void readIPv4Address(int resourceDataLength,unsigned char* rdata);
void printIPv4Address(struct RESOURCE_RECORD * answers);
void readIPv6Address(int resourceDataLength,unsigned char* rdata);
void readSOAFormat(int resourceDataLength,unsigned char* rdata);
void readMXFormat(unsigned char* rdata);
void printMXFormat(struct RESOURCE_RECORD * answers);
void readNSFormat(struct RESOURCE_RECORD * answers);
void readCNAMEFormat(struct RESOURCE_RECORD * answers);
void printLocalTime();
char* convert(uint8_t *a);
void readLOCFormat(const unsigned char *binary,struct RESOURCE_RECORD * answers);
const char *precsize_ntoa(u_int8_t prec);

#endif
