#define PORT 53 
#define MAXLINE 1024

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

void changeDomainFormat(char * regularDomain, unsigned char * dnsDomain);
int prepareDnsHeader();
void sendAndReceiveFromSocket();
void readAnswerName();
void parseAnswer();
void readIPv4Address();
void readIPv6Address();
void readMXFormat();
void readSOAFormat();
void printLocalTime();
const char *precsize_ntoa(u_int8_t prec);
void readLOCFormat();
