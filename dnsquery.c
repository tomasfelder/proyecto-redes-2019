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
#include "definitions.h"

unsigned char message[512];
unsigned char* qname;
char* originalQueryName;
int globalQueryType;
int iterative;
char* server;
int port;
int status;
unsigned char* response;
char dnsServers[15][15];
long micros;
int sizeOfAnswer,printIP,root,serversCount,serversUsed;

int main(int argc, char **argv){
	
	initializeVariables(argv);
	if(iterative)
		resolveIterative(originalQueryName,globalQueryType);
	else{
		resolveRecursive(originalQueryName,globalQueryType);
	}
	return 0;
	
}

void initializeVariables(char **argv){
	originalQueryName = argv[1];
	globalQueryType = atoi(argv[2]);
	iterative = atoi(argv[3]);
	server = dnsServers[0];
	sprintf(server,argv[4]);
	
	port = atoi(argv[5]);
	
	serversUsed = 0;
	serversCount = 1;

	printIP = 1;
}


void resolveIterative(char* queryName, unsigned short queryType){
	printf("; <<>> DnsQuery <<>> google.com +trace\n");
	printf(";; global options: +cmd\n");
	int answer = 0;
	root = 1;
	resolveRecursive(".",T_NS);
	while(answer != 1 && serversUsed != serversCount){
		answer = resolveRecursive(queryName,queryType);
		if(answer ==  2){
			server = dnsServers[serversUsed];
			serversUsed++;
		}
	}
}

int resolveRecursive(char* queryName, unsigned short queryType){
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
    dns->rd = 1;
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
	
	struct timeval start, end;

	gettimeofday(&start, NULL);

	if( sendto(sockfd,(char*)message,sizeOfMessage,0,(struct sockaddr*)&servaddr,sizeof(servaddr)) < 0)
    {
        perror("sendto failed");
    }
    
    i = sizeof servaddr;
    if((sizeOfAnswer = recvfrom (sockfd,(char*)message , 512 , 0 , (struct sockaddr*)&servaddr , (socklen_t*)&i )) < 0)
    {
        perror("recvfrom failed");
    }
    
    gettimeofday(&end, NULL);
    long seconds = (end.tv_sec - start.tv_sec);
    micros = ((seconds * 1000000) + end.tv_usec) - (start.tv_usec);
    
}

int parseResponse(int sizeOfHeader){
	
    struct DNS_HEADER *dns = (struct DNS_HEADER*) message;
    response = &message[sizeOfHeader];
    
    status = dns->rcode;
	
	int questionsCount = ntohs(dns->qdcount);
	int answersCount = ntohs(dns->ancount);
	int authoritativeCount = ntohs(dns->nscount);
	int additionalRecordsCount = ntohs(dns->arcount);
	struct RESOURCE_RECORD answers[answersCount],additionals[additionalRecordsCount],authorities[authoritativeCount];
	
	if(iterative)
		return parseIterativeMethod(answers,additionals,authorities,answersCount,additionalRecordsCount,authoritativeCount,questionsCount);
	else
		parseRecursiveMethod(answers,additionals,authorities,answersCount,additionalRecordsCount,authoritativeCount,questionsCount);
	return 0;
	
}

void parseRecursiveMethod(struct RESOURCE_RECORD answers[],struct RESOURCE_RECORD additionals[],struct RESOURCE_RECORD authorities[],int answersCount, int additionalRecordsCount, int authoritativeCount, int questionsCount){
	printf("\n; <<>> DnsQuery <<>> %s \n",originalQueryName);
	printf(";; global options: +cmd\n");
    printf(";; Got answer:\n");
	printf(";; ->>HEADER<<- opcode: QUERY, status: %s, id: %u\n",ERRORS[status],getpid());
	printf(";; flags: qr rd ra; QUERY: %i, ANSWER: %i, AUTHORITY: %i, ADDITIONAL: %i\n\n",questionsCount,answersCount,authoritativeCount,additionalRecordsCount);
	printf(";; QUESTION SECTION:\n");
    printf(";%s			IN	A\n",originalQueryName);
    
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
}

int parseIterativeMethod(struct RESOURCE_RECORD answers[],struct RESOURCE_RECORD additionals[],struct RESOURCE_RECORD authorities[],int answersCount, int additionalRecordsCount, int authoritativeCount, int questionsCount){
	printf(";; flags: qr rd ra; QUERY: %i, ANSWER: %i, AUTHORITY: %i, ADDITIONAL: %i\n\n",questionsCount,answersCount,authoritativeCount,additionalRecordsCount);
	if(!additionalRecordsCount && !answersCount)
		return 2;
    readResourceRecords(answers,answersCount);
	readResourceRecords(authorities,authoritativeCount);
	
	
	printIP = 1;
	readResourceRecords(additionals,additionalRecordsCount);
	printIP = 1;
	printf(";; Received %i bytes from %s#%i(%s) in %ld ms\n\n",sizeOfAnswer,server,port,server,micros/1000);
	if(answersCount && !root)
		return 1;
	root = 0;
	int v;
	serversCount = 0;
	serversUsed = 0;
	for(v = 0 ; v < additionalRecordsCount ; v++){
		if(ntohs(additionals[v].resource->type)==T_A){
			sprintf(dnsServers[serversCount],"%i.%i.%i.%i",additionals[v].rdata[0],additionals[v].rdata[1],additionals[v].rdata[2],additionals[v].rdata[3]);
			serversCount++;
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
				readNSFormat(&resourceRecords[i]);
				break;
			case T_CNAME:
				resourceRecords[i].rdata = (unsigned char*)malloc(256);
				readCNAMEFormat(&resourceRecords[i]);
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
}

void readIPv4Address(int resourceDataLength,unsigned char* rdata){
	int j;
    for(j=0 ; j<resourceDataLength ; j++)
    {
		rdata[j]=response[j];
    }
	rdata[resourceDataLength] = '\0';
	response = response + resourceDataLength;
}

void printIPv4Address(struct RESOURCE_RECORD * answers){
	printf("%s		%i	IN	A	",answers->name,ntohl(answers->resource->ttl));
	int j;
	for(j=0 ; j< ntohs(answers->resource->data_len) ; j++){
		if(j+1 == ntohs(answers->resource->data_len))
			printf("%i",answers->rdata[j]);
		else
			printf("%i.",answers->rdata[j]);
	}
	printf("\n");
}

void readIPv6Address(int resourceDataLength,unsigned char* rdata){
	response = response + resourceDataLength;
}

void readSOAFormat(int resourceDataLength,unsigned char* rdata){
	int soaLenght1 = 0;
	unsigned char* mname = (unsigned char*)malloc(256);
	readAnswerName(response,message,&soaLenght1,mname);
	response = response + soaLenght1;
	rdata+= soaLenght1;
	int soaLenght2 = 0;
	unsigned char* rname = (unsigned char*)malloc(256);
	readAnswerName(response,message,&soaLenght2,rname);
	response = response + soaLenght2;
	rdata+= soaLenght2;
	struct SOA *soa = (struct SOA*) response;
	printf(".		5	IN	SOA	%s %s ",mname,rname);
	printf("%i %i %i %i %i\n",ntohl(soa->serial),ntohl(soa->refresh),ntohl(soa->retry),ntohl(soa->expire),ntohl(soa->minimum));
	rdata = rdata - soaLenght1 - soaLenght2 - sizeof(struct SOA);
	printf("%s\n",rdata);
	response = response + sizeof(struct SOA);
}

void readMXFormat(unsigned char* rdata){
	short preference = *(response+1);
	*rdata = preference;
	response+=sizeof(short);
	rdata+=sizeof(short);
	int nextPart = 0;
	readAnswerName(response,message,&nextPart,rdata);
	rdata-=sizeof(short);
	response = response + nextPart;
}

void printMXFormat(struct RESOURCE_RECORD * answers){
	printf("%s		%i	IN	MX	",answers->name,ntohl(answers->resource->ttl));
	printf("%u ",*(answers->rdata));
	printf("%s\n",answers->rdata+sizeof(short));
}

void readNSFormat(struct RESOURCE_RECORD * answers){
	int nextPart = 0;
	readAnswerName(response,message,&nextPart,answers->rdata);
	response = response + nextPart;
	printf("%s		%i	IN	NS	",answers->name,ntohl(answers->resource->ttl));
	printf("%s\n",answers->rdata);
}

void readCNAMEFormat(struct RESOURCE_RECORD * answers){
	int nextPart = 0;
	readAnswerName(response,message,&nextPart,answers->rdata);
	response = response + nextPart;
	printf("%s		%i	IN	CNAME	",answers->name,ntohl(answers->resource->ttl));
	printf("%s\n",answers->rdata);
}

void printLocalTime(){
	time_t now;
	time(&now);
	printf(";; WHEN: %s", ctime(&now));
}

char* convert(uint8_t *a){
  char* buffer2;
  int i;

  buffer2 = malloc(9);
  if (!buffer2)
    return NULL;

  buffer2[8] = 0;
  for (i = 0; i <= 7; i++)
    buffer2[7 - i] = (((*a) >> i) & (0x01)) + '0';

  puts(buffer2);

  return buffer2;
}

/* takes an on-the-wire LOC RR and prints it in zone file(human readable) format. */
void readLOCFormat(const unsigned char *binary,struct RESOURCE_RECORD * answers) {
		static char tmpbuf[255*3];
		
        register char *cp;
        register const unsigned char *rcp;

        int latdeg, latmin, latsec, latsecfrac;
        int longdeg, longmin, longsec, longsecfrac;
        char northsouth, eastwest;
        int altmeters, altfrac, altsign;

        const int referencealt = 100000 * 100;

        int32_t latval, longval, altval;
        u_int32_t templ;
        u_int8_t sizeval, hpval, vpval;
        u_int8_t versionval;


        rcp = binary;
 
        cp = tmpbuf;
        
        versionval = *rcp++;
		

        if (versionval) {
                sprintf(cp,"; error: unknown LOC RR version");
                
        }
		
        sizeval = *rcp++;
		
        hpval = *rcp++;
        
        vpval = *rcp++;


        GETLONG(templ,rcp);
        latval = (templ - ((unsigned)1<<31));       
        GETLONG(templ,rcp);
        longval = (templ - ((unsigned)1<<31));		
        GETLONG(templ,rcp);
        
        if (templ < referencealt) { /* below WGS 84 spheroid */
                altval = referencealt - templ;
                altsign = -1;
        } else {altval = templ - referencealt;
                altsign = 1;
        }

        if (latval < 0) {
                northsouth = 'S';
                latval = -latval;
        }
        else
                northsouth = 'N';

        latsecfrac = latval % 1000;
        latval = latval / 1000;
        latsec = latval % 60;
        latval = latval / 60;
        latmin = latval % 60;
        latval = latval / 60;
        latdeg = latval;

        if (longval < 0) {
                eastwest = 'W';
                longval = -longval;
        }
        else
                eastwest = 'E';

        longsecfrac = longval % 1000;
        longval = longval / 1000;
        longsec = longval % 60;
        longval = longval / 60;
        longmin = longval % 60;
        longval = longval / 60;
        longdeg = longval;

        altfrac = altval % 100;
        altmeters = (altval / 100) * altsign;
		printf("%s		%i	IN	LOC	",answers->name,ntohl(answers->resource->ttl));
        printf(
                "%d %.d %.2d.%.3d %c %d %.d %.2d.%.3d %c %d.%.2dm %sm %sm %sm\n",
                latdeg, latmin, latsec, latsecfrac, northsouth,
                longdeg, longmin, longsec, longsecfrac, eastwest,
                altmeters, altfrac, precsize_ntoa(sizeval), precsize_ntoa(hpval), precsize_ntoa(vpval));    
}

static unsigned int poweroften[10] = {1, 10, 100, 1000, 10000, 100000, 1000000,10000000,100000000,1000000000};

/* takes an XeY precision/size value, returns a string representation. */
const char *precsize_ntoa(u_int8_t prec){
	static char retbuf[sizeof "90000000.00"];	/* XXX nonreentrant */
	unsigned long val;
	int mantissa, exponent;

	mantissa = (int)((prec >> 4) & 0x0f) % 10;
	exponent = (int)((prec >> 0) & 0x0f) % 10;

	val = mantissa * poweroften[exponent];

	(void) sprintf(retbuf, "%ld.%.2ld", val/100, val%100);
	return (retbuf);
}
