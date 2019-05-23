
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
unsigned char* response;
long micros;
int soaLenght1,soaLenght2,sizeOfAnswer;

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
    changeDomainFormat("SW1A2AA.find.me.uk",qname);
    question = (struct QUESTION*)&message[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)];
    question->qtype = htons( T_LOC );
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

void parseAnswer(int sizeOfHeader){
	
	int i;
    
    struct DNS_HEADER *dns = (struct DNS_HEADER*) message;
    response = &message[sizeOfHeader];
	
	int questionsCount = ntohs(dns->q_count);
	int answersCount = ntohs(dns->ans_count);
	int authoritativeCount = ntohs(dns->auth_count);
	int additionalRecordsCount = ntohs(dns->add_count);
    printf("\n;; Got answer:\n");
	printf(";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: %u\n",getpid());
	printf(";; flags: qr rd ra; QUERY: %i, ANSWER: %i, AUTHORITY: %i, ADDITIONAL: %i\n\n",questionsCount,answersCount,authoritativeCount,additionalRecordsCount);
	printf(";; QUESTION SECTION:\n");
	printf(";%s			IN	A\n",qname);
    
    struct RESOURCE_RECORD answers[answersCount],additionals[additionalRecordsCount],authorities[authoritativeCount];
    
    //Answers
    for(i = 0 ; i < answersCount ; i++){
		int nextPart = 0;
		answers[i].name = (unsigned char*)malloc(256);
		readAnswerName(response,message,&nextPart,answers[i].name);
		response = response + nextPart;
		
		answers[i].resource = (struct RESOURCE_RECORD_METADATA*)(response);
        response = response + sizeof(struct RESOURCE_RECORD_METADATA) - 2;
		
		int resourceDataLength = ntohs(answers[i].resource->data_len);
		
        if(ntohs(answers[i].resource->type) == T_A) //if its an ipv4 address
        {
			answers[i].rdata = (unsigned char*)malloc(resourceDataLength);
			readIPv4Address(resourceDataLength,answers[i].rdata);
        }
		if(ntohs(answers[i].resource->type) == T_MX){
			answers[i].rdata = (unsigned char*)malloc(256);
			readMXFormat(answers[i].rdata);
		}
		if(ntohs(answers[i].resource->type) == T_AAAA)
        {
			answers[i].rdata = (unsigned char*)malloc(resourceDataLength);
			readIPv6Address(resourceDataLength,answers[i].rdata);
        }
        if(ntohs(answers[i].resource->type) == T_NS)
        {
			answers[i].rdata = (unsigned char*)malloc(256);
			int nextPart = 0;
			readAnswerName(response,message,&nextPart,answers[i].rdata);
			response = response + nextPart;
        }
        if(ntohs(answers[i].resource->type) == T_LOC)
        {
			readLOCFormat(response);
        }
	}
	
	    for(i=0;i<authoritativeCount;i++){
					int nextPart = 0;
					authorities[i].name = (unsigned char*)malloc(256);
					readAnswerName(response,message,&nextPart,authorities[i].name);
					response = response + nextPart;
					
					authorities[i].resource = (struct RESOURCE_RECORD_METADATA*)(response);
					response = response + sizeof(struct RESOURCE_RECORD_METADATA) - 2;
					
					int resourceDataLength = ntohs(authorities[i].resource->data_len);
					
					if(ntohs(authorities[i].resource->type)==T_SOA)
					{
						authorities[i].rdata = (unsigned char*)malloc(256);
						readSOAFormat(resourceDataLength,authorities[i].rdata);
					}
					if(ntohs(authorities[i].resource->type)==T_NS)
					{
						authorities[i].rdata = (unsigned char*)malloc(256);
						int nextPart = 0;
						readAnswerName(response,message,&nextPart,authorities[i].rdata);
						printf("%s		%i	IN	NS	",authorities[i].name,ntohl(authorities[i].resource->ttl));
						printf("%s\n",authorities[i].rdata);
						response = response + nextPart;
					}
	}
	
	//Additionals
    for(i=0;i<additionalRecordsCount;i++)
    {
        int nextPart = 0;
		additionals[i].name = (unsigned char*)malloc(256);
		readAnswerName(response,message,&nextPart,additionals[i].name);
		response = response + nextPart;
 
        additionals[i].resource = (struct RESOURCE_RECORD_METADATA*)(response);
        response = response + sizeof(struct RESOURCE_RECORD_METADATA) - 2;
		
		int resourceDataLength = ntohs(additionals[i].resource->data_len);
		additionals[i].rdata = (unsigned char*)malloc(resourceDataLength);
		
        if(ntohs(additionals[i].resource->type)==T_A)
        {
            readIPv4Address(resourceDataLength,additionals[i].rdata);
        }
        if(ntohs(additionals[i].resource->type)==T_AAAA)
        {
            readIPv6Address(resourceDataLength,additionals[i].rdata);
        }
    }
    
	if(answersCount>0){
		printf("\n;; ANSWER SECTION:\n");
		for(i = 0 ; i < answersCount ; i++){
	 
			if( ntohs(answers[i].resource->type) == T_A) //IPv4 address
			{
				printf("%s		%i	IN	A	",answers[i].name,ntohl(answers[i].resource->ttl));
				int j;
				for(j=0 ; j< ntohs(answers[i].resource->data_len) ; j++)
				{
					if(j+1 == ntohs(answers[i].resource->data_len))
						printf("%i",answers[i].rdata[j]);
					else
						printf("%i.",answers[i].rdata[j]);
				}
				printf("\n");
			}
			if(ntohs(answers[i].resource->type) == T_MX){
				printf("%s		%i	IN	MX	",answers[i].name,ntohl(answers[i].resource->ttl));
				printf("%u ",*(answers[i].rdata));
				printf("%s\n",answers[i].rdata+sizeof(short));
			}
			if(ntohs(answers[i].resource->type) == T_NS){
				printf("%s		%i	IN	NS	",answers[i].name,ntohl(answers[i].resource->ttl));
				printf("%s\n",answers[i].rdata);
			}
		}
	}
	if(additionalRecordsCount>0){
		printf("\n;; ADDITIONAL SECTION:\n");
		for(i = 0 ; i < additionalRecordsCount ; i++){
			if( ntohs(additionals[i].resource->type) == T_A) //IPv4 address
			{
				if(i==0)
					printf("%s		%i	IN	A	",additionals[i].name,ntohl(answers[i].resource->ttl));
				else
					printf("%s	%i	IN	A	",additionals[i].name,ntohl(answers[i].resource->ttl));
				int j;
				for(j=0 ; j< ntohs(additionals[i].resource->data_len) ; j++)
				{
					if(j+1 == ntohs(additionals[i].resource->data_len))
						printf("%i",additionals[i].rdata[j]);
					else
						printf("%i.",additionals[i].rdata[j]);
				}
				printf("\n");
			}
		}
	}
	if(authoritativeCount>0){
		printf("\n;; AUTHORITY SECTION:\n");
		    for(i=0;i<authoritativeCount;i++){
					int nextPart = 0;
					authorities[i].name = (unsigned char*)malloc(256);
					readAnswerName(response,message,&nextPart,authorities[i].name);
					response = response + nextPart;
					
					authorities[i].resource = (struct RESOURCE_RECORD_METADATA*)(response);
					response = response + sizeof(struct RESOURCE_RECORD_METADATA) - 2;
					
					int resourceDataLength = ntohs(authorities[i].resource->data_len);
					
					if(ntohs(authorities[i].resource->type)==T_SOA)
					{
						authorities[i].rdata = (unsigned char*)malloc(256);
						readSOAFormat(resourceDataLength,authorities[i].rdata);
					}
			}
	}
	
	printf("\n");
	printf(";; Query time: %ld msec\n",micros/1000);
	printf(";; SERVER: 192.168.140.2#53(192.168.140.2)\n");
	printLocalTime();
	printf(";; MSG SIZE  rcvd: %i\n\n",sizeOfAnswer);
	
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

void readIPv6Address(int resourceDataLength,unsigned char* rdata){
	response = response + resourceDataLength;
}

void readSOAFormat(int resourceDataLength,unsigned char* rdata){
	soaLenght1 = 0;
	//unsigned char* mname = (unsigned char*)malloc(256);
	readAnswerName(response,message,&soaLenght1,rdata);
	response = response + soaLenght1;
	rdata+= soaLenght1;
	soaLenght2 = 0;
	//unsigned char* rname = (unsigned char*)malloc(256);
	readAnswerName(response,message,&soaLenght2,rdata);
	response = response + soaLenght2;
	rdata+= soaLenght2;
	struct SOA *soa = (struct SOA*) response;
	//printf(".		5	IN	SOA	%s %s ",mname,rname);
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

void printLocalTime(){
	// time_t is arithmetic time type
	time_t now;
	
	// Obtain current time
	// time() returns the current time of the system as a time_t value
	time(&now);

	// Convert to local time format and print to stdout
	printf(";; WHEN: %s", ctime(&now));
}

char* convert(uint8_t *a)
{
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

/* takes an on-the-wire LOC RR and prints it in zone file
 * (human readable) format. */
void readLOCFormat(binary) const unsigned char *binary;
{
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

        printf(
                "%d %.d %.2d.%.3d %c %d %.d %.2d.%.3d %c %d.%.2dm %sm %sm %sm\n",
                latdeg, latmin, latsec, latsecfrac, northsouth,
                longdeg, longmin, longsec, longsecfrac, eastwest,
                altmeters, altfrac, precsize_ntoa(sizeval), precsize_ntoa(hpval), precsize_ntoa(vpval));    
}

static unsigned int poweroften[10] = {1, 10, 100, 1000, 10000, 100000,
				      1000000,10000000,100000000,1000000000};

/* takes an XeY precision/size value, returns a string representation. */
const char *precsize_ntoa(u_int8_t prec)
{
	static char retbuf[sizeof "90000000.00"];	/* XXX nonreentrant */
	unsigned long val;
	int mantissa, exponent;

	mantissa = (int)((prec >> 4) & 0x0f) % 10;
	exponent = (int)((prec >> 0) & 0x0f) % 10;

	val = mantissa * poweroften[exponent];

	(void) sprintf(retbuf, "%ld.%.2ld", val/100, val%100);
	return (retbuf);
}
