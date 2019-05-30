
#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h>
#include "definitions.h" 

#include <stdint.h>
#include "loc_ntoa.h"

#include <arpa/nameser.h>

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
	servaddr.sin_addr.s_addr = inet_addr("200.49.130.47");
	
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
	printf(";%s			IN	LOC\n",qname);
    
    struct RESOURCE_RECORD answers[answersCount];
    
    for(i = 0 ; i < answersCount ; i++){
		int nextPart = 0;
		answers[i].name = readAnswerName(response,message,&nextPart);
		printf("Name: %s	IN	LOC	",answers[i].name);
		response = response + nextPart;
		
		answers[i].resource = (struct RESOURCE_RECORD_METADATA*)(response);
        response = response + sizeof(struct RESOURCE_RECORD_METADATA) -2;
		readLOCFormat(response);
		
		
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
		rdata[j]=response[j];
    }
	rdata[resourceDataLength] = '\0';
	printf("\n%i\n",resourceDataLength);
	response = response + resourceDataLength;
}

char *convert(uint8_t *a)
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
                "Latitud: %d %.d %.2d.%.3d %c Longitud: %d %.d %.2d.%.3d %c Altitud: %d.%.2dm Tamanio: %sm %sm %sm\n",
                latdeg, latmin, latsec, latsecfrac, northsouth,
                longdeg, longmin, longsec, longsecfrac, eastwest,
                altmeters, altfrac, precsize_ntoa(sizeval), precsize_ntoa(hpval), precsize_ntoa(vpval));
        
   
		
        
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

