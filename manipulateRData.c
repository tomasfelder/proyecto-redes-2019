#include "definitions.h"

static unsigned int poweroften[10] = {1, 10, 100, 1000, 10000, 100000, 1000000,10000000,100000000,1000000000};

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
