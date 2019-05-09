#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <resolv.h>

void get_dns_servers();

//List of DNS Servers registered on the system
char dns_servers[10][100];
int dns_server_count = 0;
  
int main(int argc,char* argv[]) 
{ 
    int counter;
    int aFlag = 0;
    int mxFlag = 0;
    int locFlag = 0; 
    int rFlag = 0;
    int tFlag = 0;
    int hFlag = 0;
    
    
    char ipDNS[15];
    char puerto[10];
    
     
    printf("Program Name Is: %s",argv[0]); 
    if(argc==1) 
        printf("\nNo Extra Command Line Argument Passed Other Than Program Name"); 
    if(argc>=2) 
    { 
		char consulta[sizeof(argv[1])];
		strcpy(consulta, argv[1]);
		printf("\n consulta: %s \n", consulta);
		
        printf("\nNumber Of Arguments Passed: %d\n",argc); 
        if (argc>=3){
			int j;
			int flagServidor = 0;
			int flagPuerto = 0;
			int x = 0;
			int s = 0;
			for (j=0; (argv[2][j] != '\0') && j<strlen(argv[2]) ;j++){
				
			
				
				if (flagPuerto == 1){
					puerto[s]= argv[2][j];
					s++;
				}
				
				if (argv[2][j] == ':'){
					flagServidor = 0;
					flagPuerto = 1;
					
				}
				
				if (flagServidor == 1){
					ipDNS[x] = argv[2][j];
					x++;
				}
				
				
				if (argv[2][j] == '@'){
					flagServidor = 1;
				}
				
			}
			puerto[s]='\0';
			ipDNS[x]='\0';
			printf("\n DNS:%s\n", ipDNS);
			printf("\n puerto:%s\n", puerto);
			
			if (strcmp(ipDNS,"") == 0){
				get_dns_servers();
				printf("LocalDNS:%s\n", dns_servers[0]);
			}
			
			if (argc>=4){
				printf("\n----Following Are The Command Line Arguments Passed----"); 
				for(counter=3;counter<argc;counter++){
					char* argumento = argv[counter];
					printf("\n%s",argumento);
					if ((strcmp(argumento, "-a") == 0) && (mxFlag == 0) && (locFlag == 0))
						aFlag=1;
					else if ((strcmp(argumento, "-mx") == 0) && (aFlag == 0) && (locFlag == 0))
							mxFlag=1;
						
						else if (strcmp(argumento, "-loc") == 0 && (aFlag == 0) && (mxFlag == 0))
							{
								locFlag = 1;
							} 
							else if (strcmp(argumento, "-r") == 0 && (tFlag == 0))
									rFlag = 1;
								else if (strcmp(argumento, "-t") == 0 && (rFlag == 0))
										tFlag = 1;
									else if (strcmp(argumento, "-h") == 0)
											hFlag = 1;
				}
				printf("\naFlag = %i\n",aFlag);
				printf("mxFlag = %i\n",mxFlag);
				printf("locFlag = %i\n",locFlag);
				printf("rFlag = %i\n",rFlag);
				printf("tFlag = %i\n",tFlag);
				printf("hFlag = %i\n",hFlag);
			}							
		}
		
    } 
    return 0; 
} 

void get_dns_servers()
{
    FILE *fp;
    char line[200] , *p;
    if((fp = fopen("/etc/resolv.conf" , "r")) == NULL)
    {
        printf("Failed opening /etc/resolv.conf file \n");
    }
     
    while(fgets(line , 200 , fp))
    {
        if(line[0] == '#')
        {
            continue;
        }
        if(strncmp(line , "nameserver" , 10) == 0)
        {
            p = strtok(line , " ");
            p = strtok(NULL , " ");
             
            //p now is the dns ip :)
            //????
        }
    }
     
    strcpy(dns_servers[0] , p);
    
}
