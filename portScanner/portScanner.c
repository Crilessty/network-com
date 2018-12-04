#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>
#include <string.h>
#include <netdb.h>
#include <pthread.h>

#define SEGMENT_LENGTH     100
#define MAX_PORT          1024 
#define THREAD_NUM          24 
#define MAX_NUM_IP         100 

int scan_num = 0;

typedef struct port_data_segment{
    struct in_addr ip;
    unsigned int start;
}port_data_segment;

int scan_(char *ip,int po)
{
    
    struct sockaddr_in sa;
    int sockfd;


    memset(&sa, 0, sizeof(sa));

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(ip);
    sa.sin_port = htons(po);

    if( (sockfd = socket(AF_INET,SOCK_STREAM,0)) < 0)
    {
        perror("socket error :");
        return 0;
    }
    
    
    if( connect(sockfd,(struct sockaddr *)&sa,sizeof(sa)) < 0){
        //perror("connect fail: ");
        close(sockfd);
        return 0;
    }
    else
    {
        close(sockfd);
        return 1;
    }
      
}

//扫描函数
void *scan(void *arg)
{
    port_data_segment port;
    int i = 0;

    //pthread_detach(pthread_self());  

    memcpy(&port,arg,sizeof(port_data_segment));

    while(port.start <= MAX_PORT)
    {
        if(scan_(inet_ntoa(port.ip),port.start) == 1)
            printf("%s : The port %d is accepted.\n",inet_ntoa(port.ip),port.start);
        port.start += THREAD_NUM;
    }

}

int main(int argc,char **argv)
{
    pthread_t *thread;
    int i,j;
    struct in_addr IP[MAX_NUM_IP];
    port_data_segment *port;
    thread = (pthread_t*)malloc( THREAD_NUM * sizeof(pthread_t));
    port = (port_data_segment*)malloc(THREAD_NUM * sizeof(port_data_segment));

    if(argc >2) {
        printf("usage: 1. ./scan\n");
        printf("       2. ./scan  IP\n");
    }
    
    if(argc == 2) {
        if(inet_aton(argv[1],&IP[0]) == 0){
            printf("ip address is wrong");
            exit(1);
        }
        scan_num ++;
    } else {
        FILE *fiplist, *fnamelist;
        char buffer1[40],buffer2[40];
        //shell arp -na
        printf("\n");
        system("sudo arp -na | cut -d \" \" -f 1 > .name");
        system("sudo arp -na | cut -d \" \" -f 2 | sed \"s/(//g\" | sed \"s/)//g\" > .ip");

        fiplist = fopen(".ip","r");
        fnamelist = fopen(".name","r");
        while (fgets(buffer1,40,fiplist) && fgets(buffer2,40,fnamelist)) {
            inetaton(buffer1,&IP[scan_num - 1]);
            printf("%s\t%s\n",buffer2,buffer1);
            scan_num ++;
        }
        fclose(fiplist);
        fclose(fnamelist);
    }

    for (int j = 0;j < scan_num;j ++) {
        //thread 实现
        for(i = 0;i < THREAD_NUM; i++) {
            port[i].ip = IP;
            port[i].start = i;
            
            if(pthread_create(&thread[i], NULL, scan, (void *)&port[i]) != 0){
                perror("pthread create failed");
                return 0;
            }
        }
        
        for(i = 0;i<THREAD_NUM;i++){
            pthread_join(*(thread+i),NULL);
        }

        printf("%s : ports (1 - %d) scanning is completed .\n",argv[1],MAX_PORT);
    }
    
    
    free(thread);
    free(port);

    return 0;
    
}
