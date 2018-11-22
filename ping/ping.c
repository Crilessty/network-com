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


#define PACKET_SEND_MAX_NUM 1024

typedef struct ping_packet_status
{
    struct timeval begin_time;
    struct timeval end_time;
    int flag;   
    int seq;    
}ping_packet_status;



ping_packet_status ping_packet[PACKET_SEND_MAX_NUM];

int rawsock;
int send_count = 0;
int recv_count = 0;
int counts = 4;
int icmp_length = 64;
pid_t pid;
struct sockaddr_in dest;
struct timeval start_time;
struct timeval end_time;
struct timeval time_interval;


unsigned short cal_chksum(unsigned short *addr,int len)
{       int nleft=len;
        int sum=0;
        unsigned short *w=addr;
        unsigned short answer=0;

        while(nleft>1)
        {       
            sum+=*w++;
            nleft-=2;
        }
    
        if( nleft==1)
        {       
            *(unsigned char *)(&answer)=*(unsigned char *)w;
            sum+=answer;
        }
        sum=(sum>>16)+(sum&0xffff);
        sum+=(sum>>16);
        answer=~sum;
        return answer;
}

struct timeval cal_time_offset(struct timeval begin, struct timeval end)
{
    struct timeval ans;
    ans.tv_sec = end.tv_sec - begin.tv_sec;
    ans.tv_usec = end.tv_usec - begin.tv_usec;
    if(ans.tv_usec < 0) 
    {
        ans.tv_sec--;
        ans.tv_usec+=1000000;
    }
    return ans;
}

void icmp_pack(struct icmp* icmphdr, int seq, int length)
{
    int i = 0;

    icmphdr->icmp_type = ICMP_ECHO;
    icmphdr->icmp_code = 0;
    icmphdr->icmp_cksum = 0;
    icmphdr->icmp_seq = seq;
    icmphdr->icmp_id = pid & 0xffff;
    for(i=0;i<length;i++)
    {
        icmphdr->icmp_data[i] = i;
    }

    icmphdr->icmp_cksum = cal_chksum((unsigned short*)icmphdr, length);
}

int icmp_unpack(char* buf, int len)
{
    int iphdr_len;
    struct timeval begin_time, recv_time, offset_time;
    double rtt;  

    struct ip* ip_hdr = (struct ip *)buf;
    iphdr_len = ip_hdr->ip_hl*4;
    struct icmp* icmp = (struct icmp*)(buf+iphdr_len);
    len-=iphdr_len;  
    if(len < 8)  
    {
        fprintf(stderr, "Invalid icmp packet.Its length is less than 8\n");
        return -1;
    }

    if((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == (pid & 0xffff))) 
    {
        if((icmp->icmp_seq < 0) || (icmp->icmp_seq > PACKET_SEND_MAX_NUM))
        {
            fprintf(stderr, "icmp packet seq is out of range!\n");
            return -1;
        }

        ping_packet[icmp->icmp_seq].flag = 0;
        begin_time = ping_packet[icmp->icmp_seq].begin_time;
        gettimeofday(&recv_time, NULL);

        offset_time = cal_time_offset(begin_time, recv_time);
        rtt = offset_time.tv_sec*1000000 + (offset_time.tv_usec); 
        rtt /= 1000;

        printf("%d byte from %s: icmp_seq=%u ttl=%d time=%.2f ms\n",
            len, inet_ntoa(ip_hdr->ip_src), icmp->icmp_seq, ip_hdr->ip_ttl, rtt);        

    }
    else
    {
        return -1;
    }
    return 0;
}

void ping_send()
{
    char send_buf[4096];
    memset(send_buf, 0, sizeof(send_buf));
    gettimeofday(&start_time, NULL); 
    while(send_count < counts)
    {
        int size = 0;
        gettimeofday(&(ping_packet[send_count].begin_time), NULL);
        ping_packet[send_count].flag = 1; 

        icmp_pack((struct icmp*)send_buf, send_count, icmp_length); 
        size = sendto(rawsock, send_buf, icmp_length, 0, (struct sockaddr*)&dest, sizeof(dest));
        send_count++; 
        if(size < 0)
        {
            fprintf(stderr, "send icmp packet fail!\n");
            continue;
        }

        sleep(1);
    }
}

void ping_recv()
{
    struct timeval tv;
    tv.tv_usec = 200;  //select超时时间
    tv.tv_sec = 0;
    fd_set read_fd;
    char recv_buf[4096];
    memset(recv_buf, 0 ,sizeof(recv_buf));
    while(recv_count < counts)
    {
        int ret = 0;
        FD_ZERO(&read_fd);
        FD_SET(rawsock, &read_fd);
        ret = select(rawsock+1, &read_fd, NULL, NULL, &tv);
        switch(ret)
        {
            case -1:
                fprintf(stderr,"fail to select!\n");
                break;
            case 0:
                break;
            default:
                {
                    int size = recv(rawsock, recv_buf, sizeof(recv_buf), 0);
                    if(size < 0)
                    {
                        fprintf(stderr,"recv data fail!\n");
                        continue;
                    }

                    ret = icmp_unpack(recv_buf, size); 
                    if(ret == -1)  
                    {
                        continue;
                    }
                    recv_count++; 
                }
                break;
        }

    }
}

void ping_stats_show()
{
    printf("%d packets transmitted, %d recieved, %d%c packet loss\n",
        send_count, recv_count, (send_count-recv_count)*100/send_count,'%');
}


int main(int argc, char* argv[])
{
    int size = 144*1024;
    struct protoent* protocol = NULL;
    char dest_addr_str[80];
    memset(dest_addr_str, 0, 80);
    unsigned int inaddr = 1;
    struct hostent* host = NULL;

    pthread_t send_id,recv_id;

    if(argc < 6)
    {
        printf("usage : ./ping IP -n counts -l length\n");
        return -1;
    }

    counts = atoi(argv[3]);
    if(atoi(argv[5]) != 0)
        icmp_length = atoi(argv[5]);

    protocol = getprotobyname("icmp"); 
    if(protocol == NULL)
    {
        printf("Fail to getprotobyname!\n");
        return -1;
    }

    memcpy(dest_addr_str, argv[1], strlen(argv[1])+1);

    rawsock = socket(AF_INET,SOCK_RAW,protocol->p_proto);
    if(rawsock < 0)
    {
        printf("Fail to create socket!\n");
        return -1;
    }

    pid = getpid();

    setsockopt(rawsock, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)); //增大接收缓冲区至128K

    bzero(&dest,sizeof(dest));

    dest.sin_family = AF_INET;

    inaddr = inet_addr(argv[1]);
    if(inaddr == INADDR_NONE)  
    {
        host = gethostbyname(argv[1]);
        if(host == NULL)
        {
            printf("Fail to gethostbyname!\n");
            return -1;
        }

        memcpy((char*)&dest.sin_addr, host->h_addr, host->h_length);
    }
    else
    {
        memcpy((char*)&dest.sin_addr, &inaddr, sizeof(inaddr));
    }
    inaddr = dest.sin_addr.s_addr;
    printf("PING %s, (%d.%d.%d.%d) %d(%d) bytes of data.\n",dest_addr_str,
        (inaddr&0x000000ff), (inaddr&0x0000ff00)>>8, 
        (inaddr&0x00ff0000)>>16, (inaddr&0xff000000)>>24,
        icmp_length,icmp_length+28);

    if(pthread_create(&send_id, NULL, (void*)ping_send, NULL))
    {
        printf("Fail to create ping send thread!\n");
        return -1;
    }

    if(pthread_create(&recv_id, NULL, (void*)ping_recv, NULL))
    {
        printf("Fail to create ping recv thread!\n");
        return -1;
    }
 
    pthread_join(send_id, NULL);
    pthread_join(recv_id, NULL);
 
    ping_stats_show();
    close(rawsock);
    return 0;
}