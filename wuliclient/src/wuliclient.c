/************************************************************************************************/
/* Copyring (C), by K.L & lcuops                                        */
/************************************************************************************************/
/**
* @file wuliclient.c
* @brief HC3 inode 7.1 protal anthenticate client
* @author K.L
* @version 1.0
* @data 2017-2-27
*/

/************************************************************************************************/
/*                                        Include Files                                         */
/************************************************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include "MD5.h"
#include <malloc.h>


/************************************************************************************************/
/*                                       Macros & Typedefs                                      */
/************************************************************************************************/
// #define _DEBUG

#define SER_ADRE      "10.0.15.103" //服务器地址
#define SER_PORT      50200         //服务器端口号
#define CALL_PORT     50101         //一开始的数据发往的端口
#define MAXDATASIZE   1024          //缓存区的最大字节
#define CHECK_ONLINE  120           //联网检测时间
#define RECV_TIMEOUT  5             //接收超时


/************************************************************************************************/
/*                                     Structre Declarations                                    */
/************************************************************************************************/
typedef struct tar_PACKET_HEAD_S
{
    unsigned char       version;
    unsigned char       type;
    unsigned char       pap_chap;
    unsigned char       rsvd;
    unsigned short int  serialNo;
    unsigned short int  reqId;
    unsigned int        userIp;
    unsigned short int  userPort;
    unsigned char       errCode;
    unsigned char       attNum;

}PACKET_HEAD_S;

/************************************************************************************************/
/*                                        Global Variables                                      */
/************************************************************************************************/
char          g_userId[15];
char          g_passwd[15];
char          g_eth_name[10];
char          userid[8];
char          UserPortInDev[31];
char          g_recv_buf[MAXDATASIZE];
char          g_packeType;
char          g_Timelimit_flag;
int           g_host_ip;
short int     g_randNum;
unsigned int  g_loginTimeOut;
unsigned int  g_offset = 0;
PACKET_HEAD_S g_packHead_s;
unsigned int  ser_infor_len;
struct sockaddr_in ser_infor_s;
struct sockaddr_in ser_addr_s;




const char   *share_key = "hello";
const char   *vertion   = "CH-7.10-0313";
const char   *ser_name  = "@huawei2.com";
const char   call_pack[]={0x02,0x64,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x05,
                          0xba,0xd3,0x4e,0x49,0x6e,0x69,0x2e,0xab,0xff,0xd8,0x9e,0xca,0x49,0x9b,0xba,0xcb,
                          0x68,0x06,0x00,0x00,0x00,0x00,0x67,0x06,0x00,0x00,0x00,0x00,0x65,0x09,0x68,0x75,
                          0x61,0x33,0x63,0x6f,0x6d,0x66,0x09,0x68,0x75,0x61,0x33,0x63,0x6f,0x6d,0x71,0x06,
                          0x02,0xbd,0xc0,0x70};

const char   heartData[]={0x7a,0x06,0x00,0x00,0x00,0x00,0x78,0x06,0x00,0x00,0x00,0x01,0x7d,0x03,0x63,0x60,
                          0x03,0x01}   ;


//tmp
const char   E_vertion[]={0x01,0x1e,0x4d,0x47,0x73,0x4f,0x48,0x78,0x6f,0x45,0x50,0x79,0x74,0x79,0x52,0x78,
                          0x78,0x68,0x4a,0x31,0x5a,0x79,0x49,0x73,0x52,0x64,0x59,0x30,0x73,0x3d};

const char  E_vertion2[]={0x06,0x07,0x4f,0x7a,0x64,0x56,0x54,0x55,0x68,0x66,0x59,0x79,0x42,0x35,0x47,0x30,
                          0x63,0x7a,0x64,0x51,0x30,0x75,0x4b,0x52,0x48,0x54,0x4f,0x55,0x30,0x3d};

const char  E_password[]={0x9a,0x4f,0x87,0x04,0x0b,0x9b,0xdc,0x23};





/************************************************************************************************/
/*                                     Function Declarations                                    */
/************************************************************************************************/
/* NONE */

void free_memory(char *addr)
{
    if(NULL != addr){
        free(addr);
    }
}

void MD5(unsigned char *dst_str , unsigned char *src_str ,int leng)
{
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx,src_str,leng);
    MD5_Final(dst_str,&ctx);
}

int addMd5(char *data,int len)
{
    char *md5Data = NULL;
    char md5Code[16] = {0x000};


    md5Data = (char*)malloc(sizeof(char)*(len+5));
    if(NULL == md5Data){
        printf("malloc error\n");
        return -1;
    }

    memcpy(md5Data, data, g_offset);
    memcpy(md5Data+g_offset, share_key , 5);  //add share_key
    MD5(md5Code, md5Data, (g_offset + 5));
    memcpy(data+16, md5Code, 16);

    free_memory(md5Data);

    return 0;

}


void disp_hex(unsigned char *data, int len)
{
    int cnt;
    for(cnt=0; cnt<len; cnt++)
    {
        printf("%02x",data[cnt]);
    }
}

int getHostIP(void)
{
    int sockfd;
    struct sockaddr_in sin;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1){
    perror("socket");
    return -1;
    }

    strncpy(ifr.ifr_name, g_eth_name, IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = 0;

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0)
    {
    perror("ioctl");
    close(sockfd);
    return -1;
    }

    memcpy(&sin, &ifr.ifr_addr, sizeof(sin));
    g_host_ip = sin.sin_addr.s_addr;
    close(sockfd);
    return 0;
}


void packetHeadBuil(char *_pdst)
{
    *(_pdst)         = g_packHead_s.version;
    *(_pdst+1)       = g_packHead_s.type;
    *(_pdst+2)       = g_packHead_s.pap_chap;
    *(_pdst+3)       = g_packHead_s.rsvd;
    *(_pdst+14)      = g_packHead_s.errCode;
    *(_pdst+15)      = g_packHead_s.attNum;
    memcpy((_pdst+4), &g_packHead_s.serialNo,2);
    memcpy((_pdst+6), &g_packHead_s.reqId,2);
    memcpy((_pdst+8), &g_packHead_s.userIp,4);
    memcpy((_pdst+12),&g_packHead_s.userPort,2);
}

void attData_add(const unsigned char *src, unsigned char flag, unsigned char len, unsigned char *dst)
{
    unsigned char len2;
    len2 = len + 2;
    memcpy(dst+g_offset,   &(flag), 1);
    memcpy(dst+g_offset+1, &(len2), 1);
    memcpy(dst+g_offset+2, src,     len);
    g_offset +=  len2;
}

int sentAndRecv(char *_data, unsigned int _len)
{
    int ret;
    int sockfd;
    struct timeval timeo = {3, 0};
    socklen_t t_len;

    /*set server's address */
    bzero( &ser_addr_s,        sizeof(ser_addr_s) );
    ser_addr_s.sin_port        = htons(SER_PORT);
    ser_addr_s.sin_family      = AF_INET;
    ser_addr_s.sin_addr.s_addr = inet_addr(SER_ADRE);


    /* creat a sock */
    t_len           = sizeof(timeo);
    sockfd          = socket(AF_INET,SOCK_DGRAM,0);
    timeo.tv_sec    = RECV_TIMEOUT;
    ret = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeo, t_len); //set receive time out
    if(-1 == sockfd && !ret){
        printf("creat and set a socket error\n");
        perror("socket");
        return -1;
    }

    /* sent to data */
    ret = sendto(sockfd, _data, _len, 0, (struct sockaddr *)&ser_addr_s, sizeof(ser_addr_s));
    if(_len != ret){
        printf("sent error.return value:%d!\n",ret);
        return -1;
    }
    #ifdef _DEBUG
    printf("(----sent-to-data-----[len]=%d)\n",_len);
    disp_hex(_data,_len);
    printf("\n");
    #endif


    /* Receive the message */
    #ifdef _DEBUG
    printf("(--Wating-for-server's-answer--)\n");
    #endif
    memset(g_recv_buf,0,sizeof(g_recv_buf));
    ret = recvfrom(sockfd,g_recv_buf,sizeof(g_recv_buf),
                    0,(struct sockaddr *)&ser_infor_s,&ser_infor_len);

    close(sockfd);
    if(-1 == ret){
        if(errno == EAGAIN){                         //time out
             printf("Recevce time out \n");
             return -1;
         }
        perror("recvfrom");
        return -1;
    }
    #ifdef _DEBUG
    printf("Server return information:[len]=%d \n",ret);
    disp_hex(g_recv_buf,ret);
    printf("\n");
    #endif
    return 0;
}


int packetAnalyze()
{
    /* check the packet md5 code */
    //neet to add check_md5()function

    g_packeType = g_recv_buf[1];

    /* check the errocode */
    if(g_recv_buf[14] != 0){
        return g_recv_buf[14];
    }


    /* check the type */
    //need to something
    switch(g_recv_buf[1]){

       case 0x6f:{
            //get userid from server
            memcpy(userid,(g_recv_buf+34),sizeof(userid));
            #ifdef _DEBUG
            printf("[set]--userid--\n");
            disp_hex(userid,sizeof(userid));
            printf("\n");
            #endif
            return 0;
        }
        case 0x65:{
            if( *(g_recv_buf+15) == 0x0d ){
                //get userportdev from server and success
                memcpy(UserPortInDev,(g_recv_buf+148),sizeof(UserPortInDev));

                //get login time out
                memcpy(&g_loginTimeOut,(g_recv_buf+103),4);

                #ifdef _DEBUG
                printf("[set]--UserPortInDev--\n");
                disp_hex(UserPortInDev,sizeof(UserPortInDev));
                printf("\n");
                printf("[LoginTimeOut:%d]\n",g_loginTimeOut);
                #endif
            }
            return 0;
        }

        case 0x69:{        //heartbeat
            return 0;
        }

        default : return 0;
    }
}


int getSerInfor()
{
    int ret;
    char md5Code[16] = {0x000};
    unsigned char *data = NULL;

    #ifdef _DEBUG
    printf("----get server information----\n");
    #endif

    data = (char*)malloc(sizeof(char)*44);
    if(NULL == data){
        printf("malloc error\n");
        return -1;
    }
    memset(data, 0, 44);


    /* set head information */
    memset(&g_packHead_s,0,sizeof(g_packHead_s));
    g_packHead_s.version   = 0x02;
    g_packHead_s.type      = 0x6e;
    g_packHead_s.serialNo  = g_randNum;
    g_packHead_s.userIp    = g_host_ip;
    g_packHead_s.attNum    = 0x02;
    packetHeadBuil(data);

    /* set att data */
    g_offset = 32 ;
    attData_add((char *)&g_host_ip, 0x67, sizeof(g_host_ip),data);
    attData_add((char *)&g_host_ip, 0x68, sizeof(g_host_ip),data);


    /* set MD5 code */
    ret = addMd5(data,g_offset);
    if(ret){

        free_memory(data);
        return -1;
    }

    /* sent request to server */
    ret = sentAndRecv(data,g_offset);
    if(-1 == ret){
        free_memory(data);
        return -1;
    }

    /* analyze packet message*/
    ret = packetAnalyze();
    if(0 != ret && g_packeType == 0x6f){
        // need to add analyze_error() function
        /* free memory */
        free_memory(data);
        return ret;
    }

    free_memory(data);
    return 0;
}

int sentReqPacket()
{
    int ret;
    time_t nowTime;
    char   interval;
    unsigned char *data    = NULL;
    unsigned char *IDdata  = NULL;


    #ifdef _DEBUG
    printf("--sent userID and password---\n");
    #endif

    data = (char*)malloc(sizeof(char)*153);
    if(NULL == data){
        printf("malloc error\n");
        return -1;
    }
    memset(data, 0, 153);

    /* set head information */
    memset(&g_packHead_s,0,sizeof(g_packHead_s));
    g_packHead_s.version   = 0x02;
    g_packHead_s.pap_chap  = 0x01;
    g_packHead_s.type      = 0x64;
    g_packHead_s.serialNo  = g_randNum;
    g_packHead_s.userIp    = g_host_ip;
    g_packHead_s.attNum    = 0x07;
    packetHeadBuil(data);


    /* set att data */
    IDdata = (char*)malloc(sizeof(char)*56);//store E_vertiong & userID
    if(NULL == IDdata){
        printf("malloc error\n");
        return -1;
    }
    g_offset = 0;
    memcpy(IDdata,   E_vertion2,    sizeof(E_vertion2));
    g_offset += sizeof(E_vertion2);
    interval  = 0x20;
    memcpy(IDdata+g_offset, &interval,               1);
    g_offset ++;
    memcpy(IDdata+g_offset, &interval,               1);
    g_offset ++;
    memcpy(IDdata+g_offset, g_userId, strlen(g_userId));
    g_offset += strlen(g_userId);
    memcpy(IDdata+g_offset, ser_name,               12);

    g_offset = 32 ;
    interval = 0x01;
    attData_add(E_vertion,          0x21, sizeof(E_vertion), data);
    attData_add((char *)&g_host_ip, 0x68, sizeof(g_host_ip), data);
    attData_add((char *)&g_host_ip, 0x67, sizeof(g_host_ip), data);
    attData_add(IDdata,             0x65, 56,                data);
    attData_add(E_password,         0x66, sizeof(E_password),data);
    attData_add(&interval,          0x38, 1,                 data);
    nowTime = time(NULL);      // timestamp
    nowTime = htonl(nowTime);  //chang to net format
    attData_add((unsigned char *)&nowTime, 0x71, 4, data);


    /* set MD5 code */
    ret = addMd5(data,g_offset);
    if(ret){
        free_memory(data);
        free_memory(IDdata);
        return -1;
    }



    /* sent request to server */
    ret = sentAndRecv(data,g_offset);
    if(-1 == ret){
        free_memory(data);
        free_memory(IDdata);
        return -1;
    }

    /* analyze packet message*/
    ret = packetAnalyze();
    if(0 != ret && g_packeType == 0x65){

        /* free memory */
        free_memory(data);
        free_memory(IDdata);
        return ret;
    }

    /* free the memory */
    free_memory(data);
    free_memory(IDdata);
    printf("log in sucess!\n");

    return 0;
}

int call_packet()
{
    int ret;
    int sockfd;
    struct timeval timeo = {3, 0};
    socklen_t t_len;

    /*set server's address */
    bzero( &ser_addr_s,        sizeof(ser_addr_s) );
    ser_addr_s.sin_port        = htons(CALL_PORT);
    ser_addr_s.sin_family      = AF_INET;
    ser_addr_s.sin_addr.s_addr = inet_addr(SER_ADRE);


    /* creat a sock */
    t_len           = sizeof(timeo);
    sockfd          = socket(AF_INET,SOCK_DGRAM,0);
    timeo.tv_sec    = RECV_TIMEOUT;
    ret = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeo, t_len); //set receive time out
    if(-1 == sockfd && !ret){
        printf("creat and set a socket error\n");
        perror("socket");
        return -1;
    }

    /* sent data */
    ret = sendto(sockfd, call_pack, sizeof(call_pack),
                 0, (struct sockaddr *)&ser_addr_s, sizeof(ser_addr_s));

    close(sockfd);
    if(sizeof(call_pack) != ret){
        printf("sent error.return value:%d!\n",ret);
        return -1;
    }

   return 0;
}

int sentLogReq()
{
    int ret;
    int cnt;

    /* sent call_packet twice */

    #ifdef _DEBUG
    printf("sent-call_packet\n");
    #endif
    for(cnt=0; cnt<2; cnt++){
        ret = call_packet();
        if(-1 == ret){
            return -1;
        }

    }

    usleep(500);

    /* get server information */
    ret = getSerInfor();
    if(0 != ret){
        return -1;

    }

    /* sent logReqPacket */
    ret = sentReqPacket();
    return ret;

}

int sentLogoutReq()
{
    int ret;
    unsigned char *data  = NULL;


    data = (char*)malloc(sizeof(char)*54);
    if(NULL == data){
        printf("malloc error\n");
        return -1;
    }
    memset(data, 0, 54);

    /* set head information */
    memset(&g_packHead_s,0,sizeof(g_packHead_s));
    g_packHead_s.version   = 0x02;
    g_packHead_s.type      = 0x66;
    g_packHead_s.serialNo  = g_randNum;
    g_packHead_s.userIp    = g_host_ip;
    g_packHead_s.attNum    = 0x03;
    packetHeadBuil(data);

    /* add data */
    g_offset = 32 ;
    attData_add((char *)&g_host_ip, 0x68, sizeof(g_host_ip), data);
    attData_add((char *)&g_host_ip, 0x67, sizeof(g_host_ip), data);
    attData_add(userid,             0x64, sizeof(userid),    data);

    /* set MD5 code */
    ret = addMd5(data,g_offset);
    if(ret){
        free_memory(data);
        return -1;
    }

    /* sent request to server */
    ret = sentAndRecv(data,g_offset);
    if(-1 == ret){
        free_memory(data);
        return -1;
    }

    /* analyze packet message*/
    ret = packetAnalyze();
    if(0 != ret && g_packeType == 0x67){

        /* free memory */
        free_memory(data);
        return ret;
    }

    /* free the memory */
    free_memory(data);

    return 0;

}

int startHeartbeatthread()
{
    int ret;
    time_t nowTime;
    char *data = NULL;

    data = (char*)malloc(sizeof(char)*123);
    if(NULL == data){
        printf("malloc error\n");
        return -1;
    }
    memset(data, 0, 123);

    /* set head information */
    memset(&g_packHead_s,0,sizeof(g_packHead_s));
    g_packHead_s.version   = 0x02;
    g_packHead_s.type      = 0x68;
    g_packHead_s.pap_chap  = 0x01;
    g_packHead_s.serialNo  = g_randNum;
    g_packHead_s.userIp    = g_host_ip;
    g_packHead_s.attNum    = 0x0b;
    packetHeadBuil(data);

    /* set att data */
    g_offset = 32;
    attData_add((char *)&g_host_ip, 0x7f, sizeof(g_host_ip),     data);
    attData_add((char *)&g_host_ip, 0x7e, sizeof(g_host_ip),     data);
    attData_add((char *)&g_host_ip, 0x68, sizeof(g_host_ip),     data);
    attData_add((char *)&g_host_ip, 0x67, sizeof(g_host_ip),     data);
    attData_add(UserPortInDev,      0x72, sizeof(UserPortInDev), data);
    attData_add(userid,             0x64, sizeof(userid),        data);
    nowTime = time(NULL);      // timestamp
    nowTime = htonl(nowTime);  //chang to net format
    attData_add((unsigned char *)&nowTime, 0x71, 4, data);
    memcpy((data+g_offset),heartData,sizeof(heartData));
    g_offset += sizeof(heartData);

        /* set MD5 code */
    ret = addMd5(data,123);
    if(ret){
        free_memory(data);
        return -1;
    }


    /* sent request to server */
    #ifdef _DEBUG
    printf("-----heartbeat-packet-------\n");
    #endif
    ret = sentAndRecv(data,123);
    if(-1 == ret){
        free_memory(data);
        return -1;
    }

    /* analyze packet message*/
    ret = packetAnalyze();
    if(0 != ret){
        // need to add analyze_error() function
        /* free memory */
        free_memory(data);
        return ret;
    }

    /* free the memory */
    free_memory(data);
    return 0;

}

int authenticate()
{
    int ret;
    int cnt;


    /* get host IP address */
    ret = getHostIP();
    if(-1 == ret){
        printf("get ip fail.\n");
        printf("You might not be connected cables\n");
        return -1;
    }
    #ifdef _DEBUG
    printf("ip:%02x\n",g_host_ip);
    #endif


    /* Ready for log in */
    do{
        ret = sentLogReq();


        if(  ret == 0) {
            break;
        }

        /* Analyze ERROR code*/
        else if( ret == 2 ){
            printf("Checked serialNo Inconsistent with previous\n");
            printf("Start to re-login\n");
            sentLogoutReq();
            sleep(2);
            continue;
        }
        else if(ret == 1)
        {
            if(0x19 == g_recv_buf[33]){
                printf("In to Limit of time\n");
                printf("Try to login again after 5 mintues\n");
                sleep(300);
                return -1;
            }

            else if(0x26 == g_recv_buf[33]){
                printf("!!!! Password ERROR,please don't try again !!!!!!!!!\n");
                exit(0);
            }

            else if(0x21 == g_recv_buf[33]){
                printf("Vlan bind fail,Maybe your id is not correct.\n");
                exit(0);
            }

            else if(0x20 == g_recv_buf[33]){
                printf("Your Mac address not correct.\n");
                exit(0);
            }


        }

        else if(ret == 3){
            return -1;
        }

        else{
            printf("log in error!\n");
            printf("ErrorCode:%d\n",(unsigned int)ret);
            printf("5 second re-log in\n");
            sleep(5);
        }

    }while(1);


    printf("Welcome to ZHBIT net!\n");

    /* check Server's login time out */
    if(g_loginTimeOut == 0){  //Server dose not require heartbeatpacket

        do{
                /* check whether can surf the internet by ping command*/
                ret = system("ping -c 2 114.114.114.114");
                if( 256 == ret){
                    printf("Can't ping to 114.114.114.114\n");
                    return -1;
                }
                printf("-----【Online】------\n");
                sleep(CHECK_ONLINE);

        }while(1);

    }


    /* start heartbeat packet */
    else if(g_loginTimeOut > 1000){ //    > 1 second

        do{
            sleep(g_loginTimeOut);
            ret = startHeartbeatthread();
            if(ret){
                break;
            }
        }
        while(1);

    }


}


int main(int argc, char *argv[])
{
     if(argc != 4){
        printf("输入账号密码错误,请重新输入\n");
        printf("格式：wuliclient 账号 密码 网卡名\n");
        printf("(目前只支持密码为默认密码：1234)\n");
        return -1;
     }

     if( strcmp(argv[2], "1234") ){
         printf("抱歉，目前密码只支持默认密码1234\n");
         return -1;
     }

    printf("-----------------------------------------\n");
    printf("WULICLIENT OF ZHBIT\n");
    printf("定制号：%s\n",g_userId);
    printf("【声明】\n");
    printf("本版本仅作为学习交流之用，请于24小时内删除\n");
    printf("创作者：K.L & lcuops\n");
    printf("---------欢迎反馈问题---------\n");
    printf("反馈/交流 Email: kuling321@qq.com\n");
    printf("-----------------------------------------\n");


    strcpy(g_userId,   argv[1]);
    strcpy(g_passwd,   argv[2]);
    strcpy(g_eth_name, argv[3]);
    #ifdef _DEBUG
    printf("userid:%s\n",g_userId);
    printf("passwd:%s\n",g_passwd);
    #endif



    do{

        /* get random number for serialNo of this connet */
        srand(time(NULL));
        g_randNum = rand();
        #ifdef _DEBUG
        printf("randNum: ");
        disp_hex((char *)&g_randNum, 2);
        printf("\n");
        #endif

        /* start authenticate */
        authenticate();
        sleep(3);

    }while(1);


    return 0;
}

