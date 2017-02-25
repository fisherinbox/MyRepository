/*
	Copyright (c) 2013-2014 EasyDarwin.ORG.  All rights reserved.
	Github: https://github.com/EasyDarwin
	WEChat: EasyDarwin
	Website: http://www.EasyDarwin.org
	配置文件第一行为推送数据的网卡编号；第二行为当前采集主机的视频路数偏移；第三行开始为视频源url，视频路数取决于第三行开始有多少大于10个字符的行
	包计数日志更新到160路
*/
#include <stdio.h>
#include "pcap.h"
#include "Win32-Extensions.h"
#include <windows.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <list>
#include "concurrent_queue.h"
#include "EasyPusherAPI.h"
#include "EasyRTSPClientAPI.h"
#include "gettime.h"
using namespace std;
//#pragma comment(linker,"/subsystem:windows /ENTRY:mainCRTStartup")

#pragma pack(1)
#define MAX_STREAM_COUNT  300					//最大视频路数
#define MAX_DATA_LENGTH 1474					//包数据部分的最大长度
#define MEM_MAX_AVAILABLE 10000					//最大可分配内存数量，给每一个包分配内存时使用
#define MAX_PACKET_LEN 1514						//数据包最大总长度
#define MEDIA_LENGTH 40							//媒体信息包长度
#define MEDIA_SEND_INTERVAL	5000				//媒体信息包发送循环时间间隔（毫秒）
typedef struct  {
	char SNAME[64];			//
	char RTSPURL[128];		//rtsp来源url
	char SHOST[32];			//推送去的目的 darwin server
	unsigned short SPORT;	
} RTSP_CJ;
typedef struct
{
	Easy_U32    u32VFrameType;		/* 视频的类型，I帧或P帧 */
	Easy_U32    u32AVFrameLen;		/* 帧的长度 */
	Easy_U32    u32AVFrameFlag;		/* 帧标志  视频 or 音频 */    
	Easy_U32	u32TimestampSec;	/* 时间戳(秒)*/
	Easy_U32	u32TimestampUsec;	/* 时间戳(微秒) */   
} AVFRAME_HEADER;
typedef struct
{
	Easy_U32 u32VideoCodec;			/* 视频编码类型 */
	Easy_U32 u32VideoFps;			/* 视频帧率 */
	Easy_U32 u32AudioCodec;			/* 音频编码类型 */
	Easy_U32 u32AudioSamplerate;	/* 音频采样率 */
	Easy_U32 u32AudioChannel;		/* 音频通道数 */
} MEDIAINFO_HEADER;   //没有用到这个
union  HEADER_BY {
	AVFRAME_HEADER avframe;
	EASY_MEDIA_INFO_T mediainfo;
};
typedef struct
{
	unsigned short streamID;				//第几路
	unsigned char  mediainfo_or_avframe;	//0: mediainfo;  1: avframe ; 2:auframe
	unsigned short offset;					//包偏移量
	unsigned char endFlag;					//结束标志位  0：不是此帧的最后一个包 1：此帧的最后一个包
	union  HEADER_BY  header;
    Easy_U8     data[MAX_DATA_LENGTH];		/* 数据 */
} EASY_AV_Frame_BY;     
typedef struct  {
char RTSPURL[128];		//rtsp来源url

char SHOST[32];			//推送去的目的 darwin server
unsigned short SPORT;	
char SNAME[64];			//

Easy_Pusher_Handle fPusherHandle;
//char* fPusherHandle;
Easy_RTSP_Handle fRTSPHandle;
EasyPusher_Callback pusher_callback;
RTSPSourceCallBack source_callback;
EASY_PUSH_STATE_T _state;
} PUSH_RTSP_STU;

PUSH_RTSP_STU  g_stu[MAX_STREAM_COUNT];
EASY_AV_Frame_BY* gp_avFrame[MAX_STREAM_COUNT];
int g_count_mediainfo = 0;
DWORD lastTime = 0;
DWORD curTime = 0;
DWORD interval = 0;
static int packetCount = 0;
FILE *fp;					//日志文件
FILE *fp2;					//日志文件
FILE *fp3;					//日志文件
FILE *video;
int INUM = 0;			    //配置文件中第一行网卡编号
int OFFSET = 0;				//配置文件中第二行视频路数偏移
int syn = 0;				//选择同步或异步发送方式（1 == 同步，0 == 异步）
int dus = 20;               //每个包的发送时间间隔（us）
bool g_exit_app = false;	//用户控制退出
int frameCount[300] = {0};		//记录每一路的包数量，每十秒打印一次并清零，已经覆盖到第80路
HANDLE hMutex;				//控制打印资源
pcap_t *adhandle = NULL;	//标志发送网卡的句柄
bool g_bAllThreadStop = false;
const unsigned int npacks=1000;
static DWORD MemAllocated = 0;
pcap_send_queue *pcap_squeue=NULL;					//发送队列
pcap_send_queue *pcap_media = NULL;		
boost::mutex pool_mutex;
boost::mutex mediaList_mutex;
boost::mutex frameCount_mutex[300];					//包计数的锁
concurrent_queue<EASY_AV_Frame_BY *> frameQueue;	//待发送包队列
list<EASY_AV_Frame_BY *> memory_pool;				//包内存分配池
std::list<EASY_AV_Frame_BY *> mediaInfoList;		//媒体信息存储列表，供循环发送使用
unsigned char* frame_packet;
timeval add_stamp(timeval *ptv,unsigned int dus);
void send_queue(pcap_t *fp);
bool init_pcap_queue(int min_count);				//给发送队列分配内存，参数为队列中包个数
extern void push_pcap_queue();
DWORD WINAPI run(LPVOID lpParam);					//pcap接收和rtsp回调主线程
DWORD WINAPI sendMediaInfo(LPVOID lpParam);			//媒体信息包发送线程
DWORD WINAPI printLog(LPVOID lpParam);				//日志打印线程
int initRTSP( PUSH_RTSP_STU* pSTU);
void initConfig();
void finitRTSP( PUSH_RTSP_STU* pSTU);
void PutMemToPool(EASY_AV_Frame_BY* p);
EASY_AV_Frame_BY* GetMemFromPool();
int Easy_APICALL __RTSPSourceCallBack000( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack001( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack002( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack003( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack004( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack005( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack006( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack007( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack008( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack009( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack010( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack011( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack012( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack013( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack014( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack015( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack016( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack017( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack018( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack019( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack020( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack021( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack022( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack023( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack024( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack025( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack026( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack027( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack028( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack029( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack030( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack031( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack032( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack033( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack034( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack035( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack036( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack037( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack038( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack039( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack040( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack041( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack042( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack043( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack044( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack045( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack046( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack047( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack048( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack049( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack050( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack051( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack052( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack053( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack054( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack055( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack056( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack057( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack058( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack059( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack060( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack061( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack062( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack063( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack064( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack065( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack066( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack067( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack068( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack069( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack070( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack071( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack072( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack073( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack074( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack075( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack076( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack077( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack078( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack079( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack080( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack081( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack082( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack083( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack084( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack085( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack086( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack087( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack088( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack089( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack090( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack091( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack092( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack093( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack094( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack095( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack096( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack097( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack098( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack099( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack100( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack101( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack102( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack102( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack103( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack104( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack105( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack106( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack107( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack108( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack109( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack110( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack111( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack112( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack113( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack114( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack115( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack116( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack117( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack118( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack119( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack120( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack121( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack122( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack123( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack124( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack125( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack126( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack127( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack128( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack129( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack130( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack131( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack132( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack133( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack134( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack135( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack136( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack137( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack138( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack139( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack140( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack141( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack142( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack143( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack144( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack145( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack146( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack147( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack148( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack149( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack150( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack151( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack152( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack153( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack154( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack155( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack156( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack157( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack158( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack159( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack160( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack161( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack162( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack163( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack164( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack165( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack166( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack167( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack168( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack169( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack170( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack171( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack172( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack173( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack174( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack175( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack176( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack177( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack178( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack179( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack180( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack181( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack182( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack183( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack184( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack185( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack186( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack187( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack188( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack189( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack190( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack191( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack192( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack193( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack194( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack195( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack196( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack197( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack198( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack199( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack200( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack201( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack202( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack203( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack204( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack205( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack206( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack207( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack208( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack209( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack210( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack211( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack212( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack213( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack214( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack215( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack216( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack217( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack218( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack219( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack220( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack221( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack222( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack223( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack224( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack225( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack226( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack227( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack228( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack229( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack230( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack231( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack232( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack233( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack234( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack235( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack236( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack237( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack238( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack239( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack240( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack241( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack242( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack243( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack244( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack245( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack246( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack247( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack248( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack249( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack250( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack251( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack252( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack253( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack254( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack255( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack256( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack257( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack258( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack259( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack260( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack261( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack262( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack263( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack264( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack265( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack266( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack267( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack268( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack269( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack270( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack271( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack272( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack273( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack274( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack275( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack276( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack277( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack278( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack279( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack280( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack281( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack282( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack283( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack284( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack285( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack286( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack287( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack288( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack289( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack290( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack291( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack292( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack293( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack294( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack295( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack296( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack297( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack298( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
int Easy_APICALL __RTSPSourceCallBack299( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo);
unsigned int GetCrc32(char* pdata,unsigned int len){   
    //生成Crc32的查询表
    unsigned int Crc32Table[256]; 
    int i,j;   
    unsigned int Crc;   
    for (i = 0; i < 256; i++){   
        Crc = i;   
        for (j = 0; j < 8; j++){   
            if (Crc & 1)   
                Crc = (Crc >> 1) ^ 0xEDB88320;   
            else  
                Crc >>= 1; 
        }   
        Crc32Table[i] = Crc;   
    }   
    //开始计算CRC32校验值
    Crc=0xffffffff;   
    for(int i=0; i<len; i++)
    {     
        Crc = (Crc >> 8) ^ Crc32Table[(Crc & 0xFF) ^ pdata[i]];   
    }
    
    Crc ^= 0xFFFFFFFF;
    return Crc;   
}   
static const unsigned short Crc16Table[256] = 
{                      
    0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241, 
    0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440, 
    0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40, 
    0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841, 
    0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40, 
    0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41, 
    0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641, 
    0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040, 
    0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240, 
    0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441, 
    0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41, 
    0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840, 
    0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41, 
    0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40, 
    0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640, 
    0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041, 
    0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240, 
    0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441, 
    0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41, 
    0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840, 
    0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41, 
    0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40, 
    0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640, 
    0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041, 
    0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241, 
    0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440, 
    0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40, 
    0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841, 
    0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40, 
    0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,  
    0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641, 
    0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040 
};

//生成Crc16的查询表
void GetCrc16Table()
{   
    unsigned short crc16tbl[256]; 
    unsigned int i,j;
    unsigned short Crc;
//    printf("unsigned short Crc16Table[256] = \r\n{\r\n");
    for (i = 0; i < 256; i++) {  
        Crc = i;   
        for (j = 0; j < 8; j++) {   
            if(Crc & 0x1)   
                Crc = (Crc >> 1) ^ 0xA001;   
            else  
                Crc >>= 1; 
            
        }
//        printf("0x%04X,",Crc);
        if ((i+1)%8==0)
        {
            printf("\r\n");
        }
        crc16tbl[i] = Crc;
    }
//    printf("};\r\n");
}
unsigned short GetCrc16(char* pdata,unsigned int len)
{   
    //开始计算CRC16校验值
    unsigned short crc16=0x0000;       
    for(int i=0; i<len; i++){     
        crc16 = (crc16 >> 8) ^ Crc16Table[(crc16 & 0xFF) ^ pdata[i]];  
    }
    //Crc ^= 0x0000;  
    return crc16;   
}  
unsigned short get_crc16 (unsigned char *bufData, unsigned int buflen, unsigned char *pcrc,FILE *fp)  
{  
    int ret = 0;  
    unsigned short CRC = 0xffff;  
    unsigned short POLYNOMIAL = 0xa001;  
    int i, j;  
  
  
    if(bufData == NULL || pcrc == NULL)  
    {  
        return -1;  
    }  
  
    if (buflen == 0)  
    {  
        return ret;  
    }  
    for (i = 0; i < buflen; i++)  
    {  
        CRC ^= bufData[i];  
        for (j = 0; j < 8; j++)  
        {  
            if ((CRC & 0x0001) != 0)  
            {  
                CRC >>= 1;  
                CRC ^= POLYNOMIAL;  
            }  
            else  
            {  
                CRC >>= 1;  
            }  
        }  
    }   
    fprintf (fp,"\t%X\n", CRC);  
    pcrc[0] = (unsigned char)(CRC & 0x00ff);  
    pcrc[1] = (unsigned char)(CRC >> 8);  
  
    return ret;  
}  
int main()
{
	//GetCrc16Table();
	fp = fopen("cjlog.txt","w");
	//fp2 = fopen("cjlog2.txt","w");
	//video = fopen("video.264","wb");
	frame_packet = (unsigned char*)malloc(MAX_PACKET_LEN);
	//初始化
	for(int i=0;i<MAX_STREAM_COUNT;i++)
	{
		memset(&g_stu[i], 0, sizeof( PUSH_RTSP_STU));
		gp_avFrame[i] = new EASY_AV_Frame_BY;
	}
	//MAX_STREAM_COUNT 路视频的 回掉函数 设置
	//读配置 文件 ，根据 设置的 N 路配置项 ，启动 N 路视频流的拉取和推送
	initConfig();

	HANDLE hThread = CreateThread(NULL, 0, run, NULL, 0, NULL);
	HANDLE hThread_sendMedia = CreateThread(NULL, 0, sendMediaInfo, NULL, 0, NULL);
	HANDLE hThread_print = CreateThread(NULL, 0, printLog, NULL, 0, NULL);
	for(int i=0;i<MAX_STREAM_COUNT;i++)
	{
		initRTSP(&g_stu[i]);
	}
	int count = 0;
//	fprintf(fp,"/*-------------*/\n");
	getchar();
/*	while( !g_exit_app )
	{
		//if(count > 100)
		//{
		//	g_bAllThreadStop = true;
		//	break;
		//}
		//else
		//{
		//	count++;
		//}
		//查看 哪一路视频 异常 ，则 注销/重新启动
		//for(int i=0;i<PUSHER_NUM;i++)
		//{
		//	if( (g_stu[i]._state == EASY_PUSH_STATE_DISCONNECTED)||(g_stu[i]._state == EASY_PUSH_STATE_CONNECT_FAILED)||(g_stu[i]._state == EASY_PUSH_STATE_CONNECT_ABORT) )
		//	{
		//		finitRTSP(&g_stu[i]);
		//		initRTSP(&g_stu[i]);
		//	}
		//}
		//for(int i = 0;i<300;i++)
		//{			
		//	fprintf(fp,"%d\n",frameCount[i]);
		//	frameCount[i] = 0;
		//}
		//fprintf(fp,"/-------------/\n");
		Sleep(100);
	}*/
	fclose(fp);
	//清理 N 路视频流的 资源
	for(int i=0;i<MAX_STREAM_COUNT;i++)
	{
		finitRTSP(&g_stu[i]);
	}
	free(frame_packet);
//	std::cout<<"packetCount: "<<packetCount<<endl;
//	getchar();
	return 0;
}
DWORD WINAPI run(LPVOID lpParam)
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i=0;
    char errbuf[PCAP_ERRBUF_SIZE];
//    WaitForSingleObject(hMutex, INFINITE);
   
	if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL,&alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs:%s\n", errbuf);
        exit(1);
    }
   
   
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }
   
    if(i==0)
    {
        printf("\nNo interfaces found!Make sure WinPcap is installed.\n");
        return -1;
    }
 
   
//    printf("Enter the interface number (1-%d):",i);
//    scanf("%d", &INUM);
   
    if(INUM < 1 || INUM > i)
    {
        printf("\nInterface number out of range.\n");
       
        pcap_freealldevs(alldevs);
        return -1;
    }
   
   
    for(d=alldevs, i=0; i< INUM-1 ;d=d->next, i++);
   
   
if ( (adhandle= pcap_open(d->name, 65536,PCAP_OPENFLAG_PROMISCUOUS, 1000,NULL, errbuf  ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter.%s is not supported by WinPcap\n", d->name);
       
        pcap_freealldevs(alldevs);
        return -1;
    } 
   
    printf("\nlistening on %s...\n", d->description);
//	ReleaseMutex(hMutex);   
    

	while(!g_bAllThreadStop){
		//if(frameQueue.empty())
		//{
		//	continue;
		//}
		frameQueue.wait_and_push_allitem_to_pcapqueue();
		send_queue(adhandle);
	}
	pcap_close(adhandle);
    pcap_freealldevs(alldevs);
	
	OutputDebugStringA("run() exit...\n");
	return 0;
			
}
DWORD WINAPI sendMediaInfo(LPVOID lpParam)
{
	while(1)
	{
		if(adhandle!=NULL)
		{
			for(int i=OFFSET; i<=g_count_mediainfo+OFFSET; i++)
			{
				//从 queue 的头部取出1个元素
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame!=NULL)
				{
					boost::mutex::scoped_lock lock(mediaList_mutex);
					memcpy(p_avFrame, gp_avFrame[i], sizeof(EASY_AV_Frame_BY));
					lock.unlock();
					frameQueue.push(p_avFrame);
				}
			}
		}		
		Sleep(MEDIA_SEND_INTERVAL);
	}
	return 0;
}
DWORD WINAPI printLog(LPVOID lpParam)
{
	while(1)
	{
		for(int i = 0;i<g_count_mediainfo;i++)
		{		
			//if(i > 0 && i%20 == 0)
			//{
			//	fprintf(fp,"\n");
			//}	
			boost::mutex::scoped_lock lock(frameCount_mutex[i]);
			//fprintf(fp,"%d\t",frameCount[i]);
			frameCount[i] = 0;
			lock.unlock();
		}
		//time_t t;
		//time(&t);
		//fprintf(fp,"\n%d \n",t);
		//fflush(fp);  //刷新缓冲区，以便快速查看打印内容
		Sleep(10000);
	}
}
void initConfig()
{
	g_stu[0].source_callback = __RTSPSourceCallBack000;
	g_stu[1].source_callback = __RTSPSourceCallBack001;	
	g_stu[2].source_callback = __RTSPSourceCallBack002;
	g_stu[3].source_callback = __RTSPSourceCallBack003;
	g_stu[4].source_callback = __RTSPSourceCallBack004;
	g_stu[5].source_callback = __RTSPSourceCallBack005;
	g_stu[6].source_callback = __RTSPSourceCallBack006;
	g_stu[7].source_callback = __RTSPSourceCallBack007;
	g_stu[8].source_callback = __RTSPSourceCallBack008;
	g_stu[9].source_callback = __RTSPSourceCallBack009;
	g_stu[10].source_callback = __RTSPSourceCallBack010;
	g_stu[11].source_callback = __RTSPSourceCallBack011;
	g_stu[12].source_callback = __RTSPSourceCallBack012;
	g_stu[13].source_callback = __RTSPSourceCallBack013;
	g_stu[14].source_callback = __RTSPSourceCallBack014;
	g_stu[15].source_callback = __RTSPSourceCallBack015;
	g_stu[16].source_callback = __RTSPSourceCallBack016;
	g_stu[17].source_callback = __RTSPSourceCallBack017;
	g_stu[18].source_callback = __RTSPSourceCallBack018;
	g_stu[19].source_callback = __RTSPSourceCallBack019;
	g_stu[20].source_callback = __RTSPSourceCallBack020;
	g_stu[21].source_callback = __RTSPSourceCallBack021;
	g_stu[22].source_callback = __RTSPSourceCallBack022;
	g_stu[23].source_callback = __RTSPSourceCallBack023;
	g_stu[24].source_callback = __RTSPSourceCallBack024;
	g_stu[25].source_callback = __RTSPSourceCallBack025;
	g_stu[26].source_callback = __RTSPSourceCallBack026;
	g_stu[27].source_callback = __RTSPSourceCallBack027;
	g_stu[28].source_callback = __RTSPSourceCallBack028;
	g_stu[29].source_callback = __RTSPSourceCallBack029;
	g_stu[30].source_callback = __RTSPSourceCallBack030;
	g_stu[31].source_callback = __RTSPSourceCallBack031;
	g_stu[32].source_callback = __RTSPSourceCallBack032;
	g_stu[33].source_callback = __RTSPSourceCallBack033;
	g_stu[34].source_callback = __RTSPSourceCallBack034;
	g_stu[35].source_callback = __RTSPSourceCallBack035;
	g_stu[36].source_callback = __RTSPSourceCallBack036;
	g_stu[37].source_callback = __RTSPSourceCallBack037;
	g_stu[38].source_callback = __RTSPSourceCallBack038;
	g_stu[39].source_callback = __RTSPSourceCallBack039;
	g_stu[40].source_callback = __RTSPSourceCallBack040;
	g_stu[41].source_callback = __RTSPSourceCallBack041;
	g_stu[42].source_callback = __RTSPSourceCallBack042;
	g_stu[43].source_callback = __RTSPSourceCallBack043;
	g_stu[44].source_callback = __RTSPSourceCallBack044;
	g_stu[45].source_callback = __RTSPSourceCallBack045;
	g_stu[46].source_callback = __RTSPSourceCallBack046;
	g_stu[47].source_callback = __RTSPSourceCallBack047;
	g_stu[48].source_callback = __RTSPSourceCallBack048;
	g_stu[49].source_callback = __RTSPSourceCallBack049;
	g_stu[50].source_callback = __RTSPSourceCallBack050;
	g_stu[51].source_callback = __RTSPSourceCallBack051;
	g_stu[52].source_callback = __RTSPSourceCallBack052;
	g_stu[53].source_callback = __RTSPSourceCallBack053;
	g_stu[54].source_callback = __RTSPSourceCallBack054;
	g_stu[55].source_callback = __RTSPSourceCallBack055;
	g_stu[56].source_callback = __RTSPSourceCallBack056;
	g_stu[57].source_callback = __RTSPSourceCallBack057;
	g_stu[58].source_callback = __RTSPSourceCallBack058;
	g_stu[59].source_callback = __RTSPSourceCallBack059;
	g_stu[60].source_callback = __RTSPSourceCallBack060;
	g_stu[61].source_callback = __RTSPSourceCallBack061;
	g_stu[62].source_callback = __RTSPSourceCallBack062;
	g_stu[63].source_callback = __RTSPSourceCallBack063;
	g_stu[64].source_callback = __RTSPSourceCallBack064;
	g_stu[65].source_callback = __RTSPSourceCallBack065;
	g_stu[66].source_callback = __RTSPSourceCallBack066;
	g_stu[67].source_callback = __RTSPSourceCallBack067;
	g_stu[68].source_callback = __RTSPSourceCallBack068;
	g_stu[69].source_callback = __RTSPSourceCallBack069;
	g_stu[70].source_callback = __RTSPSourceCallBack070;
	g_stu[71].source_callback = __RTSPSourceCallBack071;
	g_stu[72].source_callback = __RTSPSourceCallBack072;
	g_stu[73].source_callback = __RTSPSourceCallBack073;
	g_stu[74].source_callback = __RTSPSourceCallBack074;
	g_stu[75].source_callback = __RTSPSourceCallBack075;
	g_stu[76].source_callback = __RTSPSourceCallBack076;
	g_stu[77].source_callback = __RTSPSourceCallBack077;
	g_stu[78].source_callback = __RTSPSourceCallBack078;
	g_stu[79].source_callback = __RTSPSourceCallBack079;
	g_stu[80].source_callback = __RTSPSourceCallBack080;
	g_stu[81].source_callback = __RTSPSourceCallBack081;
	g_stu[82].source_callback = __RTSPSourceCallBack082;
	g_stu[83].source_callback = __RTSPSourceCallBack083;
	g_stu[84].source_callback = __RTSPSourceCallBack084;
	g_stu[85].source_callback = __RTSPSourceCallBack085;
	g_stu[86].source_callback = __RTSPSourceCallBack086;
	g_stu[87].source_callback = __RTSPSourceCallBack087;
	g_stu[88].source_callback = __RTSPSourceCallBack088;
	g_stu[89].source_callback = __RTSPSourceCallBack089;
	g_stu[90].source_callback = __RTSPSourceCallBack090;
	g_stu[91].source_callback = __RTSPSourceCallBack091;
	g_stu[92].source_callback = __RTSPSourceCallBack092;
	g_stu[93].source_callback = __RTSPSourceCallBack093;
	g_stu[94].source_callback = __RTSPSourceCallBack094;
	g_stu[95].source_callback = __RTSPSourceCallBack095;
	g_stu[96].source_callback = __RTSPSourceCallBack096;
	g_stu[97].source_callback = __RTSPSourceCallBack097;
	g_stu[98].source_callback = __RTSPSourceCallBack098;
	g_stu[99].source_callback = __RTSPSourceCallBack099;
	g_stu[100].source_callback = __RTSPSourceCallBack100;
	g_stu[101].source_callback = __RTSPSourceCallBack101;
	g_stu[102].source_callback = __RTSPSourceCallBack102;
	g_stu[103].source_callback = __RTSPSourceCallBack103;
	g_stu[104].source_callback = __RTSPSourceCallBack104;
	g_stu[105].source_callback = __RTSPSourceCallBack105;
	g_stu[106].source_callback = __RTSPSourceCallBack106;
	g_stu[107].source_callback = __RTSPSourceCallBack107;
	g_stu[108].source_callback = __RTSPSourceCallBack108;
	g_stu[109].source_callback = __RTSPSourceCallBack109;
	g_stu[110].source_callback = __RTSPSourceCallBack110;
	g_stu[111].source_callback = __RTSPSourceCallBack111;
	g_stu[112].source_callback = __RTSPSourceCallBack112;
	g_stu[113].source_callback = __RTSPSourceCallBack113;
	g_stu[114].source_callback = __RTSPSourceCallBack114;
	g_stu[115].source_callback = __RTSPSourceCallBack115;
	g_stu[116].source_callback = __RTSPSourceCallBack116;
	g_stu[117].source_callback = __RTSPSourceCallBack117;
	g_stu[118].source_callback = __RTSPSourceCallBack118;
	g_stu[119].source_callback = __RTSPSourceCallBack119;
	g_stu[120].source_callback = __RTSPSourceCallBack120;
	g_stu[121].source_callback = __RTSPSourceCallBack121;
	g_stu[122].source_callback = __RTSPSourceCallBack122;
	g_stu[123].source_callback = __RTSPSourceCallBack123;
	g_stu[124].source_callback = __RTSPSourceCallBack124;
	g_stu[125].source_callback = __RTSPSourceCallBack125;
	g_stu[126].source_callback = __RTSPSourceCallBack126;
	g_stu[127].source_callback = __RTSPSourceCallBack127;
	g_stu[128].source_callback = __RTSPSourceCallBack128;
	g_stu[129].source_callback = __RTSPSourceCallBack129;
	g_stu[130].source_callback = __RTSPSourceCallBack130;
	g_stu[131].source_callback = __RTSPSourceCallBack131;
	g_stu[132].source_callback = __RTSPSourceCallBack132;
	g_stu[133].source_callback = __RTSPSourceCallBack133;
	g_stu[134].source_callback = __RTSPSourceCallBack134;
	g_stu[135].source_callback = __RTSPSourceCallBack135;
	g_stu[136].source_callback = __RTSPSourceCallBack136;
	g_stu[137].source_callback = __RTSPSourceCallBack137;
	g_stu[138].source_callback = __RTSPSourceCallBack138;
	g_stu[139].source_callback = __RTSPSourceCallBack139;
	g_stu[140].source_callback = __RTSPSourceCallBack140;
	g_stu[141].source_callback = __RTSPSourceCallBack141;
	g_stu[142].source_callback = __RTSPSourceCallBack142;
	g_stu[143].source_callback = __RTSPSourceCallBack143;
	g_stu[144].source_callback = __RTSPSourceCallBack144;
	g_stu[145].source_callback = __RTSPSourceCallBack145;
	g_stu[146].source_callback = __RTSPSourceCallBack146;
	g_stu[147].source_callback = __RTSPSourceCallBack147;
	g_stu[148].source_callback = __RTSPSourceCallBack148;
	g_stu[149].source_callback = __RTSPSourceCallBack149;
	g_stu[150].source_callback = __RTSPSourceCallBack150;
	g_stu[151].source_callback = __RTSPSourceCallBack151;
	g_stu[152].source_callback = __RTSPSourceCallBack152;
	g_stu[153].source_callback = __RTSPSourceCallBack153;
	g_stu[154].source_callback = __RTSPSourceCallBack154;
	g_stu[155].source_callback = __RTSPSourceCallBack155;
	g_stu[156].source_callback = __RTSPSourceCallBack156;
	g_stu[157].source_callback = __RTSPSourceCallBack157;
	g_stu[158].source_callback = __RTSPSourceCallBack158;
	g_stu[159].source_callback = __RTSPSourceCallBack159;
	g_stu[160].source_callback = __RTSPSourceCallBack160;
	g_stu[161].source_callback = __RTSPSourceCallBack161;
	g_stu[162].source_callback = __RTSPSourceCallBack162;
	g_stu[163].source_callback = __RTSPSourceCallBack163;
	g_stu[164].source_callback = __RTSPSourceCallBack164;
	g_stu[165].source_callback = __RTSPSourceCallBack165;
	g_stu[166].source_callback = __RTSPSourceCallBack166;
	g_stu[167].source_callback = __RTSPSourceCallBack167;
	g_stu[168].source_callback = __RTSPSourceCallBack168;
	g_stu[169].source_callback = __RTSPSourceCallBack169;
	g_stu[170].source_callback = __RTSPSourceCallBack170;
	g_stu[171].source_callback = __RTSPSourceCallBack171;
	g_stu[172].source_callback = __RTSPSourceCallBack172;
	g_stu[173].source_callback = __RTSPSourceCallBack173;
	g_stu[174].source_callback = __RTSPSourceCallBack174;
	g_stu[175].source_callback = __RTSPSourceCallBack175;
	g_stu[176].source_callback = __RTSPSourceCallBack176;
	g_stu[177].source_callback = __RTSPSourceCallBack177;
	g_stu[178].source_callback = __RTSPSourceCallBack178;
	g_stu[179].source_callback = __RTSPSourceCallBack179;
	g_stu[180].source_callback = __RTSPSourceCallBack180;
	g_stu[181].source_callback = __RTSPSourceCallBack181;
	g_stu[182].source_callback = __RTSPSourceCallBack182;
	g_stu[183].source_callback = __RTSPSourceCallBack183;
	g_stu[184].source_callback = __RTSPSourceCallBack184;
	g_stu[185].source_callback = __RTSPSourceCallBack185;
	g_stu[186].source_callback = __RTSPSourceCallBack186;
	g_stu[187].source_callback = __RTSPSourceCallBack187;
	g_stu[188].source_callback = __RTSPSourceCallBack188;
	g_stu[189].source_callback = __RTSPSourceCallBack189;
	g_stu[190].source_callback = __RTSPSourceCallBack190;
	g_stu[191].source_callback = __RTSPSourceCallBack191;
	g_stu[192].source_callback = __RTSPSourceCallBack192;
	g_stu[193].source_callback = __RTSPSourceCallBack193;
	g_stu[194].source_callback = __RTSPSourceCallBack194;
	g_stu[195].source_callback = __RTSPSourceCallBack195;
	g_stu[196].source_callback = __RTSPSourceCallBack196;
	g_stu[197].source_callback = __RTSPSourceCallBack197;
	g_stu[198].source_callback = __RTSPSourceCallBack198;
	g_stu[199].source_callback = __RTSPSourceCallBack199;
	g_stu[200].source_callback = __RTSPSourceCallBack200;
	g_stu[201].source_callback = __RTSPSourceCallBack201;
	g_stu[202].source_callback = __RTSPSourceCallBack202;
	g_stu[203].source_callback = __RTSPSourceCallBack203;
	g_stu[204].source_callback = __RTSPSourceCallBack204;
	g_stu[205].source_callback = __RTSPSourceCallBack205;
	g_stu[206].source_callback = __RTSPSourceCallBack206;
	g_stu[207].source_callback = __RTSPSourceCallBack207;
	g_stu[208].source_callback = __RTSPSourceCallBack208;
	g_stu[209].source_callback = __RTSPSourceCallBack209;
	g_stu[210].source_callback = __RTSPSourceCallBack210;
	g_stu[211].source_callback = __RTSPSourceCallBack211;
	g_stu[212].source_callback = __RTSPSourceCallBack212;
	g_stu[213].source_callback = __RTSPSourceCallBack213;
	g_stu[214].source_callback = __RTSPSourceCallBack214;
	g_stu[215].source_callback = __RTSPSourceCallBack215;
	g_stu[216].source_callback = __RTSPSourceCallBack216;
	g_stu[217].source_callback = __RTSPSourceCallBack217;
	g_stu[218].source_callback = __RTSPSourceCallBack218;
	g_stu[219].source_callback = __RTSPSourceCallBack219;
	g_stu[220].source_callback = __RTSPSourceCallBack220;
	g_stu[221].source_callback = __RTSPSourceCallBack221;
	g_stu[222].source_callback = __RTSPSourceCallBack222;
	g_stu[223].source_callback = __RTSPSourceCallBack223;
	g_stu[224].source_callback = __RTSPSourceCallBack224;
	g_stu[225].source_callback = __RTSPSourceCallBack225;
	g_stu[226].source_callback = __RTSPSourceCallBack226;
	g_stu[227].source_callback = __RTSPSourceCallBack227;
	g_stu[228].source_callback = __RTSPSourceCallBack228;
	g_stu[229].source_callback = __RTSPSourceCallBack229;
	g_stu[230].source_callback = __RTSPSourceCallBack230;
	g_stu[231].source_callback = __RTSPSourceCallBack231;
	g_stu[232].source_callback = __RTSPSourceCallBack232;
	g_stu[233].source_callback = __RTSPSourceCallBack233;
	g_stu[234].source_callback = __RTSPSourceCallBack234;
	g_stu[235].source_callback = __RTSPSourceCallBack235;
	g_stu[236].source_callback = __RTSPSourceCallBack236;
	g_stu[237].source_callback = __RTSPSourceCallBack237;
	g_stu[238].source_callback = __RTSPSourceCallBack238;
	g_stu[239].source_callback = __RTSPSourceCallBack239;
	g_stu[240].source_callback = __RTSPSourceCallBack240;
	g_stu[241].source_callback = __RTSPSourceCallBack241;
	g_stu[242].source_callback = __RTSPSourceCallBack242;
	g_stu[243].source_callback = __RTSPSourceCallBack243;
	g_stu[244].source_callback = __RTSPSourceCallBack244;
	g_stu[245].source_callback = __RTSPSourceCallBack245;
	g_stu[246].source_callback = __RTSPSourceCallBack246;
	g_stu[247].source_callback = __RTSPSourceCallBack247;
	g_stu[248].source_callback = __RTSPSourceCallBack248;
	g_stu[249].source_callback = __RTSPSourceCallBack249;
	g_stu[250].source_callback = __RTSPSourceCallBack250;
	g_stu[251].source_callback = __RTSPSourceCallBack251;
	g_stu[252].source_callback = __RTSPSourceCallBack252;
	g_stu[253].source_callback = __RTSPSourceCallBack253;
	g_stu[254].source_callback = __RTSPSourceCallBack254;
	g_stu[255].source_callback = __RTSPSourceCallBack255;
	g_stu[256].source_callback = __RTSPSourceCallBack256;
	g_stu[257].source_callback = __RTSPSourceCallBack257;
	g_stu[258].source_callback = __RTSPSourceCallBack258;
	g_stu[259].source_callback = __RTSPSourceCallBack259;
	g_stu[260].source_callback = __RTSPSourceCallBack260;
	g_stu[261].source_callback = __RTSPSourceCallBack261;
	g_stu[262].source_callback = __RTSPSourceCallBack262;
	g_stu[263].source_callback = __RTSPSourceCallBack263;
	g_stu[264].source_callback = __RTSPSourceCallBack264;
	g_stu[265].source_callback = __RTSPSourceCallBack265;
	g_stu[266].source_callback = __RTSPSourceCallBack266;
	g_stu[267].source_callback = __RTSPSourceCallBack267;
	g_stu[268].source_callback = __RTSPSourceCallBack268;
	g_stu[269].source_callback = __RTSPSourceCallBack269;
	g_stu[270].source_callback = __RTSPSourceCallBack270;
	g_stu[271].source_callback = __RTSPSourceCallBack271;
	g_stu[272].source_callback = __RTSPSourceCallBack272;
	g_stu[273].source_callback = __RTSPSourceCallBack273;
	g_stu[274].source_callback = __RTSPSourceCallBack274;
	g_stu[275].source_callback = __RTSPSourceCallBack275;
	g_stu[276].source_callback = __RTSPSourceCallBack276;
	g_stu[277].source_callback = __RTSPSourceCallBack277;
	g_stu[278].source_callback = __RTSPSourceCallBack278;
	g_stu[279].source_callback = __RTSPSourceCallBack279;
	g_stu[280].source_callback = __RTSPSourceCallBack280;
	g_stu[281].source_callback = __RTSPSourceCallBack281;
	g_stu[282].source_callback = __RTSPSourceCallBack282;
	g_stu[283].source_callback = __RTSPSourceCallBack283;
	g_stu[284].source_callback = __RTSPSourceCallBack284;
	g_stu[285].source_callback = __RTSPSourceCallBack285;
	g_stu[286].source_callback = __RTSPSourceCallBack286;
	g_stu[287].source_callback = __RTSPSourceCallBack287;
	g_stu[288].source_callback = __RTSPSourceCallBack288;
	g_stu[289].source_callback = __RTSPSourceCallBack289;
	g_stu[290].source_callback = __RTSPSourceCallBack290;
	g_stu[291].source_callback = __RTSPSourceCallBack291;
	g_stu[292].source_callback = __RTSPSourceCallBack292;
	g_stu[293].source_callback = __RTSPSourceCallBack293;
	g_stu[294].source_callback = __RTSPSourceCallBack294;
	g_stu[295].source_callback = __RTSPSourceCallBack295;
	g_stu[296].source_callback = __RTSPSourceCallBack296;
	g_stu[297].source_callback = __RTSPSourceCallBack297;
	g_stu[298].source_callback = __RTSPSourceCallBack298;
	g_stu[299].source_callback = __RTSPSourceCallBack299;
	char buffer[256];  
    fstream outFile;  
    outFile.open("d://RTSPCONFIG//rtspcj.ini",ios::in);
	int i = 0;
	bool inumOk =false;
    while(!outFile.eof())  
    {  
        outFile.getline(buffer,256,'\n');//getline(char *,int,char) 表示该行字符达到256个或遇到换行就结束
		if((!inumOk)&&strlen(buffer)>0)
		{
			INUM = atoi(buffer);
			inumOk = true;
			continue;
		}
		if(strlen(buffer)>10)
		{
			strcpy(g_stu[i+OFFSET].RTSPURL,buffer);
			i++;//保证上一行的i在变化
		} else 
		{
			OFFSET = atoi(buffer);
		}
        cout<<buffer<<endl;  
    }
    outFile.close();
	g_count_mediainfo = i;
}
int initRTSP( PUSH_RTSP_STU* pSTU)
{
	EasyRTSP_Init(&(pSTU->fRTSPHandle));

	if (NULL == pSTU->fRTSPHandle) return 0;

	unsigned int mediaType = EASY_SDK_VIDEO_FRAME_FLAG | EASY_SDK_AUDIO_FRAME_FLAG;	//获取音/视频数据
	/* 设置数据回调 ，参数怎么传进__RTSPSourceCallBack的？？*/
	int flag = EasyRTSP_SetCallback(pSTU->fRTSPHandle, pSTU->source_callback);

	/* 打开网络流 */
	EasyRTSP_OpenStream(pSTU->fRTSPHandle, 0, pSTU->RTSPURL, RTP_OVER_TCP, mediaType, 0, 0, NULL, 1000, 0);

	return 1;
}
void  finitRTSP( PUSH_RTSP_STU* pSTU)
{
	//if(pSTU->fPusherHandle)
	//{
	//	EasyPusher_StopStream(pSTU->fPusherHandle);
	//	EasyPusher_Release(pSTU->fPusherHandle);
	//	pSTU->fPusherHandle = NULL;
	//}

   
	if(pSTU->fRTSPHandle)
	{
		EasyRTSP_CloseStream(pSTU->fRTSPHandle);
		EasyRTSP_Deinit(&(pSTU->fRTSPHandle));
		pSTU->fRTSPHandle = NULL;
	}

}
timeval add_stamp(timeval *ptv,unsigned int dus)
{
    ptv->tv_usec=ptv->tv_usec+dus; 
    if(ptv->tv_usec>=1000000)
    {
       ptv->tv_sec=ptv->tv_sec+1;
       ptv->tv_usec=ptv->tv_usec-1000000;
    }
    return *ptv;
}
void send_queue(pcap_t *fp)
{          
    unsigned int res;
	//发送数据包
	if(syn == 1){
		if ((res = pcap_sendqueue_transmit(fp, pcap_squeue, 1))< pcap_squeue->len)//同步发送
		{
			printf("syn==1发送数据包时出现错误：%s. 仅%d字节被发送\n",pcap_geterr(fp), res);
		}  
	}else
	{
		if ((res = pcap_sendqueue_transmit(fp, pcap_squeue, 0))< pcap_squeue->len)//异步发送
		{
			printf("syn==0发送数据包时出现错误：%s. 仅%d字节被发送\n",pcap_geterr(fp), res);
		}  
	}
    //释放发送队列
    pcap_sendqueue_destroy(pcap_squeue); 
    return;   
}
bool init_pcap_queue(int min_count)
{
    //分配发送队列
    pcap_squeue = pcap_sendqueue_alloc((unsigned int)((MAX_PACKET_LEN+sizeof(struct pcap_pkthdr))*min_count));
	if(NULL!=pcap_squeue)
		return true;

	return false;
}
void push_pcap_queue()
{
    char errbuf[PCAP_ERRBUF_SIZE];          
    unsigned int res;     
    struct pcap_pkthdr mpktheader;  //数据包的包头
    struct pcap_pkthdr *pktheader;
    pktheader=&mpktheader; 
    timeval tv;                   //时间戳
    tv.tv_sec=0;
    tv.tv_usec=0;
	size_t count = frameQueue.getSize();
	unsigned int min_count = (count<npacks)?count:npacks;
	if(!init_pcap_queue(min_count))
	{
		std::cout<<"Error: init_pcap_queue()"<<endl;
		return ;
	}
    for(int i =0;i<min_count;i++)
    {
		//用数据包填充发送队列		
		memset(frame_packet,0x0,MAX_PACKET_LEN); //全部赋值为零
		//从 queue 的头部取出1个元素
		EASY_AV_Frame_BY* p_avFrame = NULL;
		frameQueue.just_pop(p_avFrame);

		if( 0 == p_avFrame->mediainfo_or_avframe )//媒体信息包
		{
//			unsigned char* frame_packet;
			memcpy(frame_packet+14,p_avFrame,MEDIA_LENGTH-14);
			pktheader->caplen = MEDIA_LENGTH;
			pktheader->len = MEDIA_LENGTH;
		}
		else	//	1: avframe
		{			
			//如果是最后一个包，则重新计算包长度
			if(p_avFrame->endFlag == 1)
			{				
				int realLen = p_avFrame->header.avframe.u32AVFrameLen-(p_avFrame->offset)*MAX_DATA_LENGTH;
//				unsigned char* frame_packet;
				memcpy(frame_packet+14,p_avFrame,realLen+26);
				pktheader->caplen = realLen+40;
				pktheader->len = realLen+40;
			}else
			{
//				unsigned char frame_packet;
				memcpy(frame_packet+14,p_avFrame,MAX_PACKET_LEN-14);
				pktheader->caplen = MAX_PACKET_LEN;
				pktheader->len = MAX_PACKET_LEN;
			}			
		}
		//给前六个用于判断的字节赋值全1
		for(int k=0;k<14;k++)
		{
			frame_packet[k]=0x11;
		}
		//获得生成的数据包，长度为MAX_PACKET_LEN
		//设置数据包的包头
		pktheader->ts=tv;
		if(pcap_sendqueue_queue(pcap_squeue, pktheader, frame_packet) == -1)
        {
            printf("警告: 数据包缓冲区太小，不是所有的数据包被发送.\n");
            return;
        }
		add_stamp(&tv,dus);  //增加时间戳
		pktheader->ts=tv;    //更新数据包头的时间戳

		//把 用完的内存块，放入 pool
		PutMemToPool(p_avFrame);		
	} 
}
EASY_AV_Frame_BY* GetMemFromPool()
{
	boost::mutex::scoped_lock lock(pool_mutex);
//	lock( memory_pool );
	//首先，从 pool 里获取内存块
	EASY_AV_Frame_BY* p = NULL;
	if(memory_pool.size()!=0)
	{
		p = memory_pool.front();
		memory_pool.pop_front();		
//		printf("********* No MemAllocated\n");
	}else if( MemAllocated < MEM_MAX_AVAILABLE)//其次，如果 系统仍有可分配的内存，则 分配一块
	{
		p = new EASY_AV_Frame_BY;
		MemAllocated++;
//		printf("++++++++ MemAllocated: %d\n",MemAllocated);
	}
//	else{
//////		printf("------\n");
////	}
	return p;
}
void PutMemToPool(EASY_AV_Frame_BY* p)
{
	boost::mutex::scoped_lock lock(pool_mutex);
//	lock(memory_pool);
	memory_pool.push_back(p);
	lock.unlock();
}
int Easy_APICALL __RTSPSourceCallBack000( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	
	unsigned short stream_id = 0;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();
	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			curTime = GetTickCount();
			interval = curTime - lastTime;	
			unsigned char crcs[3] = {0}; 
//			GetCrc16(pbuf,frameinfo->length);
//			fwrite(pbuf,1,strlen(pbuf),video);
//			fprintf(fp,"%u\t%d",frameinfo->type,frameinfo->length);
//			get_crc16((unsigned char*)pbuf,frameinfo->length,crcs,fp);
//			fprintf(fp2,"%d\t%d\n",frameinfo->type,frameinfo->length);
//			fflush(fp);
//			fflush(fp2);
			lastTime = curTime;
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){//拆分的最后一个包
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack001( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 1;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();
	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack002( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{	
	unsigned short stream_id = 2;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();
	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack003( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{	
	unsigned short stream_id = 3;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();
	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack004( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 4;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack005( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 5;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();
	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack006( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 6;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();
	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack007( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 7;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();
	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack008( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 8;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();
	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack009( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 9;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();
	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack010( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 10;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();
	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack011( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 11;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();
	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack012( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 12;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();
	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack013( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 13;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();
	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack014( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 14;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();
	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack015( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 15;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();
	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack016( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 16;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack017( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 17;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack018( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 18;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack019( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 19;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack020( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 20;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack021( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 21;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack022( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 22;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack023( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 23;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack024( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 24;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack025( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 25;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack026( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 26;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack027( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 27;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack028( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 28;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack029( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 29;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack030( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 30;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack031( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 31;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack032( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 32;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack033( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 33;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack034( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 34;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack035( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 35;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack036( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 36;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack037( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 37;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack038( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 38;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack039( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 39;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack040( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 40;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack041( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 41;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack042( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 42;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack043( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 43;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack044( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 44;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack045( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 45;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack046( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 46;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack047( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 47;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack048( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 48;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack049( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 49;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack050( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 50;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack051( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 51;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack052( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 52;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack053( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 53;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack054( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 54;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack055( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 55;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack056( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{

	unsigned short stream_id = 56;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack057( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 57;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack058( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 58;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack059( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 59;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack060( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 60;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack061( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 61;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack062( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 62;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack063( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 63;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack064( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 64;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack065( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 65;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack066( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 66;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack067( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 67;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack068( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 68;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack069( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 69;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack070( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 70;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack071( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 71;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack072( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 72;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack073( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 73;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack074( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 74;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack075( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 75;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack076( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 76;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack077( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 77;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack078( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 78;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack079( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 79;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack080( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 80;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack081( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 81;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack082( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 82;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack083( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 83;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack084( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 84;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack085( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 85;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack086( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 86;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack087( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 87;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack088( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 88;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack089( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 89;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}

	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack090( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 90;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack091( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 91;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack092( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 92;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack093( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 93;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack094( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 94;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack095( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 95;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack096( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 96;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack097( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 97;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack098( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 98;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack099( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 99;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack100( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 100;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack101( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 101;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack102( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 102;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack103( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 103;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}

	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack104( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 104;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack105( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 105;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack106( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 106;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}

	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack107( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 107;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack108( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 108;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}

	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack109( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 109;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack110( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 110;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}

	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack111( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 111;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}

	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack112( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 112;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack113( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 113;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack114( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 114;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack115( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 115;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack116( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 116;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack117( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 117;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack118( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 118;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack119( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 119;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack120( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 120;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack121( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 121;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack122( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 122;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack123( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 123;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack124( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 124;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack125( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 125;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack126( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 126;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack127( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 127;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack128( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 128;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack129( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 129;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack130( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 130;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack131( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 131;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack132( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 132;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack133( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 133;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack134( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 134;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack135( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id =135;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack136( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 136;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack137( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 137;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack138( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 138;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack139( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 139;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack140( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 140;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack141( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 141;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack142( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 142;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack143( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 143;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack144( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 144;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack145( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 145;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack146( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 146;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}

	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack147( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 147;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack148( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 148;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack149( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 149;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack150( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 150;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack151( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 151;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack152( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 152;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack153( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 153;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack154( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 154;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack155( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 155;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack156( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 156;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack157( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 157;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack158( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 158;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack159( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 159;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack160( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 160;
	if(pbuf != NULL)
	{
		boost::mutex::scoped_lock lock(frameCount_mutex[stream_id]);
		frameCount[stream_id]++;
		lock.unlock();	
	}
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack161( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 161;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack162( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 162;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack163( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 163;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack164( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 164;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack165( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 165;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack166( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 166;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack167( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 167;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack168( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 168;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack169( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 169;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack170( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 170;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack171( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 171;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack172( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 172;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack173( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 173;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack174( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 174;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack175( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 175;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack176( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 176;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack177( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 177;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack178( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 178;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack179( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 179;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack180( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 180;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack181( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 181;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack182( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 182;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack183( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 183;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack184( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 184;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack185( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 185;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack186( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 186;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack187( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 187;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack188( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 188;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack189( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 189;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack190( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 190;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack191( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 191;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack192( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 192;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack193( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 193;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack194( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 194;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack195( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 195;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack196( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 196;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack197( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 197;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack198( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 198;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack199( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 199;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}

int Easy_APICALL __RTSPSourceCallBack200( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 200;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack201( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 201;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack202( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 202;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack203( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 203;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack204( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 204;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack205( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 205;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack206( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 206;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack207( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 207;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack208( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 208;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack209( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 209;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack210( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 210;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack211( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 211;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack212( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 212;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack213( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 213;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack214( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 214;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack215( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 215;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack216( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 216;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack217( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 217;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack218( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 218;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack219( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 219;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack220( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 220;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack221( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 221;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack222( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 222;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack223( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 223;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack224( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 224;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack225( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 225;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack226( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 226;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack227( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 227;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack228( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 228;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack229( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 229;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack230( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 230;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack231( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 231;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack232( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 232;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack233( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 233;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack234( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 234;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack235( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id =235;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack236( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 236;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack237( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 237;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack238( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 238;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack239( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 239;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}

int Easy_APICALL __RTSPSourceCallBack240( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 240;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack241( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 241;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack242( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 242;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack243( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 243;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack244( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 244;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack245( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 245;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack246( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 246;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack247( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 247;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack248( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 248;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack249( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 249;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack250( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 250;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack251( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 251;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack252( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 252;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack253( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 253;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack254( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 254;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack255( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 255;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack256( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 256;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack257( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 257;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack258( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 258;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack259( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 259;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack260( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 260;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack261( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 261;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack262( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 262;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack263( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 263;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack264( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 264;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack265( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 265;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack266( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 266;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack267( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 267;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack268( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 268;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack269( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 269;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack270( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 270;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack271( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 271;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack272( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 272;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack273( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 273;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack274( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 274;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack275( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 275;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack276( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 276;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack277( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 277;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack278( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 278;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack279( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 279;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack280( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 280;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack281( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 281;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack282( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 282;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack283( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 283;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack284( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 284;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack285( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 285;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack286( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 286;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack287( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 287;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack288( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 288;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack289( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 289;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack290( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 290;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack291( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 291;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack292( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 292;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack293( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 293;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack294( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 294;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack295( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 295;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack296( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 296;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack297( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 297;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack298( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 298;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
int Easy_APICALL __RTSPSourceCallBack299( int _chid, int *_chPtr, int _mediatype, char *pbuf, RTSP_FRAME_INFO *frameinfo)
{
	unsigned short stream_id = 299;
	if (_mediatype == EASY_SDK_VIDEO_FRAME_FLAG||_mediatype == EASY_SDK_AUDIO_FRAME_FLAG)
	{
		if(frameinfo && frameinfo->length)
		{
			int tmp = 0;
			if(frameinfo->length%MAX_DATA_LENGTH == 0)
				tmp = frameinfo->length/MAX_DATA_LENGTH;
			else
				tmp = (frameinfo->length/MAX_DATA_LENGTH)+1;
			for(int i =0;i<tmp;i++)
			{
				//从内存池取得1块空闲内存块
				EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
				if(p_avFrame==NULL)
				{
					return 0;
				}
				p_avFrame->streamID = stream_id;
				p_avFrame->offset = i;
				if(_mediatype == EASY_SDK_VIDEO_FRAME_FLAG)
				{
					p_avFrame->mediainfo_or_avframe = 1;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				}
				else
				{
					p_avFrame->mediainfo_or_avframe = 2;
					p_avFrame->header.avframe.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				}
				p_avFrame->header.avframe.u32VFrameType = frameinfo->type;
				p_avFrame->header.avframe.u32TimestampSec = frameinfo->timestamp_sec;
				p_avFrame->header.avframe.u32TimestampUsec = frameinfo->timestamp_usec;
				p_avFrame->header.avframe.u32AVFrameLen = frameinfo->length;
				if(i == tmp-1){
					p_avFrame->endFlag = 0x01;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,p_avFrame->header.avframe.u32AVFrameLen-i*MAX_DATA_LENGTH );// p_avFrame->header.avframe.u32AVFrameLen//p_avFrame->header.avframe.u32AVFrameLen>1477?1477:p_avFrame->header.avframe.u32AVFrameLen
				}
				else{
					p_avFrame->endFlag = 0x00;
					memcpy(p_avFrame->data, pbuf+i*MAX_DATA_LENGTH,MAX_DATA_LENGTH);
				}
				frameQueue.push(p_avFrame);
			}
		}	
	}
	if (_mediatype == EASY_SDK_MEDIA_INFO_FLAG)
	{
		if((pbuf != NULL) && (g_stu[stream_id].fPusherHandle == NULL))
		{
			EASY_AV_Frame_BY* p_avFrame = GetMemFromPool();
			if(p_avFrame==NULL)
			{
				return 0;
			}
			p_avFrame->mediainfo_or_avframe = 0;
			p_avFrame->streamID = stream_id;
			memcpy(&(p_avFrame->header.mediainfo), pbuf, sizeof(EASY_MEDIA_INFO_T));				
			boost::mutex::scoped_lock lock(mediaList_mutex);
			memcpy(gp_avFrame[stream_id],p_avFrame, sizeof(EASY_AV_Frame_BY));
			lock.unlock();
			frameQueue.push(p_avFrame);
		}
	}
	return 0;
}
