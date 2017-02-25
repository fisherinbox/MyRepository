#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 配置文件第一行为采集数据的网卡编号，第二行为视频路数，第三行为服务器地址，第四行开始为url名称

/*
    我想了一下，现阶段简化实现，不再搞一个单独的 程序来做UDP转发了，而是直接 放在 recv 程序里。为什么这么考虑？理由是：我们的设备是在工业现场的，不需要面对大量客户端并发请求我们提供转发的视频流。通常情况下，使用者是打开web管理系统，打开视频监控网页，里面同时也就是有4~9路访问请求。即使有多个用户，也不会太多。所以，完全不必要。

---------------------------------- 改造你现在的 recv 程序 ------------------------------------
你现在的  recv 程序，具有2个独立功能（工作线程）：
线程1： 基于 libpcap 抓包，然后把 包 放到一个 数据结构（vector）里；
线程2： 基于easy_pusher 把 vector 里的 包，推送给 easydarwin。

现在改造一下：
线程1：不变！

线程2：改造成基于 udp 的 sendto() 把 vector 里的 某一路视频流的包，发送到 对应这一路视频流的多个请求客户端的 ip:port；每一路视频流，有自己的一个 请求客户端的ip:port 的 list列表；

线程3：负责给每一路视频流，维护一个  请求客户端的ip:port 的 list列表！本质上，就是你之前集成在 easydarwin 里的 udp 监听线程！
添加：该线程 recvfrom() 接收到 各个请求客户端的“请求格式包”，取得 ip:port，添加到所被请求的 这一路视频流 的 list 列表中。
清除：
1) 如果收到 某个 ip:port发来的“注销格式包”，就立刻从 list列表中清除掉！
2) 如果 超过5秒没有收到某个 ip:port发来的心跳，就从 list列表中清除掉！
*/



#define _CRT_SECURE_NO_WARNINGS
#endif

#include <winsock2.h>
#include <WinUser.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <list>
#include <set>
#include <windows.h>
#include "pcap.h"
#include "EasyPusherAPI.h"
#include "EasyRTSPClientAPI.h"
#include "concurrent_queue.h"
//std的bind与socket的bind冲突，不使用全局的std，而是在每个需要的地方加上std即可
//using namespace std;  
//#pragma comment(linker,"/subsystem:windows /ENTRY:mainCRTStartup")
#pragma pack(1)
#define MAX_STREAM_COUNT 300			//视频的最大路数
#define MAX_DATA_LENGTH 1474			//包数据部分的最大长度
#define PACKET_LEN 1514					//包的最大总长度
#define MEM_MAX_AVAILABLE 300000		//最大可分配内存数量，给每一个包分配内存时使用
#define FRAME_LEN 1024*1024				//一帧的最大长度，给一帧分配内存时使用
#define FRAME_MEM_MAX_AVAILABLE 300		//最大可分配内存数量，给每一帧分配内存时使用
#define RECON_INTERVAL 20				//重新建立pushhandle的最小间隔（秒）
//调试打印日志文件
FILE *fp;
FILE *fp2;
FILE *fp3;
FILE *fp4;
typedef struct{
	char SHOST[32];			//推送去的目的 darwin server
	unsigned short SPORT;	
	char SNAME[64];				//客户端播放时的sdp文件名
	unsigned char frameFlag;	//用于判断前后两个数据包是否属于同一帧，以决定是否重新分配内存，每一帧分配一次内存
	//unsigned char frameFlag;
	Easy_Pusher_Handle fPusherHandle;
	EasyPusher_Callback pusher_callback;
	EASY_PUSH_STATE_T _state;
	EASY_AV_Frame  avFrame;
} PUSH_RTSP_STU;
//每一个数据包在内存池中的大小
typedef struct
{
	unsigned char packet[PACKET_LEN];
}PushPacket;
//每一帧在内存池中的大小
typedef struct
{
	unsigned char packet[FRAME_LEN];
}PBuffer;
PUSH_RTSP_STU  g_stu[MAX_STREAM_COUNT] = {0};

concurrent_queue<PushPacket*> EasyPushQueue;			//收到包之后的缓存队列
std::list<PushPacket*> EasyPushMemPool;					//包内存分配池
std::list<unsigned char*> FrameMemPool;					//帧内存分配池
boost::mutex pushQueueMutex;							//线程锁
boost::mutex requestListMutex;							//请求视频的 客户端列表 线程锁
boost::mutex g_time_lastMutex;							//控制 上次发送 视频包 的时间戳 的线程锁
boost::mutex pushhandleMutex;							//控制 pushhandle的线程锁
boost::mutex frameCount_mutex;							//接收的包计数的锁
boost::mutex frameCount_mutex_send;						//发送的包计数的锁
int frameCount[MAX_STREAM_COUNT] = {0};					//记录每一路的包数量
int frameCount_Send[MAX_STREAM_COUNT] = {0};			//记录每一路发送的包数量
time_t g_time_lastsend[MAX_STREAM_COUNT] = {0};			//记录收到视频包的最新时间
DWORD lastTime = 0;
DWORD curTime = 0;
DWORD interval = 0;
int caplen = 0;
int INUM = 0;											//端口号
int StreamNum = 0;										//视频路数
struct timeval tv1;
struct timeval tv2;
static int nCount = 0;
static int packetNum = 0;
static pcap_t *adhandle = NULL;
static int MemAllocated = 0;
static int FrameMemAllocated = 0;
static int Puted = 0;
int loseCount[MAX_STREAM_COUNT]={0};
bool g_bIsUDPRecvRunning=false;																	//监视线程的状态
bool g_bStopUDPRecvThread=false;																//监视线程的状态
time_t g_time_recv_udp = 0;														
unsigned short g_UDP_port = 6060;																//监听的端口
SOCKET g_sUDPListen = INVALID_SOCKET;
SOCKADDR_IN g_addrClient;
int g_nLen = sizeof(SOCKADDR);
// prototype of the packet handler 
DWORD WINAPI CapPcap(LPVOID lpParamter);														//pcap收包线程
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);	//pcap收包回调，在CapPcap线程中被回调
DWORD WINAPI pushFrame(LPVOID lpParamter);														//发送包线程
DWORD WINAPI threadFuncMonitor(LPVOID lpParamter);												//监视包发送间隔，重新建立pushhandle
DWORD WINAPI printLog(LPVOID lpParam);															//打印10秒内每一路收包数量，每隔10秒打印一次并清零
DWORD WINAPI ThreadFuncUDPRecv(LPVOID lpParam);													//监听接收Darwin发过来的反馈信息，了解哪一路视频已被darwin删除
void StartThreadUDPRecv();																		//启动ThreadFuncUDPRecv()
void StopThreadUDPRecv();																		//结束ThreadFuncUDPRecv()
int initConfig();
void PutMemToPool(PushPacket* p);
PushPacket* GetMemFromPool();
void PutFrameMemToPool(unsigned char* p);
unsigned char* GetFrameMemFromPool();
int __EasyPusher_Callback000(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback001(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback002(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback003(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback004(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback005(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback006(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback007(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback008(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback009(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback010(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback011(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback012(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback013(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback014(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback015(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback016(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback017(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback018(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback019(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback020(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback021(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback022(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback023(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback024(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback025(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback026(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback027(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback028(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback029(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback030(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback031(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback032(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback033(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback034(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback035(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback036(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback037(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback038(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback039(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback040(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback041(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback042(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback043(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback044(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback045(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback046(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback047(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback048(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback049(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback050(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback051(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback052(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback053(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback054(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback055(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback056(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback057(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback058(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback059(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback060(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback061(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback062(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback063(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback064(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback065(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback066(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback067(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback068(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback069(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback070(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback071(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback072(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback073(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback074(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback075(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback076(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback077(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback078(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback079(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback080(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback081(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback082(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback083(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback084(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback085(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback086(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback087(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback088(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback089(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback090(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback091(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback092(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback093(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback094(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback095(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback096(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback097(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback098(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback099(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback100(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback101(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback102(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback103(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback104(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback105(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback106(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback107(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback108(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback109(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback110(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback111(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback112(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback113(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback114(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback115(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback116(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback117(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback118(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback119(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback120(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback121(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback122(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback123(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback124(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback125(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback126(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback127(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback128(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback129(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback130(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback131(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback132(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback133(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback134(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback135(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback136(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback137(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback138(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback139(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback140(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback141(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback142(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback143(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback144(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback145(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback146(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback147(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback148(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback149(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback150(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback151(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback152(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback153(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback154(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback155(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback156(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback157(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback158(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback159(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback160(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback161(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback162(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback163(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback164(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback165(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback166(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback167(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback168(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback169(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback170(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback171(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback172(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback173(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback174(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback175(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback176(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback177(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback178(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback179(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback180(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback181(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback182(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback183(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback184(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback185(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback186(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback187(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback188(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback189(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback190(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback191(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback192(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback193(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback194(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback195(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback196(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback197(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback198(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback199(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback200(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback201(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback202(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback203(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback204(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback205(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback206(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback207(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback208(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback209(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback210(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback211(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback212(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback213(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback214(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback215(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback216(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback217(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback218(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback219(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback220(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback221(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback222(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback223(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback224(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback225(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback226(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback227(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback228(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback229(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback230(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback231(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback232(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback233(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback234(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback235(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback236(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback237(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback238(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback239(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback240(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback241(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback242(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback243(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback244(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback245(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback246(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback247(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback248(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback249(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback250(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback251(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback252(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback253(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback254(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback255(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback256(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback257(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback258(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback259(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback260(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback261(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback262(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback263(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback264(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback265(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback266(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback267(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback268(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback269(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback270(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback271(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback272(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback273(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback274(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback275(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback276(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback277(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback278(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback279(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback280(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback281(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback282(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback283(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback284(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback285(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback286(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback287(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback288(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback289(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback290(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback291(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback292(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback293(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback294(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback295(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback296(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback297(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback298(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
int __EasyPusher_Callback299(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr);
//启动udp接收线程，接受来自客户端的请求
void StartRecvRequest();
//终止udp接收线程
void StopRecvRequest();
time_t request_lastsend[MAX_STREAM_COUNT] = {0};
typedef struct
{
	short port;
	char* ip;
	time_t heartBeat;
} PlayClient;
struct Comparator
{
   bool operator() (PlayClient pc1, PlayClient pc2) const
   {	   
	   return (pc1.port < pc2.port) || (strcmp(pc1.ip, pc2.ip) < 0);
   }
};
typedef struct{
	std::set<PlayClient,Comparator> playerList;
} PushUdpInfo;
PushUdpInfo pushInfo[MAX_STREAM_COUNT];
int sendFrameUdp(char* packet);
DWORD WINAPI pushFrameUdp(LPVOID lpParamter);
DWORD WINAPI recvRequest(LPVOID lpParamter);
DWORD WINAPI checkHeart(LPVOID lpParamter);
void  finitRTSP( PUSH_RTSP_STU* pSTU)
{
	if(pSTU->fPusherHandle != NULL)
	{
		EasyPusher_StopStream(pSTU->fPusherHandle);
		EasyPusher_Release(pSTU->fPusherHandle);
		pSTU->fPusherHandle = NULL;
//		printf("exe finit---\n");
	}
}
bool g_exit_app = false;	//用户控制退出
DWORD WINAPI CapPcap(LPVOID lpParamter)
{    
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int i=0;
	
	char errbuf[PCAP_ERRBUF_SIZE];
	
	// Retrieve the device list 
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	// Print the list 
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
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	
//	printf("Enter the interface number (1-%d):",i);
//	scanf("%d", &inum);

	
	if(INUM < 1 || INUM > i)
	{
//		printf("\nInterface number out of range.\n");
		// Free the device list 
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	// Jump to the selected adapter 
	for(d=alldevs, i=0; i< INUM-1 ;d=d->next, i++);
	
	// Open the device 
	// Open the adapter 
	if ((adhandle= pcap_open_live(d->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 100,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
//		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		// Free the device list 
		pcap_freealldevs(alldevs);
		return -1;
	}
	
//	printf("\nlistening on %s...\n", d->description);
	
	// At this point, we don't need any more the device list. Free it 
	pcap_freealldevs(alldevs);
	
//	printf("pcap_loop before\n");
	//start the capture 
	pcap_loop(adhandle, 0, packet_handler, NULL);
//	printf("pcap_loop after\n");

	pcap_close(adhandle);    
//	printf("CapPcap() Exit!\n");
	return 0;
}
int main(int argc,char *argv[])
{
	fp = fopen("recvlog.txt","w");
	fp2 = fopen("recvlog2.txt","w");
	fp3 = fopen("recvlog3.txt","w");
	//fp4 = fopen("recvlog4.txt","w");
	//初始化
	if(initConfig()!=0)
	{
		printf("initConfig failed!!");
		return 0;
	}
	HANDLE hThread_print = CreateThread(NULL, 0, printLog, NULL, 0, NULL);
	StartThreadUDPRecv();
	HANDLE hThread_recv = CreateThread(NULL, 0, CapPcap,NULL, 0, NULL);
	HANDLE hThread_push = CreateThread(NULL, 0, pushFrame, NULL, 0, NULL);
//	HANDLE hThread_monitor = CreateThread(NULL, 0, threadFuncMonitor,NULL, 0, NULL);
    while(!g_exit_app) 
	{
//		printf("Please input 'e' to exit...\n");

		int input = getchar();
		if(input == 'e')
		{
			g_exit_app = true;
			if(adhandle!=NULL)
			{
				pcap_breakloop(adhandle);
			}
			StopThreadUDPRecv();
			break;
		}
	} 
	WaitForSingleObject(hThread_recv, 9000);
	CloseHandle(hThread_recv);
	WaitForSingleObject(hThread_push, 9000);
	CloseHandle(hThread_push);
	fclose(fp);
	fclose(fp2);
	fclose(fp3);
	//fclose(fp4);
	//清理 N 路视频流的 资源
	for(int i=0;i<2;i++)
	{
		finitRTSP(&g_stu[i]);
	}
	return 0;
}
DWORD WINAPI ThreadFuncUDPRecv( LPVOID lp ) //UDP接收包的线程函数 
{
	//Sleep(240000);
	time(&g_time_recv_udp);	//起始时间

	//读取监听的端口号
	g_UDP_port = GetPrivateProfileIntA("MEDIASERVER", "PORT", 6060, "C:\\RTSPCONFIG\\fsl.ini"); 
	char strPort[16] = {0};
	itoa( g_UDP_port, strPort, 10);
	WritePrivateProfileStringA("MEDIASERVER", "PORT", strPort, "C:\\RTSPCONFIG\\fsl.ini"); 

	//发送
	struct sockaddr_in si_other;
	memset((char *)&si_other, 0, sizeof(si_other));
	si_other.sin_family = AF_INET;
	si_other.sin_port = htons(g_UDP_port);
	si_other.sin_addr.S_un.S_addr = inet_addr(g_stu[0].SHOST);

	WSAData wsData;
	SOCKADDR_IN addrListen;

	// 定义一个地址结构 接收发送数据方的地址信息
	char recvBuf[1514];

	DWORD nMode = 1;
	int g_nRes;
	int nLength;

	WSAStartup(MAKEWORD(2,2),&wsData);
	g_sUDPListen = socket(AF_INET, SOCK_DGRAM, 0);
	if(g_sUDPListen == INVALID_SOCKET)
	{
		printf("		socket() timeout...\n");
		WSACleanup();
		g_sUDPListen = INVALID_SOCKET;
		return -1;
	}

	// 设置链接地址
	addrListen.sin_addr.S_un.S_addr = htonl(INADDR_ANY); // 转换为网络字节序
	addrListen.sin_family = AF_INET;
	addrListen.sin_port = htons(g_UDP_port);

	// 绑定套接字到本地地址和端口上
	g_nRes = bind(g_sUDPListen,(SOCKADDR*)&addrListen,sizeof(SOCKADDR));
	if(g_nRes == SOCKET_ERROR )
	{
		printf("		bind() timeout...\n");                                                                                                                                                                           
		closesocket(g_sUDPListen);
		WSACleanup();
		g_sUDPListen = INVALID_SOCKET;
		return -1;
	}

	//设定非阻塞UDP
	nMode = 1;
	g_nRes = ioctlsocket(g_sUDPListen, FIONBIO, &nMode);
	if(g_nRes == SOCKET_ERROR )
	{
		printf("		ioctlsocket() timeout...\n");
		closesocket(g_sUDPListen);
		WSACleanup();
		g_sUDPListen = INVALID_SOCKET;
		return -1;
	}
	g_bIsUDPRecvRunning = true;
	printf("		ThreadFuncUDPRecv Begin............\n");

	fd_set fdRead;
	timeval tv;
	tv.tv_sec = 2;
	tv.tv_usec = 0;

	while( !g_bStopUDPRecvThread )
	{
		Sleep(15000);
		for(int i=0;(i<StreamNum)&&(!g_bStopUDPRecvThread);i++)
		{
			g_nRes = sendto(g_sUDPListen, g_stu[i].SNAME, strlen(g_stu[i].SNAME), 0, (struct sockaddr *)&si_other,g_nLen);
			if(g_nRes == SOCKET_ERROR )
			{
				printf("		sendto() Error...\n");
				break;
			}
			FD_ZERO(&fdRead);
			FD_SET(g_sUDPListen, &fdRead);
		
			g_nRes = select(0, &fdRead, NULL, NULL, &tv);
			if(g_nRes == 0)
			{
				printf("		select() timeout...\n");
				continue;
			}
			else if(g_nRes < 0)
			{
				printf("		select() Error...\n");
				break;
			}
			//检查UDP连接
			if(FD_ISSET(g_sUDPListen, &fdRead))
			{
				memset(recvBuf, '\0', 1514);
				if( (nLength = recvfrom(g_sUDPListen,(char *)recvBuf,1514,0,(SOCKADDR*)&g_addrClient,&g_nLen)) > 0 )	//收到数据
				{
					time(&g_time_recv_udp);	//收到数据包的时间
					//显示client端的网络地址 
			//		printf("		recvfrom( %s ) %d: %s  %d %d\n", inet_ntoa( g_addrClient.sin_addr), nLength, recvBuf, num, g_time_recv_udp );
					//fprintf(fp2,"		recvfrom( %s ) %d: %s %d \n", inet_ntoa( g_addrClient.sin_addr), nLength, recvBuf,i, g_time_recv_udp );
					//fflush(fp2);
					//fprintf(fp3," %s %d \n",recvBuf,i );
					//fflush(fp3);
					//int num = atoi(recvBuf);					
					//if (300 != num)
					//{
					//	//fprintf(fp3," %d \n",num );
					//	//fflush(fp3);
					//	boost::mutex::scoped_lock lock(pushhandleMutex);
					//	if (g_stu[num].fPusherHandle != NULL)
					//	{
					//		//fprintf(fp3," n %d \n",num );
					//		//fflush(fp3);
					//		EasyPusher_StopStream(g_stu[num].fPusherHandle);
					//		EasyPusher_Release(g_stu[num].fPusherHandle);
					//		g_stu[num].fPusherHandle = NULL;
					//	}
					//	lock.unlock();
					//}
					//收到‘1’表示这个url已经被unregistered
					boost::mutex::scoped_lock lock(pushhandleMutex);
					if ('1' == recvBuf[0] && g_stu[i].fPusherHandle != NULL)
					{					
						EasyPusher_StopStream(g_stu[i].fPusherHandle);
						EasyPusher_Release(g_stu[i].fPusherHandle);
						g_stu[i].fPusherHandle = NULL;
					}
					lock.unlock();
				}
				else if(nLength == SOCKET_ERROR )
				{
					printf("		recvfrom() Error...\n");
					break;
				} else {
					printf("		recvfrom() Error2...\n");
					break;
				}
			}
		}
	}
	closesocket(g_sUDPListen);
	WSACleanup();
	g_sUDPListen = INVALID_SOCKET;
	g_bIsUDPRecvRunning = false;
	printf("		ThreadFuncUDPRecv() End............ \n");
	return 0; 
}
void StartThreadUDPRecv()
{
	//启动线程
	if(!g_bIsUDPRecvRunning)
	{
		CreateThread( NULL,0,ThreadFuncUDPRecv, NULL, 0, NULL); 
	}
}
void StopThreadUDPRecv()
{
	if(g_bIsUDPRecvRunning)
	{
		g_bStopUDPRecvThread = true;

		int nCount =0;
		while( g_bIsUDPRecvRunning && (nCount<20) )
		{
			Sleep( 100 );
			nCount++;
		}
	}
}
DWORD WINAPI threadFuncMonitor(LPVOID lpParamter)
{ 
//	Sleep(200000);
	time_t time_now;
	while( !g_exit_app )
	{
		for(int i=0;i<StreamNum;i++)
		{
			//超过RECON_INTERVAL(s)没有发送视频包，说明这一路出现问题，则清理这一路的pushhandle，
			//目的是当再次收到这一路的视频包时，给EasyDarwin server发送一个新的pushhandle，重新建立连接
			time(&time_now);
			boost::mutex::scoped_lock lock(g_time_lastMutex);
			boost::mutex::scoped_lock lock2(pushhandleMutex);
			if( (NULL!=g_stu[i].fPusherHandle)&&(time_now - g_time_lastsend[i] > RECON_INTERVAL) )  
			{				
				EasyPusher_StopStream(g_stu[i].fPusherHandle);
				EasyPusher_Release(g_stu[i].fPusherHandle);
				g_stu[i].fPusherHandle = NULL;				
//				finitRTSP(&g_stu[i]);
				fprintf(fp3,"%d\t%d\n",i,time_now);
				fflush(fp3);					
			}
			lock.unlock();
			lock2.unlock();
		}
		Sleep(2000);
	}
	return 0;
}
DWORD WINAPI printLog(LPVOID lpParam)
{
	while(1)
	{
		for(int i = 0;i<StreamNum;i++)
		{		
			//if(i > 0 && i%20 == 0)
			//{
			//	fprintf(fp,"\n");
			//	fprintf(fp2,"\n");
			//}	
			boost::mutex::scoped_lock lock(frameCount_mutex);
			//fprintf(fp,"%d\t",frameCount[i]);
			frameCount[i] = 0;
			lock.unlock();
			boost::mutex::scoped_lock lock2(frameCount_mutex_send);
			//fprintf(fp2,"%d\t",frameCount_Send[i]);
			frameCount_Send[i] = 0;
			lock2.unlock();
		}
		//time_t t;
		//time(&t);
		//fprintf(fp,"\n%d \n",t);
		//fflush(fp);  //刷新缓冲区，以便快速查看打印内容
		//fprintf(fp2,"\n%d \n",t);
		//fflush(fp2);  //刷新缓冲区，以便快速查看打印内容
		Sleep(10000);
	}
}
//Callback function invoked by libpcap for every incoming packet 
int initConfig()
{
	//MAX_STREAM_COUNT 路视频的 回掉函数 设置
	g_stu[0].pusher_callback = __EasyPusher_Callback000;
	g_stu[1].pusher_callback = __EasyPusher_Callback001;
	g_stu[2].pusher_callback = __EasyPusher_Callback002;
	g_stu[3].pusher_callback = __EasyPusher_Callback003;
	g_stu[4].pusher_callback = __EasyPusher_Callback004;
	g_stu[5].pusher_callback = __EasyPusher_Callback005;
	g_stu[6].pusher_callback = __EasyPusher_Callback006;
	g_stu[7].pusher_callback = __EasyPusher_Callback007;
	g_stu[8].pusher_callback = __EasyPusher_Callback008;
	g_stu[9].pusher_callback = __EasyPusher_Callback009;
	g_stu[10].pusher_callback = __EasyPusher_Callback010;
	g_stu[11].pusher_callback = __EasyPusher_Callback011;
	g_stu[12].pusher_callback = __EasyPusher_Callback012;
	g_stu[13].pusher_callback = __EasyPusher_Callback013;
	g_stu[14].pusher_callback = __EasyPusher_Callback014;
	g_stu[15].pusher_callback = __EasyPusher_Callback015;
	g_stu[16].pusher_callback = __EasyPusher_Callback016;
	g_stu[17].pusher_callback = __EasyPusher_Callback017;
	g_stu[18].pusher_callback = __EasyPusher_Callback018;
	g_stu[19].pusher_callback = __EasyPusher_Callback019;
	g_stu[20].pusher_callback = __EasyPusher_Callback020;
	g_stu[21].pusher_callback = __EasyPusher_Callback021;
	g_stu[22].pusher_callback = __EasyPusher_Callback022;
	g_stu[23].pusher_callback = __EasyPusher_Callback023;
	g_stu[24].pusher_callback = __EasyPusher_Callback024;
	g_stu[25].pusher_callback = __EasyPusher_Callback025;
	g_stu[26].pusher_callback = __EasyPusher_Callback026;
	g_stu[27].pusher_callback = __EasyPusher_Callback027;
	g_stu[28].pusher_callback = __EasyPusher_Callback028;
	g_stu[29].pusher_callback = __EasyPusher_Callback029;
	g_stu[30].pusher_callback = __EasyPusher_Callback030;
	g_stu[31].pusher_callback = __EasyPusher_Callback031;
	g_stu[32].pusher_callback = __EasyPusher_Callback032;
	g_stu[33].pusher_callback = __EasyPusher_Callback033;
	g_stu[34].pusher_callback = __EasyPusher_Callback034;
	g_stu[35].pusher_callback = __EasyPusher_Callback035;
	g_stu[36].pusher_callback = __EasyPusher_Callback036;
	g_stu[37].pusher_callback = __EasyPusher_Callback037;
	g_stu[38].pusher_callback = __EasyPusher_Callback038;
	g_stu[39].pusher_callback = __EasyPusher_Callback039;
	g_stu[40].pusher_callback = __EasyPusher_Callback040;
	g_stu[41].pusher_callback = __EasyPusher_Callback041;
	g_stu[42].pusher_callback = __EasyPusher_Callback042;
	g_stu[43].pusher_callback = __EasyPusher_Callback043;
	g_stu[44].pusher_callback = __EasyPusher_Callback044;
	g_stu[45].pusher_callback = __EasyPusher_Callback045;
	g_stu[46].pusher_callback = __EasyPusher_Callback046;
	g_stu[47].pusher_callback = __EasyPusher_Callback047;
	g_stu[48].pusher_callback = __EasyPusher_Callback048;
	g_stu[49].pusher_callback = __EasyPusher_Callback049;
	g_stu[50].pusher_callback = __EasyPusher_Callback050;
	g_stu[51].pusher_callback = __EasyPusher_Callback051;
	g_stu[52].pusher_callback = __EasyPusher_Callback052;
	g_stu[53].pusher_callback = __EasyPusher_Callback053;
	g_stu[54].pusher_callback = __EasyPusher_Callback054;
	g_stu[55].pusher_callback = __EasyPusher_Callback055;
	g_stu[56].pusher_callback = __EasyPusher_Callback056;
	g_stu[57].pusher_callback = __EasyPusher_Callback057;
	g_stu[58].pusher_callback = __EasyPusher_Callback058;
	g_stu[59].pusher_callback = __EasyPusher_Callback059;
	g_stu[60].pusher_callback = __EasyPusher_Callback060;
	g_stu[61].pusher_callback = __EasyPusher_Callback061;
	g_stu[62].pusher_callback = __EasyPusher_Callback062;
	g_stu[63].pusher_callback = __EasyPusher_Callback063;
	g_stu[64].pusher_callback = __EasyPusher_Callback064;
	g_stu[65].pusher_callback = __EasyPusher_Callback065;
	g_stu[66].pusher_callback = __EasyPusher_Callback066;
	g_stu[67].pusher_callback = __EasyPusher_Callback067;
	g_stu[68].pusher_callback = __EasyPusher_Callback068;
	g_stu[69].pusher_callback = __EasyPusher_Callback069;
	g_stu[70].pusher_callback = __EasyPusher_Callback070;
	g_stu[71].pusher_callback = __EasyPusher_Callback071;
	g_stu[72].pusher_callback = __EasyPusher_Callback072;
	g_stu[73].pusher_callback = __EasyPusher_Callback073;
	g_stu[74].pusher_callback = __EasyPusher_Callback074;
	g_stu[75].pusher_callback = __EasyPusher_Callback075;
	g_stu[76].pusher_callback = __EasyPusher_Callback076;
	g_stu[77].pusher_callback = __EasyPusher_Callback077;
	g_stu[78].pusher_callback = __EasyPusher_Callback078;
	g_stu[79].pusher_callback = __EasyPusher_Callback079;
	g_stu[80].pusher_callback = __EasyPusher_Callback080;
	g_stu[81].pusher_callback = __EasyPusher_Callback081;
	g_stu[82].pusher_callback = __EasyPusher_Callback082;
	g_stu[83].pusher_callback = __EasyPusher_Callback083;
	g_stu[84].pusher_callback = __EasyPusher_Callback084;
	g_stu[85].pusher_callback = __EasyPusher_Callback085;
	g_stu[86].pusher_callback = __EasyPusher_Callback086;
	g_stu[87].pusher_callback = __EasyPusher_Callback087;
	g_stu[88].pusher_callback = __EasyPusher_Callback088;
	g_stu[89].pusher_callback = __EasyPusher_Callback089;
	g_stu[90].pusher_callback = __EasyPusher_Callback090;
	g_stu[91].pusher_callback = __EasyPusher_Callback091;
	g_stu[92].pusher_callback = __EasyPusher_Callback092;
	g_stu[93].pusher_callback = __EasyPusher_Callback093;
	g_stu[94].pusher_callback = __EasyPusher_Callback094;
	g_stu[95].pusher_callback = __EasyPusher_Callback095;
	g_stu[96].pusher_callback = __EasyPusher_Callback096;
	g_stu[97].pusher_callback = __EasyPusher_Callback097;
	g_stu[98].pusher_callback = __EasyPusher_Callback098;
	g_stu[99].pusher_callback = __EasyPusher_Callback099;
	g_stu[100].pusher_callback = __EasyPusher_Callback100;
	g_stu[101].pusher_callback = __EasyPusher_Callback101;
	g_stu[102].pusher_callback = __EasyPusher_Callback102;
	g_stu[103].pusher_callback = __EasyPusher_Callback103;
	g_stu[104].pusher_callback = __EasyPusher_Callback104;
	g_stu[105].pusher_callback = __EasyPusher_Callback105;
	g_stu[106].pusher_callback = __EasyPusher_Callback106;
	g_stu[107].pusher_callback = __EasyPusher_Callback107;
	g_stu[108].pusher_callback = __EasyPusher_Callback108;
	g_stu[109].pusher_callback = __EasyPusher_Callback109;
	g_stu[110].pusher_callback = __EasyPusher_Callback110;
	g_stu[111].pusher_callback = __EasyPusher_Callback111;
	g_stu[112].pusher_callback = __EasyPusher_Callback112;
	g_stu[113].pusher_callback = __EasyPusher_Callback113;
	g_stu[114].pusher_callback = __EasyPusher_Callback114;
	g_stu[115].pusher_callback = __EasyPusher_Callback115;
	g_stu[116].pusher_callback = __EasyPusher_Callback116;
	g_stu[117].pusher_callback = __EasyPusher_Callback117;
	g_stu[118].pusher_callback = __EasyPusher_Callback118;
	g_stu[119].pusher_callback = __EasyPusher_Callback119;
	g_stu[120].pusher_callback = __EasyPusher_Callback120;
	g_stu[121].pusher_callback = __EasyPusher_Callback121;
	g_stu[122].pusher_callback = __EasyPusher_Callback122;
	g_stu[123].pusher_callback = __EasyPusher_Callback123;
	g_stu[124].pusher_callback = __EasyPusher_Callback124;
	g_stu[125].pusher_callback = __EasyPusher_Callback125;
	g_stu[126].pusher_callback = __EasyPusher_Callback126;
	g_stu[127].pusher_callback = __EasyPusher_Callback127;
	g_stu[128].pusher_callback = __EasyPusher_Callback128;
	g_stu[129].pusher_callback = __EasyPusher_Callback129;
	g_stu[130].pusher_callback = __EasyPusher_Callback130;
	g_stu[131].pusher_callback = __EasyPusher_Callback131;
	g_stu[132].pusher_callback = __EasyPusher_Callback132;
	g_stu[133].pusher_callback = __EasyPusher_Callback133;
	g_stu[134].pusher_callback = __EasyPusher_Callback134;
	g_stu[135].pusher_callback = __EasyPusher_Callback135;
	g_stu[136].pusher_callback = __EasyPusher_Callback136;
	g_stu[137].pusher_callback = __EasyPusher_Callback137;
	g_stu[138].pusher_callback = __EasyPusher_Callback138;
	g_stu[139].pusher_callback = __EasyPusher_Callback139;
	g_stu[140].pusher_callback = __EasyPusher_Callback140;
	g_stu[141].pusher_callback = __EasyPusher_Callback141;
	g_stu[142].pusher_callback = __EasyPusher_Callback142;
	g_stu[143].pusher_callback = __EasyPusher_Callback143;
	g_stu[144].pusher_callback = __EasyPusher_Callback144;
	g_stu[145].pusher_callback = __EasyPusher_Callback145;
	g_stu[146].pusher_callback = __EasyPusher_Callback146;
	g_stu[147].pusher_callback = __EasyPusher_Callback147;
	g_stu[148].pusher_callback = __EasyPusher_Callback148;
	g_stu[149].pusher_callback = __EasyPusher_Callback149;
	g_stu[150].pusher_callback = __EasyPusher_Callback150;
	g_stu[151].pusher_callback = __EasyPusher_Callback151;
	g_stu[152].pusher_callback = __EasyPusher_Callback152;
	g_stu[153].pusher_callback = __EasyPusher_Callback153;
	g_stu[154].pusher_callback = __EasyPusher_Callback154;
	g_stu[155].pusher_callback = __EasyPusher_Callback155;
	g_stu[156].pusher_callback = __EasyPusher_Callback156;
	g_stu[157].pusher_callback = __EasyPusher_Callback157;
	g_stu[158].pusher_callback = __EasyPusher_Callback158;
	g_stu[159].pusher_callback = __EasyPusher_Callback159;
	g_stu[160].pusher_callback = __EasyPusher_Callback160;
	g_stu[161].pusher_callback = __EasyPusher_Callback161;
	g_stu[162].pusher_callback = __EasyPusher_Callback162;
	g_stu[163].pusher_callback = __EasyPusher_Callback163;
	g_stu[164].pusher_callback = __EasyPusher_Callback164;
	g_stu[165].pusher_callback = __EasyPusher_Callback165;
	g_stu[166].pusher_callback = __EasyPusher_Callback166;
	g_stu[167].pusher_callback = __EasyPusher_Callback167;
	g_stu[168].pusher_callback = __EasyPusher_Callback168;
	g_stu[169].pusher_callback = __EasyPusher_Callback169;
	g_stu[170].pusher_callback = __EasyPusher_Callback170;
	g_stu[171].pusher_callback = __EasyPusher_Callback171;
	g_stu[172].pusher_callback = __EasyPusher_Callback172;
	g_stu[173].pusher_callback = __EasyPusher_Callback173;
	g_stu[174].pusher_callback = __EasyPusher_Callback174;
	g_stu[175].pusher_callback = __EasyPusher_Callback175;
	g_stu[176].pusher_callback = __EasyPusher_Callback176;
	g_stu[177].pusher_callback = __EasyPusher_Callback177;
	g_stu[178].pusher_callback = __EasyPusher_Callback178;
	g_stu[179].pusher_callback = __EasyPusher_Callback179;
	g_stu[180].pusher_callback = __EasyPusher_Callback180;
	g_stu[181].pusher_callback = __EasyPusher_Callback181;
	g_stu[182].pusher_callback = __EasyPusher_Callback182;
	g_stu[183].pusher_callback = __EasyPusher_Callback183;
	g_stu[184].pusher_callback = __EasyPusher_Callback184;
	g_stu[185].pusher_callback = __EasyPusher_Callback185;
	g_stu[186].pusher_callback = __EasyPusher_Callback186;
	g_stu[187].pusher_callback = __EasyPusher_Callback187;
	g_stu[188].pusher_callback = __EasyPusher_Callback188;
	g_stu[189].pusher_callback = __EasyPusher_Callback189;
	g_stu[190].pusher_callback = __EasyPusher_Callback190;
	g_stu[191].pusher_callback = __EasyPusher_Callback191;
	g_stu[192].pusher_callback = __EasyPusher_Callback192;
	g_stu[193].pusher_callback = __EasyPusher_Callback193;
	g_stu[194].pusher_callback = __EasyPusher_Callback194;
	g_stu[195].pusher_callback = __EasyPusher_Callback195;
	g_stu[196].pusher_callback = __EasyPusher_Callback196;
	g_stu[197].pusher_callback = __EasyPusher_Callback197;
	g_stu[198].pusher_callback = __EasyPusher_Callback198;
	g_stu[199].pusher_callback = __EasyPusher_Callback199;
	g_stu[200].pusher_callback = __EasyPusher_Callback200;
	g_stu[201].pusher_callback = __EasyPusher_Callback201;
	g_stu[202].pusher_callback = __EasyPusher_Callback202;
	g_stu[203].pusher_callback = __EasyPusher_Callback203;
	g_stu[204].pusher_callback = __EasyPusher_Callback204;
	g_stu[205].pusher_callback = __EasyPusher_Callback205;
	g_stu[206].pusher_callback = __EasyPusher_Callback206;
	g_stu[207].pusher_callback = __EasyPusher_Callback207;
	g_stu[208].pusher_callback = __EasyPusher_Callback208;
	g_stu[209].pusher_callback = __EasyPusher_Callback209;
	g_stu[210].pusher_callback = __EasyPusher_Callback210;
	g_stu[211].pusher_callback = __EasyPusher_Callback211;
	g_stu[212].pusher_callback = __EasyPusher_Callback212;
	g_stu[213].pusher_callback = __EasyPusher_Callback213;
	g_stu[214].pusher_callback = __EasyPusher_Callback214;
	g_stu[215].pusher_callback = __EasyPusher_Callback215;
	g_stu[216].pusher_callback = __EasyPusher_Callback216;
	g_stu[217].pusher_callback = __EasyPusher_Callback217;
	g_stu[218].pusher_callback = __EasyPusher_Callback218;
	g_stu[219].pusher_callback = __EasyPusher_Callback219;
	g_stu[220].pusher_callback = __EasyPusher_Callback220;
	g_stu[221].pusher_callback = __EasyPusher_Callback221;
	g_stu[222].pusher_callback = __EasyPusher_Callback222;
	g_stu[223].pusher_callback = __EasyPusher_Callback223;
	g_stu[224].pusher_callback = __EasyPusher_Callback224;
	g_stu[225].pusher_callback = __EasyPusher_Callback225;
	g_stu[226].pusher_callback = __EasyPusher_Callback226;
	g_stu[227].pusher_callback = __EasyPusher_Callback227;
	g_stu[228].pusher_callback = __EasyPusher_Callback228;
	g_stu[229].pusher_callback = __EasyPusher_Callback229;
	g_stu[230].pusher_callback = __EasyPusher_Callback230;
	g_stu[231].pusher_callback = __EasyPusher_Callback231;
	g_stu[232].pusher_callback = __EasyPusher_Callback232;
	g_stu[233].pusher_callback = __EasyPusher_Callback233;
	g_stu[234].pusher_callback = __EasyPusher_Callback234;
	g_stu[235].pusher_callback = __EasyPusher_Callback235;
	g_stu[236].pusher_callback = __EasyPusher_Callback236;
	g_stu[237].pusher_callback = __EasyPusher_Callback237;
	g_stu[238].pusher_callback = __EasyPusher_Callback238;
	g_stu[239].pusher_callback = __EasyPusher_Callback239;
	g_stu[240].pusher_callback = __EasyPusher_Callback240;
	g_stu[241].pusher_callback = __EasyPusher_Callback241;
	g_stu[242].pusher_callback = __EasyPusher_Callback242;
	g_stu[243].pusher_callback = __EasyPusher_Callback243;
	g_stu[244].pusher_callback = __EasyPusher_Callback244;
	g_stu[245].pusher_callback = __EasyPusher_Callback245;
	g_stu[246].pusher_callback = __EasyPusher_Callback246;
	g_stu[247].pusher_callback = __EasyPusher_Callback247;
	g_stu[248].pusher_callback = __EasyPusher_Callback248;
	g_stu[249].pusher_callback = __EasyPusher_Callback249;
	g_stu[250].pusher_callback = __EasyPusher_Callback250;
	g_stu[251].pusher_callback = __EasyPusher_Callback251;
	g_stu[252].pusher_callback = __EasyPusher_Callback252;
	g_stu[253].pusher_callback = __EasyPusher_Callback253;
	g_stu[254].pusher_callback = __EasyPusher_Callback254;
	g_stu[255].pusher_callback = __EasyPusher_Callback255;
	g_stu[256].pusher_callback = __EasyPusher_Callback256;
	g_stu[257].pusher_callback = __EasyPusher_Callback257;
	g_stu[258].pusher_callback = __EasyPusher_Callback258;
	g_stu[259].pusher_callback = __EasyPusher_Callback259;
	g_stu[260].pusher_callback = __EasyPusher_Callback260;
	g_stu[261].pusher_callback = __EasyPusher_Callback261;
	g_stu[262].pusher_callback = __EasyPusher_Callback262;
	g_stu[263].pusher_callback = __EasyPusher_Callback263;
	g_stu[264].pusher_callback = __EasyPusher_Callback264;
	g_stu[265].pusher_callback = __EasyPusher_Callback265;
	g_stu[266].pusher_callback = __EasyPusher_Callback266;
	g_stu[267].pusher_callback = __EasyPusher_Callback267;
	g_stu[268].pusher_callback = __EasyPusher_Callback268;
	g_stu[269].pusher_callback = __EasyPusher_Callback269;
	g_stu[270].pusher_callback = __EasyPusher_Callback270;
	g_stu[271].pusher_callback = __EasyPusher_Callback271;
	g_stu[272].pusher_callback = __EasyPusher_Callback272;
	g_stu[273].pusher_callback = __EasyPusher_Callback273;
	g_stu[274].pusher_callback = __EasyPusher_Callback274;
	g_stu[275].pusher_callback = __EasyPusher_Callback275;
	g_stu[276].pusher_callback = __EasyPusher_Callback276;
	g_stu[277].pusher_callback = __EasyPusher_Callback277;
	g_stu[278].pusher_callback = __EasyPusher_Callback278;
	g_stu[279].pusher_callback = __EasyPusher_Callback279;
	g_stu[280].pusher_callback = __EasyPusher_Callback280;
	g_stu[281].pusher_callback = __EasyPusher_Callback281;
	g_stu[282].pusher_callback = __EasyPusher_Callback282;
	g_stu[283].pusher_callback = __EasyPusher_Callback283;
	g_stu[284].pusher_callback = __EasyPusher_Callback284;
	g_stu[285].pusher_callback = __EasyPusher_Callback285;
	g_stu[286].pusher_callback = __EasyPusher_Callback286;
	g_stu[287].pusher_callback = __EasyPusher_Callback287;
	g_stu[288].pusher_callback = __EasyPusher_Callback288;
	g_stu[289].pusher_callback = __EasyPusher_Callback289;
	g_stu[290].pusher_callback = __EasyPusher_Callback290;
	g_stu[291].pusher_callback = __EasyPusher_Callback291;
	g_stu[292].pusher_callback = __EasyPusher_Callback292;
	g_stu[293].pusher_callback = __EasyPusher_Callback293;
	g_stu[294].pusher_callback = __EasyPusher_Callback294;
	g_stu[295].pusher_callback = __EasyPusher_Callback295;
	g_stu[296].pusher_callback = __EasyPusher_Callback296;
	g_stu[297].pusher_callback = __EasyPusher_Callback297;
	g_stu[298].pusher_callback = __EasyPusher_Callback298;
	g_stu[299].pusher_callback = __EasyPusher_Callback299;
	char buffer[100]; 
	char sName[64];
    std::fstream outFile;  
    outFile.open("d://RTSPCONFIG//rtsprecv.ini",std::ios::in); 
	bool inumOk = false;
	int line = 0;
	 while(!outFile.eof())  
    {  
        outFile.getline(buffer,100,'\n');//getline(char *,int,char) 表示该行字符达到16个或遇到换行就结束  
		if(strlen(buffer)>0)
		{
			line++;
			//第一行为接收数据包的网卡编号
			if(line == 1)
				INUM = atoi(buffer);		
			//第二行为视频路数
			else if(line == 2)
			{
				StreamNum = atoi(buffer);
			}
			else if(line == 3)
			{				
				//第三行为推送目的服务器地址
				for(int i=0;i<StreamNum;i++)
				{
					g_stu[i]._state = EASY_PUSH_STATE_DISCONNECTED;
					g_stu[i].SPORT = 554;
					strcpy(g_stu[i].SHOST,buffer);
				}
			}
			else 
			{
				//第四行开始读取推送流的名字
				strcpy(g_stu[line-4].SNAME,buffer);
			}			
		}
		//if(strlen(buffer)>6)
		//{
		//	for(int i=0;i<MAX_STREAM_COUNT;i++)
		//	{
		//		memset(&g_stu[i], 0, sizeof( PUSH_RTSP_STU));
		//		g_stu[i]._state = EASY_PUSH_STATE_DISCONNECTED;
		//		g_stu[i].SPORT = 554;
		//		itoa(i,sName,10);
		//		strcat(sName,".sdp");//以当前路编号0、1等给sdp文件命名
		//		strcpy(g_stu[i].SNAME,sName);
		//		strcpy(g_stu[i].SHOST,buffer);
		//	}
		//	return 0;
		//} 
    }  
	 outFile.close();
	 for(int i = line-3;i<StreamNum;i++)
	 {
		itoa(i,sName,10);
		strcat(sName,".sdp");//以当前路编号0、1等给sdp文件命名
		strcpy(g_stu[i].SNAME,sName);
	 }
	 for (int x = 0; x < StreamNum; x++) 
	{
		g_stu[x].fPusherHandle = NULL;
	}
	return 0;
}

void StartRecvRequest()
{
	//启动线程
	if(!g_bIsUDPRecvRunning)
	{
		CreateThread( NULL,0,recvRequest, NULL, 0, NULL); 
	}
}
void StopRecvRequest()
{
	if(g_bIsUDPRecvRunning)
	{
		g_bStopUDPRecvThread = true;

		int nCount =0;
		while( g_bIsUDPRecvRunning && (nCount<20) )
		{
			Sleep( 100 );
			nCount++;
		}
	}
}

DWORD WINAPI recvRequest(LPVOID lpParamter)
{
	time(&g_time_recv_udp);	//起始时间

	//读取监听的端口号
	g_UDP_port = GetPrivateProfileIntA("MEDIASERVER", "PORT", 6060, "C:\\fsl.ini"); 
	char strPort[16] = {0};
	itoa( g_UDP_port, strPort, 10);
	WritePrivateProfileStringA("MEDIASERVER", "PORT", strPort, "C:\\fsl.ini"); 

	WSAData wsData;
	SOCKADDR_IN addrListen;

	// 定义一个地址结构 接收发送数据方的地址信息
	unsigned char recvBuf[1514];

	DWORD nMode = 1;
	int g_nRes;
	int nLength;

	WSAStartup(MAKEWORD(2,2),&wsData);
	g_sUDPListen = socket(AF_INET, SOCK_DGRAM, 0);
	if(g_sUDPListen == INVALID_SOCKET)
	{
		printf("		socket() timeout...\n");
		WSACleanup();
		g_sUDPListen = INVALID_SOCKET;
		return -1;
	}

	// 设置链接地址
	addrListen.sin_addr.S_un.S_addr = htonl(INADDR_ANY); // 转换为网络字节序
	addrListen.sin_family = AF_INET;
	addrListen.sin_port = htons(g_UDP_port);

	// 绑定套接字到本地地址和端口上
	g_nRes = bind(g_sUDPListen,(SOCKADDR*)&addrListen,sizeof(SOCKADDR));
	if(g_nRes == SOCKET_ERROR )
	{
		printf("		bind() timeout...\n");
		closesocket(g_sUDPListen);
		WSACleanup();
		g_sUDPListen = INVALID_SOCKET;
		return -1;
	}

	//设定非阻塞UDP
	nMode = 1;
	g_nRes = ioctlsocket(g_sUDPListen, FIONBIO, &nMode);
	if(g_nRes == SOCKET_ERROR )
	{
		printf("		ioctlsocket() timeout...\n");
		closesocket(g_sUDPListen);
		WSACleanup();
		g_sUDPListen = INVALID_SOCKET;
		return -1;
	}
	g_bIsUDPRecvRunning = true;
	printf("		ThreadFuncUDPRecv Begin............\n");

	fd_set fdRead;
	timeval tv;
	tv.tv_sec = 2;
	tv.tv_usec = 0;
	unsigned char url[100];
	//char* url = "./Movies\\";
	while( !g_bStopUDPRecvThread )
	{
		FD_ZERO(&fdRead);
		FD_SET(g_sUDPListen, &fdRead);
		
		g_nRes = select(0, &fdRead, NULL, NULL, &tv);
		if(g_nRes == 0)
		{
			printf("		select() timeout...\n");
			continue;
		}
		else if(g_nRes < 0)
		{
			printf("		select() Error...\n");
			break;
		}

		//检查UDP连接
		if(FD_ISSET(g_sUDPListen, &fdRead))
		{
			memset(recvBuf,'\0',1514);
			memset(url,'\0',100);
			//char name[5] = {'\0'};
//			url = url + (char*)recvBuf;
			strcat((char *)url,"./Movies\\");  
			if( (nLength = recvfrom(g_sUDPListen,(char *)recvBuf,1514,0,(SOCKADDR*)&g_addrClient,&g_nLen)) > 0 )	//收到数据
			{
				time(&g_time_recv_udp);	//收到数据包的时间
//				strcat((char *)url,(char*)recvBuf);
				//显示client端的网络地址 
//				qtss_fprintf(udp,"		recvfrom( %s ) %d: %s  %d\n", inet_ntoa( g_addrClient.sin_addr), nLength,url, g_time_recv_udp );	
				//收到了 查询的 rtsp url 字符串，在 集合 中查找
				
				// 获得请求的 视频id --哪一路
				if (g_nLen == 4) 
				{
					int streamId = 0;
					memcpy(&streamId,recvBuf,2);
					if (streamId >=0 && streamId < MAX_STREAM_COUNT ) 
					{
						bool requestOk = false;   
						//获取请求类型 订阅还是取消订阅  连续两个1是订阅 连续两个2是取消订阅
						PlayClient player;
						player.ip = inet_ntoa(g_addrClient.sin_addr);
						player.port = g_addrClient.sin_port;
						if (recvBuf[2] == '1' && recvBuf[3] == '1') 
						{
							//加入播放列表
							requestOk = true;
							// 获得请求者的端口和ip
							time(&player.heartBeat);
							boost::mutex::scoped_lock lock(requestListMutex);
							pushInfo[streamId].playerList.insert(player);
						} else if (recvBuf[2] == '2' && recvBuf[3] == '2')
						{
							//从播放列表中删除
							requestOk = true;
							boost::mutex::scoped_lock lock(requestListMutex);
							std::set<PlayClient, Comparator>::iterator removeIt = pushInfo[streamId].playerList.find(player);
							if (removeIt != pushInfo[streamId].playerList.end())
							{
								fprintf(fp,"%d %s\n", (*removeIt).port,(*removeIt).ip);
								pushInfo[streamId].playerList.erase(removeIt);
							}
						} else 
						{
							//更新心跳
							boost::mutex::scoped_lock lock(requestListMutex);
							if (pushInfo[streamId].playerList.size() != 0) 
							{
								std::set<PlayClient, Comparator>::iterator updateIt = pushInfo[streamId].playerList.find(player);
								if (updateIt != pushInfo[streamId].playerList.end())
								{
									time(&player.heartBeat);
									boost::mutex::scoped_lock lock(requestListMutex);
									pushInfo[streamId].playerList.erase(updateIt);
									pushInfo[streamId].playerList.insert(player);
								}
							}							
						}
						//fflush(udp);
						char* response;
						if(requestOk)
						{
							//回复 请求成功
							response = "0";
						}
						else
						{					
							//回复 请求失败
							response = "1";
						}
						//将字串返回给client端
						g_nRes = sendto(g_sUDPListen, response, strlen(response), 0, (struct sockaddr *)&g_addrClient,g_nLen);
						if(g_nRes == SOCKET_ERROR )
						{
							printf("		sendto() Error...\n");
							break;
						}
						//fflush(udp);
					}
				}				

			}
			else if(nLength == SOCKET_ERROR )
			{
				printf("		recvfrom() Error...\n");
				break;
			}
		}
	}
	closesocket(g_sUDPListen);
	WSACleanup();
	g_sUDPListen = INVALID_SOCKET;
	g_bIsUDPRecvRunning = false;
	printf("		ThreadFuncUDPRecv() End............ \n");
	return 0; 
}
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{	
	if (pkt_data[0] == 0x11 && pkt_data[1] == 0x11 && pkt_data[2] == 0x11 && pkt_data[3] == 0x11 && pkt_data[4] == 0x11 && pkt_data[5] == 0x11)
	{		
		PushPacket* push_packet = GetMemFromPool();
		if(push_packet!=NULL)
		{			
			memcpy(push_packet->packet,pkt_data,header->caplen);
			int streamId = 0;
			memcpy(&streamId,pkt_data+14,2);
			if(pkt_data[19] == 0x01 ) 
			{
				boost::mutex::scoped_lock lock(frameCount_mutex);
				frameCount[streamId]++;
				lock.unlock();
			}				
			EasyPushQueue.push(push_packet);
		}
	}	
}
int sendFrameUdp(unsigned char* packet)
{
	SOCKET s;
	struct sockaddr_in server, si_other;
	int slen, recv_len;
	WSADATA wsa;

	slen = sizeof(si_other);

	//Initialise winsock
	printf("\nInitialising Winsock...");
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		printf("Failed. Error Code :");
		printf("Failed. Error Code : %d", WSAGetLastError());
		//exit(EXIT_FAILURE);
	}
	printf("Initialised.\n");

	//Create a socket
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET)
	{
		printf("Could not create socket : %d", WSAGetLastError());
	}
	printf("Socket created.\n");

	//第几路
	unsigned short streamId = 0;			
	memcpy(&streamId,packet,2);
	//从列表获取ip:port
	boost::mutex::scoped_lock lock(requestListMutex);
	for (std::set<PlayClient,Comparator>::iterator it = pushInfo[streamId].playerList.begin(); it != pushInfo[streamId].playerList.end(); it++) 
	{
		memset((char *)&si_other, 0, sizeof(si_other));
		si_other.sin_family = AF_INET;
		si_other.sin_port = htons((*it).port);
		si_other.sin_addr.S_un.S_addr = inet_addr((char*)(*it).ip);

		//send the message
		if (sendto(s, (char*)packet, strlen((char*)packet), 0, (struct sockaddr *) &si_other, slen) == SOCKET_ERROR)
		{
			printf("sendto() failed with error code : %d", WSAGetLastError());
			exit(EXIT_FAILURE);
		}
		printf("send feedback successfully\n");
	}
	lock.unlock();
	//setup address structure
	return 0;
}
DWORD WINAPI pushFrameUdp(LPVOID lpParamter)
{
	 while(!g_exit_app)
	{
		if(!EasyPushQueue.empty())
		{
			PushPacket* packetBuf = NULL;
			EasyPushQueue.just_pop(packetBuf);
			sendFrameUdp(packetBuf->packet);
		}
	 }
	 return 0;
}
DWORD WINAPI checkHeart(LPVOID lpParamter)
{
	while (!g_exit_app) 
	{
		for (int i = 0; i < MAX_STREAM_COUNT; i++) 
		{
			boost::mutex::scoped_lock lock(requestListMutex);
			if (pushInfo[i].playerList.size() != 0) 
			{
				for (std::set<PlayClient,Comparator>::iterator it = pushInfo[i].playerList.begin(); it != pushInfo[i].playerList.end(); it++) 
				{
					time_t curT = 0;
					time(&curT);
					if ( (curT - (*it).heartBeat) > 5) 
					{
						pushInfo[i].playerList.erase(it);
					}
				}
			}
		}
		Sleep(2000);
	}
	return 0;
}
DWORD WINAPI pushFrame(LPVOID lpParamter)
{
	 while(!g_exit_app)
	{
		if(!EasyPushQueue.empty())
		{
			PushPacket* packetBuf = NULL;
			EasyPushQueue.just_pop(packetBuf);
			//帧长
			int frameLen = 0;
			//第几路
			unsigned short streamId = 0;
			//当前包编号
			unsigned short framePacketCount =0;
			
			memcpy(&streamId,packetBuf->packet+14,2);
//			fprintf(fp,"%u\n",streamId);	
			//fflush(fp);
			memcpy(&framePacketCount,packetBuf->packet+17,2);
			memcpy(&frameLen,packetBuf->packet+24,4);
			//媒体信息包
			if((packetBuf->packet)[16] == 0x00)
			{

				EASY_MEDIA_INFO_T mediainfo;
				memset(&mediainfo, 0x00, sizeof(EASY_MEDIA_INFO_T));
				memcpy(&mediainfo, packetBuf->packet+20, sizeof(EASY_MEDIA_INFO_T));
				time_t t;
				time(&t);
				boost::mutex::scoped_lock lock(pushhandleMutex);
				if(NULL==g_stu[streamId].fPusherHandle && (g_time_lastsend[streamId] == 0 || (t - g_time_lastsend[streamId] < 5)))
				{					
					g_stu[streamId].fPusherHandle = EasyPusher_Create();
					//fprintf(fp4,"%d\t%d\n",streamId,t);
					//fflush(fp4);	
					if(NULL!=g_stu[streamId].fPusherHandle) 
					{
						unsigned int flag1 = EasyPusher_SetEventCallback(g_stu[streamId].fPusherHandle, g_stu[streamId].pusher_callback, 0, NULL);
						unsigned int flag2 = EasyPusher_StartStream(g_stu[streamId].fPusherHandle, g_stu[streamId].SHOST, g_stu[streamId].SPORT,
							g_stu[streamId].SNAME, "admin", "admin", &mediainfo, 1024, false);//1M缓冲区
						//fprintf(fp,"%03d %u %u %d \n",streamId, flag1,flag2,t);
						//fflush(fp);
					}					
					//boost::mutex::scoped_lock lock2(g_time_lastMutex[streamId]);
					//time(&g_time_lastsend[streamId]);
					//lock2.unlock();
				} 
				lock.unlock();
			} else if((packetBuf->packet)[16] == 0x01||(packetBuf->packet)[16] == 0x02)
			//视频包
			{		
				boost::mutex::scoped_lock g_time_lock(g_time_lastMutex);
				time(&g_time_lastsend[streamId]);	//如果发送了 视频包，就更新 时间戳
				g_time_lock.unlock();
				//还未收到媒体信息包，则丢弃此数据包
				if(g_stu[streamId].fPusherHandle == NULL ) 
				{
					//fprintf(fp,"++\t%d\n",streamId);
					//fflush(fp);
					PutMemToPool(packetBuf);
					continue;
				}
				if(frameLen <= FRAME_LEN)//大包则直接丢弃
				{					
					if(g_stu[streamId].avFrame.pBuffer == NULL)
					{
						g_stu[streamId].avFrame.pBuffer = GetFrameMemFromPool();	
						if(g_stu[streamId].avFrame.pBuffer == NULL)
						{
							PutMemToPool(packetBuf);
							continue;
						}	
					}
					if((packetBuf->packet)[19] == 0x00)
					{
						//boost::mutex::scoped_lock lock(pushQueueMutex);
						//time(&g_time_lastsend[streamId]);	//如果发送了 视频包，就更新 时间戳
						//lock.unlock();
						memcpy(g_stu[streamId].avFrame.pBuffer+framePacketCount*MAX_DATA_LENGTH,packetBuf->packet+40,MAX_DATA_LENGTH);
					}else//最后一个包到达，才把本帧数据发送出去，最后回收内存
					{						
						memcpy(&g_stu[streamId].avFrame.u32VFrameType,packetBuf->packet+20,4);
						g_stu[streamId].avFrame.u32AVFrameLen = frameLen;
						memcpy(&g_stu[streamId].avFrame.u32AVFrameFlag,packetBuf->packet+28,sizeof(g_stu[streamId].avFrame.u32AVFrameFlag));
						memcpy(&g_stu[streamId].avFrame.u32TimestampSec,packetBuf->packet+32,sizeof(g_stu[streamId].avFrame.u32TimestampSec));
						memcpy(&g_stu[streamId].avFrame.u32TimestampUsec,packetBuf->packet+36,sizeof(g_stu[streamId].avFrame.u32TimestampUsec));
						memcpy(g_stu[streamId].avFrame.pBuffer+framePacketCount*MAX_DATA_LENGTH,packetBuf->packet+40,
							g_stu[streamId].avFrame.u32AVFrameLen-framePacketCount*MAX_DATA_LENGTH);
//						unsigned char crcs[3] = {0}; 
						
//						curTime = GetTickCount();

						EasyPusher_PushFrame(g_stu[streamId].fPusherHandle, &g_stu[streamId].avFrame);	
						//boost::mutex::scoped_lock lock(g_time_lastMutex[streamId]);
						//time(&g_time_lastsend[streamId]);	//如果发送了 视频包，就更新 时间戳
						//lock.unlock();
						boost::mutex::scoped_lock lock2(frameCount_mutex_send);
						frameCount_Send[streamId]++;
						lock2.unlock();




//						interval = curTime-lastTime;
						
//						fprintf(fp,"%u\t%d",g_stu[streamId].avFrame.u32VFrameType,g_stu[streamId].avFrame.u32AVFrameLen);
//						get_crc16(g_stu[streamId].avFrame.pBuffer,g_stu[streamId].avFrame.u32AVFrameLen,crcs,fp);
//						fflush(fp);
						//time_t cTime;
						//time(&cTime);
//						lastTime = curTime;
//						fprintf(fp,"%u\n",streamId);		
//						fflush(fp);
						//fflush(fp);
						
						/*
						if(flag != 0)
						{
							loseCount[streamId]++;
							fprintf(fp,"第%d路视频推送失败%d次\n",streamId,loseCount[streamId]);	
							fflush(fp);
						}*/
						PutFrameMemToPool(g_stu[streamId].avFrame.pBuffer);
						g_stu[streamId].avFrame.pBuffer = NULL;
						memset(&g_stu[streamId].avFrame, 0x00,sizeof(EASY_AV_Frame));//sizeof(EASY_AV_Frame)
					}	
				}
				//else 
				//{
				//	fprintf(fp,"丢弃\n");
				//}
			}
			//else {
			//	fprintf(fp3,"不是视频包也不是信息包\n");
			//}
			PutMemToPool(packetBuf);
		}else
		{
			Sleep(10);
		}

	}
	return 0;
}
PushPacket* GetMemFromPool()
{
	boost::mutex::scoped_lock lock(pushQueueMutex);
//	lock( memory_pool );
	//首先，从 pool 里获取内存块
	PushPacket* p = NULL;
//	printf("EasyPushMemPool size:%d\n",EasyPushMemPool.size());
	if(EasyPushMemPool.size()!=0)
	{
		p = EasyPushMemPool.front();
		EasyPushMemPool.pop_front();
//		printf("No MemAllocated!!\n");
	}else if(MemAllocated < MEM_MAX_AVAILABLE)//其次，如果 系统仍有可分配的内存，则 分配一块
	{
		p = new PushPacket;
		MemAllocated++;
//		printf("MemAllocated: %d\n",MemAllocated);
	}
	return p;
}
void PutMemToPool(PushPacket* p)
{
	boost::mutex::scoped_lock lock(pushQueueMutex);
//	lock(memory_pool);
//	printf("put!!\n");
	EasyPushMemPool.push_back(p);	
//	printf("puted!!\n");
//	lock.unlock();
//	Puted++;
//	printf("MemPuted: %d\n",Puted);
}
unsigned char * GetFrameMemFromPool()
{
	boost::mutex::scoped_lock lock(pushQueueMutex);
	unsigned char* p = NULL;
	if(!FrameMemPool.empty())
	{
		p = FrameMemPool.front();
		FrameMemPool.pop_front();
//		printf("No FrameMemAllocated!!\n");
	}else if(FrameMemAllocated < FRAME_MEM_MAX_AVAILABLE)
	{
		p = new unsigned char[FRAME_LEN];
		FrameMemAllocated++;
		//printf("FrameMemAllocated: %d\n",FrameMemAllocated);
	}
	return p;
} 
void PutFrameMemToPool(unsigned char* p)
{
	boost::mutex::scoped_lock lock(pushQueueMutex);
	FrameMemPool.push_back(p);
	lock.unlock();
}
int __EasyPusher_Callback000(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 0;
	g_stu[stream_id]._state = _state;
	//fprintf(fp,"id: %d  state:%d %d\n ",stream_id,_state,GetTickCount());
	//fflush(fp);
    return 0;
}
int __EasyPusher_Callback001(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 1;
	g_stu[stream_id]._state = _state;
	//fprintf(fp,"id: %d  state:%d %d\n ",stream_id,_state,GetTickCount());
	//fflush(fp);
    return 0;
}
int __EasyPusher_Callback002(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 2;
	g_stu[stream_id]._state = _state;
	//fprintf(fp,"id: %d  state:%d %d\n ",stream_id,_state,GetTickCount());
	//fflush(fp);
    return 0;
}
int __EasyPusher_Callback003(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 3;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback004(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 4;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback005(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 5;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback006(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 6;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback007(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 7;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback008(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 8;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback009(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 9;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback010(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 10;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback011(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 11;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback012(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 12;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback013(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 13;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback014(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 14;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback015(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 15;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback016(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 16;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback017(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 17;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback018(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 18;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback019(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 19;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback020(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 20;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback021(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 21;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback022(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 22;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback023(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 23;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback024(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 24;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback025(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 25;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback026(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 26;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback027(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 27;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback028(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 28;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback029(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 29;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback030(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 30;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback031(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 31;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback032(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 32;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback033(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 33;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback034(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 34;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback035(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 35;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback036(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 36;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback037(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 37;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback038(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 38;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback039(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 39;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback040(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 40;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback041(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 41;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback042(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 42;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback043(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 43;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback044(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id =44;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback045(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 45;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback046(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 46;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback047(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 47;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback048(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 48;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback049(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 49;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback050(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 50;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback051(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 51;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback052(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 52;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback053(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 53;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback054(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 54;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback055(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 55;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback056(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 56;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback057(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 57;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback058(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 58;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback059(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 59;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback060(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 60;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback061(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 61;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback062(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 62;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback063(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 63;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback064(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 64;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback065(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 65;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback066(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 66;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback067(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 67;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback068(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 68;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback069(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 69;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback070(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 70;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback071(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 71;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback072(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 72;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback073(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 73;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback074(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 74;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback075(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 75;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback076(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 76;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback077(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 77;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback078(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 78;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback079(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 79;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback080(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 80;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback081(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 81;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback082(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 82;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback083(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 83;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback084(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 84;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback085(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 85;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback086(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 86;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback087(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 87;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback088(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 88;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback089(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 89;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback090(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 90;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback091(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 91;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback092(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 92;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback093(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 93;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback094(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 94;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback095(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 95;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback096(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 96;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback097(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 97;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback098(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 98;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback099(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 99;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback100(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 100;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback101(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id =101;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback102(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 102;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback103(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 103;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback104(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 104;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback105(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 105;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback106(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 106;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback107(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 107;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback108(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 108;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback109(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 109;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback110(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 110;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback111(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 111;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback112(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 112;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback113(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 113;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback114(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 114;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback115(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 115;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback116(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 116;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback117(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 117;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback118(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 118;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback119(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 119;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback120(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 120;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback121(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 121;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback122(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 122;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback123(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 123;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback124(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 124;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback125(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 125;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback126(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 126;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback127(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id =127;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback128(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 128;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback129(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 129;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback130(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 130;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback131(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 131;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback132(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 132;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback133(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 133;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback134(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 134;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback135(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 135;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback136(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 136;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback137(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 137;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback138(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 138;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback139(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 139;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback140(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id =140;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback141(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 141;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback142(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 142;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback143(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 143;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback144(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id =144;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback145(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 145;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback146(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 146;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback147(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 147;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback148(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 148;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback149(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 149;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback150(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 150;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback151(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 151;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback152(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 152;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback153(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 153;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback154(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 154;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback155(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 155;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback156(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 156;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback157(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 157;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback158(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 158;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback159(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 159;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback160(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 160;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback161(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 161;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback162(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 162;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback163(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 163;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback164(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 164;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback165(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 165;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback166(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 166;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback167(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 167;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback168(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 168;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback169(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 169;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback170(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 170;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback171(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 171;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback172(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 172;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback173(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 173;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback174(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 174;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback175(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 175;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback176(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 176;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback177(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 177;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback178(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 178;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback179(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 179;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback180(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 180;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback181(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 181;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback182(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 182;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback183(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 183;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback184(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 184;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback185(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 185;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback186(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 186;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback187(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 187;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback188(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 188;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback189(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 189;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback190(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 190;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback191(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 191;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback192(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 192;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback193(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 193;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback194(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 194;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback195(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 195;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback196(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 196;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback197(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 197;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback198(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 198;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback199(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 199;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback200(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 200;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback201(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id =201;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback202(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 202;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback203(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 203;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback204(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 204;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback205(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 205;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback206(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 206;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback207(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 207;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback208(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 208;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback209(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 209;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback210(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 210;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback211(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 211;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback212(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 212;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback213(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 213;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback214(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 214;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback215(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 215;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback216(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 216;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback217(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 217;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback218(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 218;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback219(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 219;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback220(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 220;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback221(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 221;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback222(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 222;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback223(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 223;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback224(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 224;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback225(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 225;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback226(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 226;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback227(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id =227;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback228(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 228;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback229(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 229;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback230(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 230;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback231(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 231;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback232(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 232;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback233(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 233;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback234(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 234;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback235(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 235;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback236(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 236;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback237(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 237;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback238(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 238;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback239(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 239;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback240(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id =240;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback241(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 241;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback242(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 242;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback243(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 243;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback244(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id =244;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback245(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 245;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback246(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 246;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback247(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 247;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback248(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 248;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback249(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 249;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback250(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 250;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback251(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 251;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback252(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 252;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback253(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 253;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback254(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 254;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback255(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 255;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback256(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 256;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback257(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 257;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback258(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 258;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback259(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 259;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback260(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 260;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback261(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 261;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback262(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 262;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback263(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 263;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback264(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 264;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback265(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 265;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback266(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 266;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback267(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 267;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback268(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 268;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback269(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 269;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback270(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 270;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback271(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 271;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback272(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 272;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback273(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 273;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback274(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 274;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback275(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 275;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback276(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 276;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback277(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 277;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback278(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 278;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback279(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 279;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback280(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 280;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback281(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 281;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback282(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 282;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback283(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 283;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback284(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 284;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback285(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 285;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback286(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 286;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback287(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 287;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback288(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 288;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback289(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 289;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback290(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 290;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback291(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 291;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback292(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 292;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback293(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 293;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback294(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 294;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback295(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 295;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback296(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 296;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback297(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 297;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback298(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 298;
	g_stu[stream_id]._state = _state;
    return 0;
}
int __EasyPusher_Callback299(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{	
	int stream_id = 299;
	g_stu[stream_id]._state = _state;
    return 0;
}
