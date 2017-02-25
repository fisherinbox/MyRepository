/*
	Copyright (c) 2013-2014 EasyDarwin.ORG.  All rights reserved.
	Github: https://github.com/EasyDarwin
	WEChat: EasyDarwin
	Website: http://www.EasyDarwin.org
*/
#include <stdio.h>
#include <string.h>
#include "EasyPusherAPI.h"

#include "hi_type.h"
#include "hi_net_dev_sdk.h"
#include "hi_net_dev_errors.h"

#define UNAME	"admin"
#define PWORD	"admin"
#define DHOST	"192.168.66.189"	//EasyCamera�����IP��ַ
#define DPORT	80					//EasyCamera������˿�

#define SHOST	"115.29.139.20"		//EasyDarwin��ý���������ַ
#define SPORT	554					//EasyDarwin��ý��������˿�
#define SNAME	"easypusher_sdk.sdp"

HI_U32 u32Handle = 0;
Easy_Pusher_Handle fPusherHandle = 0;

HI_S32 OnEventCallback(HI_U32 u32Handle,			/* ��� */
                                HI_U32 u32Event,	/* �¼� */
                                HI_VOID* pUserData  /* �û�����*/
                                )
{
	return HI_SUCCESS;
}


HI_S32 NETSDK_APICALL OnStreamCallback(HI_U32 u32Handle,/* ��� */
                                HI_U32 u32DataType,		/* �������ͣ���Ƶ����Ƶ���ݻ�����Ƶ�������� */
                                HI_U8* pu8Buffer,		/* ���ݰ���֡ͷ */
                                HI_U32 u32Length,		/* ���ݳ��� */
                                HI_VOID* pUserData		/* �û�����*/
                                )
{
    HI_S_AVFrame* pstruAV = HI_NULL;
	HI_S_SysHeader* pstruSys = HI_NULL;
	
	if (u32DataType == HI_NET_DEV_AV_DATA)
	{
		pstruAV = (HI_S_AVFrame*)pu8Buffer;

		if (pstruAV->u32AVFrameFlag == HI_NET_DEV_VIDEO_FRAME_FLAG)
		{
			if(fPusherHandle == 0 ) return 0;

			if(pstruAV->u32AVFrameLen > 0)
			{
				unsigned char* pbuf = (unsigned char*)(pu8Buffer+sizeof(HI_S_AVFrame));

				EASY_AV_Frame  avFrame;
				memset(&avFrame, 0x00, sizeof(EASY_AV_Frame));
				avFrame.u32AVFrameLen = pstruAV->u32AVFrameLen;
				avFrame.pBuffer = (unsigned char*)pbuf;
				avFrame.u32VFrameType = (pstruAV->u32VFrameType==HI_NET_DEV_VIDEO_FRAME_I)?EASY_SDK_VIDEO_FRAME_I:EASY_SDK_VIDEO_FRAME_P;
				avFrame.u32AVFrameFlag = EASY_SDK_VIDEO_FRAME_FLAG;
				avFrame.u32TimestampSec = pstruAV->u32AVFramePTS/1000;
				avFrame.u32TimestampUsec = (pstruAV->u32AVFramePTS%1000)*1000;
				EasyPusher_PushFrame(fPusherHandle, &avFrame);
			}	
		}
		else
		if (pstruAV->u32AVFrameFlag == HI_NET_DEV_AUDIO_FRAME_FLAG)
		{
			if(fPusherHandle == 0 ) return 0;

			if(pstruAV->u32AVFrameLen > 0)
			{
				unsigned char* pbuf = (unsigned char*)(pu8Buffer+sizeof(HI_S_AVFrame));

				EASY_AV_Frame  avFrame;
				memset(&avFrame, 0x00, sizeof(EASY_AV_Frame));
				avFrame.u32AVFrameLen = pstruAV->u32AVFrameLen-4;//ȥ�������Զ����4�ֽ�ͷ
				avFrame.pBuffer = (unsigned char*)pbuf+4;
				avFrame.u32AVFrameFlag = EASY_SDK_AUDIO_FRAME_FLAG;
				avFrame.u32TimestampSec = pstruAV->u32AVFramePTS/1000;
				avFrame.u32TimestampUsec = (pstruAV->u32AVFramePTS%1000)*1000;
				EasyPusher_PushFrame(fPusherHandle, &avFrame);
			}			
		}
	}
	else
	if (u32DataType == HI_NET_DEV_SYS_DATA)
	{
		pstruSys = (HI_S_SysHeader*)pu8Buffer;
		printf("Video W:%u H:%u Audio: %u \n", pstruSys->struVHeader.u32Width, pstruSys->struVHeader.u32Height, pstruSys->struAHeader.u32Format);
	}
	return HI_SUCCESS;
}

HI_S32 OnDataCallback(HI_U32 u32Handle,					/* ��� */
                                HI_U32 u32DataType,		/* ��������*/
                                HI_U8*  pu8Buffer,      /* ���� */
                                HI_U32 u32Length,		/* ���ݳ��� */
                                HI_VOID* pUserData		/* �û�����*/
                                )
{
	return HI_SUCCESS;
}

/* EasyPusher���ݻص� */
int __EasyPusher_Callback(int _id, EASY_PUSH_STATE_T _state, EASY_AV_Frame *_frame, void *_userptr)
{
    if (_state == EASY_PUSH_STATE_CONNECTING)               printf("Connecting...\n");
    else if (_state == EASY_PUSH_STATE_CONNECTED)           printf("Connected\n");
    else if (_state == EASY_PUSH_STATE_CONNECT_FAILED)      printf("Connect failed\n");
    else if (_state == EASY_PUSH_STATE_CONNECT_ABORT)       printf("Connect abort\n");
    else if (_state == EASY_PUSH_STATE_PUSHING)             printf("\r Pushing to rtsp://%s:%d/%s ...", SHOST, SPORT, SNAME);
    else if (_state == EASY_PUSH_STATE_DISCONNECTED)        printf("Disconnect.\n");

    return 0;
}

int main()
{
    HI_S32 s32Ret = HI_SUCCESS;
    HI_S_STREAM_INFO struStreamInfo;
    
    HI_NET_DEV_Init();
    
    s32Ret = HI_NET_DEV_Login(&u32Handle, UNAME, PWORD, DHOST, DPORT);
    if (s32Ret != HI_SUCCESS)
    {
        HI_NET_DEV_DeInit();
		return -1;
    }
    
	//HI_NET_DEV_SetEventCallBack(u32Handle, OnEventCallback, &a);
	HI_NET_DEV_SetStreamCallBack(u32Handle, (HI_ON_STREAM_CALLBACK)OnStreamCallback, NULL);
	//HI_NET_DEV_SetDataCallBack(u32Handle, OnDataCallback, &a);

	struStreamInfo.u32Channel = HI_NET_DEV_CHANNEL_1;
	struStreamInfo.blFlag = HI_TRUE;;
	struStreamInfo.u32Mode = HI_NET_DEV_STREAM_MODE_TCP;
	struStreamInfo.u8Type = HI_NET_DEV_STREAM_ALL;
	s32Ret = HI_NET_DEV_StartStream(u32Handle, &struStreamInfo);
	if (s32Ret != HI_SUCCESS)
	{
		HI_NET_DEV_Logout(u32Handle);
		u32Handle = 0;
		return -1;
	}    
    
    EASY_MEDIA_INFO_T mediainfo;
    memset(&mediainfo, 0x00, sizeof(EASY_MEDIA_INFO_T));
    mediainfo.u32VideoCodec = EASY_SDK_VIDEO_CODEC_H264;
	mediainfo.u32VideoFps = 25;
	mediainfo.u32AudioCodec = EASY_SDK_AUDIO_CODEC_G711A;//Ĭ����������PCMA
	mediainfo.u32AudioSamplerate = 8000;
	mediainfo.u32AudioChannel = 1;

    fPusherHandle = EasyPusher_Create();
    EasyPusher_SetEventCallback(fPusherHandle, __EasyPusher_Callback, 0, NULL);
    EasyPusher_StartStream(fPusherHandle, SHOST, SPORT, SNAME, "admin", "admin", &mediainfo, 1024, false);

    printf("Press Enter exit...\n");
    getchar();

    EasyPusher_StopStream(fPusherHandle);
    EasyPusher_Release(fPusherHandle);
    fPusherHandle = 0;
   
    HI_NET_DEV_StopStream(u32Handle);
    HI_NET_DEV_Logout(u32Handle);
    
    HI_NET_DEV_DeInit();

    return 0;
}