#include <windows.h>
#include <sys/timeb.h>
#include <time.h> 
//
#if !defined(_WINSOCK2API_) && !defined(_WINSOCKAPI_)
struct timeval
{
long tv_sec;
long tv_usec;
};
#endif

static int gettimeofday(struct timeval* tv)
{
    union {
             long long ns100;
             FILETIME ft;
    } now;
    GetSystemTimeAsFileTime (&now.ft);
    tv->tv_usec = (long) ((now.ns100 / 10LL) % 1000000LL);
    tv->tv_sec = (long) ((now.ns100 - 116444736000000000LL) / 10000000LL);

    return (0);
}
//��ȡ1970������UTC��΢����
//static time_t TimeConversion::GetUtcCaressing()
//{
//    timeval tv;
//    gettimeofday(&tv); 
//    return ((time_t)tv.tv_sec*(time_t)1000000+tv.tv_usec);
//}