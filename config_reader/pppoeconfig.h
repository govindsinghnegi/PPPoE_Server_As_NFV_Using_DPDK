#ifndef PPPOECONFIG_H_INCLUDED
#define PPPOECONFIG_H_INCLUDED

#define MAX_STR_LEN 100
#define MAC_LEN 6
#define IP_LEN 4

typedef struct ConfigParam {
        char serviceName[MAX_STR_LEN];
        char acName[MAX_STR_LEN];
        int isDebug;
        int authProtocol;
        unsigned char servToIntraMac[MAC_LEN];
        unsigned char servToInterMac[MAC_LEN];
	unsigned char routerMac[MAC_LEN];
        unsigned char servToIntraIP[IP_LEN];
        unsigned char servToInterIP[IP_LEN];
	unsigned char routerIP[IP_LEN];
        unsigned char ipAddressPool[5];
        unsigned char primaryDns[IP_LEN];
        unsigned char secondaryDns[IP_LEN];
	double sessionTimeout;
	double connectionTimeout;
    } ConfigParameter;

ConfigParameter * getConfigParameters();

#endif
