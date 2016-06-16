#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include "pppoeconfig.h"

int main()
{
    int i;
    ConfigParameter *cp = getConfigParameters();
    printf("\nserviceName = %s \n", cp->serviceName);
    printf("acName = %s \n", cp->acName);
    printf("isDebug = %d \n", cp->isDebug);
    printf("authProtocol = %d \n", cp->authProtocol);
    printf("servToIntraMac = \n");
    for(i=0;i<6;i++)
        printf("%x\t", cp->servToIntraMac[i]);
    printf("\nservToInterMac = \n");
    for(i=0;i<6;i++)
        printf("%x\t", cp->servToInterMac[i]);
    printf("\nrouterMac = \n");
    for(i=0;i<6;i++)
        printf("%x\t", cp->routerMac[i]);
    printf("\n intranet ip addr array content is : \n");
    for(i=0;i<4;i++)
        printf("%u\t", cp->servToIntraIP[i]);
    printf("\n internet ip addr array content is : \n");
    for(i=0;i<4;i++)
        printf("%u\t", cp->servToInterIP[i]);
    printf("\n router ip addr array content is : \n");
    for(i=0;i<4;i++)
        printf("%u\t", cp->routerIP[i]);
    printf("\n ip addr pool array content is : \n");
    for(i=0;i<5;i++)
        printf("%u\t", cp->ipAddressPool[i]);
    printf("\n primary dns array content is : \n");
    for(i=0;i<4;i++)
        printf("%u\t", cp->primaryDns[i]);
    printf("\n secondry dns array content is : \n");
    for(i=0;i<4;i++)
        printf("%u\t", cp->secondaryDns[i]);
    return 0;
}
