#include "../include/dns_relay.h"
#include <stdio.h>
#include <winsock2.h>

#define BUFFER_SIZE 512
#define LOCAL_PORT 53
#define REMOTE_DNS "8.8.8.8"
#define REMOTE_PORT 53

static WSADATA wsaData;
static SOCKET sockfd, remote_sockfd;
static struct sockaddr_in local_addr, remote_addr, client_addr;
static int client_len = sizeof(client_addr);
static char buffer[BUFFER_SIZE];
static int n;

static void error(const char* msg) {
    fprintf(stderr, "%s: %d\n", msg, WSAGetLastError());
    exit(1);
}

void init_dns_relay() {
    // ��ʼ��Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        error("WSAStartupʧ��");

    // ��������UDP�׽���
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET)
        error("�޷����������׽���");

    // ���ñ��ص�ַ�ṹ
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(LOCAL_PORT);
    local_addr.sin_addr.s_addr = INADDR_ANY;

    // ���׽��ֵ����ض˿�
    if (bind(sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr)) == SOCKET_ERROR)
        error("��ʧ��");

    // ����Զ��DNS��������ַ�ṹ
    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(REMOTE_PORT);
    remote_addr.sin_addr.s_addr = inet_addr(REMOTE_DNS);

    // ��������ת����ѯ���׽���
    if ((remote_sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET)
        error("�޷�����Զ���׽���");

    // ���ý���Զ�˷�������ʱΪ5��
    DWORD timeout = 5000;
    if (setsockopt(remote_sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)) == SOCKET_ERROR)
        error("���ó�ʱʧ��");

    printf("DNS�м����������������˿� %d��ת���� %s:%d\n", LOCAL_PORT, REMOTE_DNS, REMOTE_PORT);
}

void run_dns_relay() {
    for (;;) {
        // ����DNS��ѯ
        n = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&client_addr, &client_len);
        if (n == SOCKET_ERROR) {
            printf("��������ʧ��: %d\n", WSAGetLastError());
            continue;
        }

        printf("�յ����� %s:%d ��DNS��ѯ\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        // ת����ѯ��8.8.8.8
        if (sendto(remote_sockfd, buffer, n, 0, (struct sockaddr*)&remote_addr, sizeof(remote_addr)) == SOCKET_ERROR) {
            printf("���͵�Զ��DNSʧ��: %d\n", WSAGetLastError());
            continue;
        }

        // ��������8.8.8.8����Ӧ
        n = recvfrom(remote_sockfd, buffer, BUFFER_SIZE, 0, NULL, NULL);
        if (n == SOCKET_ERROR) {
            printf("����Զ��DNS��Ӧʧ��: %d\n", WSAGetLastError());
            continue;
        }

        // ����Ӧ���ظ�ԭʼ�ͻ���
        if (sendto(sockfd, buffer, n, 0, (struct sockaddr*)&client_addr, client_len) == SOCKET_ERROR)
            printf("������Ӧ���ͻ���ʧ��: %d\n", WSAGetLastError());
    }
}

void close_dns_relay() {
    closesocket(sockfd);
    closesocket(remote_sockfd);
    WSACleanup();
}
