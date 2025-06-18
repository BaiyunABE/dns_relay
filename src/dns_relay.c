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
    // 初始化Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        error("WSAStartup失败");

    // 创建本地UDP套接字
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET)
        error("无法创建本地套接字");

    // 设置本地地址结构
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(LOCAL_PORT);
    local_addr.sin_addr.s_addr = INADDR_ANY;

    // 绑定套接字到本地端口
    if (bind(sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr)) == SOCKET_ERROR)
        error("绑定失败");

    // 设置远程DNS服务器地址结构
    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(REMOTE_PORT);
    remote_addr.sin_addr.s_addr = inet_addr(REMOTE_DNS);

    // 创建用于转发查询的套接字
    if ((remote_sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET)
        error("无法创建远程套接字");

    // 设置接收远端服务器超时为5秒
    DWORD timeout = 5000;
    if (setsockopt(remote_sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)) == SOCKET_ERROR)
        error("设置超时失败");

    printf("DNS中继器已启动，监听端口 %d，转发到 %s:%d\n", LOCAL_PORT, REMOTE_DNS, REMOTE_PORT);
}

void run_dns_relay() {
    for (;;) {
        // 接收DNS查询
        n = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&client_addr, &client_len);
        if (n == SOCKET_ERROR) {
            printf("接收数据失败: %d\n", WSAGetLastError());
            continue;
        }

        printf("收到来自 %s:%d 的DNS查询\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        // 转发查询到8.8.8.8
        if (sendto(remote_sockfd, buffer, n, 0, (struct sockaddr*)&remote_addr, sizeof(remote_addr)) == SOCKET_ERROR) {
            printf("发送到远程DNS失败: %d\n", WSAGetLastError());
            continue;
        }

        // 接收来自8.8.8.8的响应
        n = recvfrom(remote_sockfd, buffer, BUFFER_SIZE, 0, NULL, NULL);
        if (n == SOCKET_ERROR) {
            printf("接收远程DNS响应失败: %d\n", WSAGetLastError());
            continue;
        }

        // 将响应返回给原始客户端
        if (sendto(sockfd, buffer, n, 0, (struct sockaddr*)&client_addr, client_len) == SOCKET_ERROR)
            printf("返回响应给客户端失败: %d\n", WSAGetLastError());
    }
}

void close_dns_relay() {
    closesocket(sockfd);
    closesocket(remote_sockfd);
    WSACleanup();
}
