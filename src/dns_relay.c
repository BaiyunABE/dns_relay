#include "../include/dns_relay.h"
#include <stdio.h>
#include <stdint.h>
#include <winsock2.h>

#define BUFFER_SIZE 512
#define LOCAL_PORT 53
#define REMOTE_DNS "8.8.8.8" // 202.106.0.20
#define REMOTE_PORT 53
#define INET_ADDRSTRLEN 16

static WSADATA wsaData;
static SOCKET sockfd, remote_sockfd;
static struct sockaddr_in local_addr, remote_addr, client_addr;
static int client_len = sizeof(client_addr);
static char buffer[BUFFER_SIZE];
static int n;

static void error(const char* msg)
{
    fprintf(stderr, "%s: %d\n", msg, WSAGetLastError());
    exit(1);
}

void init_dns_relay()
{
    // 初始化Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        error("WSAStartup()失败");

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

/*
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QDCOUNT                   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     ANCOUNT                   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     NSCOUNT                   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     ARCOUNT                   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
struct dns_header {
    uint16_t id;

    struct {
        uint16_t qr : 1;        // Query/Response (0=query, 1=response)
        uint16_t opcode : 4;    // Operation Code
        uint16_t aa : 1;        // Authoritative Answer
        uint16_t tc : 1;        // Truncation
        uint16_t rd : 1;        // Recursion Desired
        uint16_t ra : 1;        // Recursion Available
        uint16_t z : 3;         // Reserved (must be zero)
        uint16_t rcode : 4;     // Response Code
    } flags;

    uint16_t qdcount;   // Question Count
    uint16_t ancount;   // Answer Count
    uint16_t nscount;   // Authority Count
    uint16_t arcount;   // Additional Count
};

static const char* read_dns_header(const char* buffer, struct dns_header* dns_header)
{
    const uint16_t* src = (uint16_t*)buffer;
    uint16_t* dst = (uint16_t*)dns_header;
    for (int i = 0; i < 6; i++) {
        *dst = ntohs(*src);
        src++;
        dst++;
    }
    return (char*)src;
}

static void print_dns_header(const struct dns_header* dns_header)
{
    printf("\033[1;36mDNS Message Header:\033[0m\n");
    printf("+---------+-------+----------------------+\n");
    printf("| \033[1;33m%-7s\033[0m | \033[1;33m%-5s\033[0m | \033[1;33m%-20s\033[0m |\n", "Field", "Value", "Description");
    printf("+---------+-------+----------------------+\n");
    printf("| %-7s | %-5d | %-20s |\n", "ID", dns_header->id, "Transaction ID");
    printf("| %-7s | %-5d | %-20s |\n", "QR", dns_header->flags.qr, dns_header->flags.qr ? "Response" : "Query");
    printf("| %-7s | %-5d | %-20s |\n", "Opcode", dns_header->flags.opcode,
        (dns_header->flags.opcode == 0) ? "Standard query" :
        (dns_header->flags.opcode == 1) ? "Inverse query" :
        (dns_header->flags.opcode == 2) ? "Server status" : "Reserved");
    printf("| %-7s | %-5d | %-20s |\n", "AA", dns_header->flags.aa, "Authoritative Answer");
    printf("| %-7s | %-5d | %-20s |\n", "TC", dns_header->flags.tc, dns_header->flags.tc ? "Truncated" : "Not truncated");
    printf("| %-7s | %-5d | %-20s |\n", "RD", dns_header->flags.rd, "Recursion Desired");
    printf("| %-7s | %-5d | %-20s |\n", "RA", dns_header->flags.ra, "Recursion Available");
    printf("| %-7s | %-5d | %-20s |\n", "Z", dns_header->flags.z, "Reserved (must be 0)");
    printf("| %-7s | %-5d | %-20s |\n", "RCODE", dns_header->flags.rcode,
        (dns_header->flags.rcode == 0) ? "No error" :
        (dns_header->flags.rcode == 1) ? "Format error" :
        (dns_header->flags.rcode == 2) ? "Server failure" :
        (dns_header->flags.rcode == 3) ? "Name error" :
        (dns_header->flags.rcode == 4) ? "Not implemented" :
        (dns_header->flags.rcode == 5) ? "Refused" : "Reserved");
    printf("+---------+-------+----------------------+\n");
    printf("| %-7s | %-5d | %-20s |\n", "QDCOUNT", dns_header->qdcount, "Questions");
    printf("| %-7s | %-5d | %-20s |\n", "ANCOUNT", dns_header->ancount, "Answer RRs");
    printf("| %-7s | %-5d | %-20s |\n", "NSCOUNT", dns_header->nscount, "Authority RRs");
    printf("| %-7s | %-5d | %-20s |\n", "ARCOUNT", dns_header->arcount, "Additional RRs");
    printf("+---------+-------+----------------------+\n");
}

/*
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
struct dns_question {
    char qname[256];
    uint16_t qtype;
    uint16_t qclass;
};

static const char* read_domain_name(const char* src, char* dst)
{
    uint8_t length;
    while (*src) {
        length = *src;
        if ((length & 0xc0) == 0xc0) {
            const uint16_t offset = ntohs(*(uint16_t*)src) & 0x3fff;
            read_domain_name(buffer + offset, dst);
            return src + 2;
        }
        else {
            src++;
            while (length--)
                *dst++ = *src++;
            *dst++ = '.';
        }
    }
    *(dst - 1) = '\0';
    return ++src;
}

static const char* read_dns_question(const char* buffer, struct dns_question* dns_question)
{
    const uint16_t* src = (uint16_t*)read_domain_name(buffer, dns_question->qname);
    dns_question->qtype = ntohs(*src++);
    dns_question->qclass = ntohs(*(src++));
    return (char*)src;
}

static void print_dns_question(const struct dns_question* dns_question)
{
    printf("\033[1;36mDNS Message Question:\033[0m\n");
    printf("QNAME: \033[1;34m%s\033[0m\n", dns_question->qname);
    printf("+--------+-------+-------------+\n");
    printf("| \033[1;33m%-6s\033[0m | \033[1;33m%-5s\033[0m | \033[1;33m%-11s\033[0m |\n", "Field", "Value", "Description");
    printf("+--------+-------+-------------+\n");
    printf("| %-6s | %-5d | %-11s |\n", "QTYPE", dns_question->qtype, 
        (dns_question->qtype == 1) ? "A" :
        (dns_question->qtype == 2) ? "NS" :
        (dns_question->qtype == 5) ? "CNAME" :
        (dns_question->qtype == 12) ? "PTR" :
        (dns_question->qtype == 13) ? "HINFO" :
        (dns_question->qtype == 15) ? "MX" :
        (dns_question->qtype == 28) ? "AAAA" : "Reserved");
    printf("| %-6s | %-5d | %-11s |\n", "QCLASS", dns_question->qclass, (dns_question->qclass == 1) ? "IN" : "Reserved");
    printf("+--------+-------+-------------+\n");
}

/*
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
struct dns_resource {
    char name[256];
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    char rdata[256];
};

static const char* read_dns_resource(const char* start, struct dns_resource* dns_resource)
{
    const uint16_t* p1 = (uint16_t*)read_domain_name(start, dns_resource->name);
    dns_resource->type = ntohs(*p1++);
    dns_resource->class = ntohs(*p1++);
    const uint32_t* p2 = (uint32_t*)p1;
    dns_resource->ttl = ntohl(*p2++);
    p1 = (uint16_t*)p2;
    dns_resource->rdlength = ntohs(*p1++);
    
    if (dns_resource->type == 1) {  // A
        const uint32_t* src = (uint32_t*)p1;
        struct in_addr addr;
        addr.s_addr = *src;
        strcpy(dns_resource->rdata, inet_ntoa(addr));
        p1 = (uint16_t*)++src;
    }
    else if (dns_resource->type == 5) { // CNAME
        const char* src = (char*)p1;
        p1 = (uint16_t*)read_domain_name(src, dns_resource->rdata);
    }
    else {
        dns_resource->rdata[0] = '\0';
        // update p1
    }
    return (char*)p1;
}

static void print_dns_answer(const struct dns_resource* dns_resource)
{
    printf("\033[1;36mDNS Message Answer:\033[0m\n");
    printf("NAME: \033[1;34m%s\033[0m\n", dns_resource->name);
    printf("+----------+-------+----------------------+\n");
    printf("| \033[1;33m%-8s\033[0m | \033[1;33m%-5s\033[0m | \033[1;33m%-20s\033[0m |\n", "Field", "Value", "Description");
    printf("+----------+-------+----------------------+\n");
    printf("| %-8s | %-5d | %-20s |\n", "TYPE", dns_resource->type,
        (dns_resource->type == 1) ? "A" :
        (dns_resource->type == 2) ? "NS" :
        (dns_resource->type == 5) ? "CNAME" :
        (dns_resource->type == 12) ? "PTR" :
        (dns_resource->type == 13) ? "HINFO" :
        (dns_resource->type == 15) ? "MX" :
        (dns_resource->type == 28) ? "AAAA" : "Reserved");
    printf("| %-8s | %-5d | %-20s |\n", "CLASS", dns_resource->class, (dns_resource->class == 1) ? "IN" : "Reserved");
    printf("| %-8s | %-5d | %-20s |\n", "TTL", dns_resource->ttl, "Time To Live");
    printf("| %-8s | %-5d | %-20s |\n", "RDLENGTH", dns_resource->rdlength, "Resource Data Length");
    printf("+----------+-------+----------------------+\n");
    printf("RDATA: \033[1;34m%s\033[0m\n", dns_resource->rdata);
}

static void print_dns_message()
{
    struct dns_header* dns_header = (struct dns_header*)malloc(sizeof(struct dns_header));
    struct dns_question* dns_question = (struct dns_question*)malloc(sizeof(struct dns_question));

    const char* src = buffer;
    src = read_dns_header(src, dns_header);
    print_dns_header(dns_header);
    src = read_dns_question(src, dns_question);
    print_dns_question(dns_question);

    if (dns_question->qtype == 1) {
        for (int i = 0; i < dns_header->ancount; i++) {
            struct dns_resource* dns_answer = (struct dns_resource*)malloc(sizeof(struct dns_resource));
            src = read_dns_resource(src, dns_answer);
            print_dns_answer(dns_answer);
            free(dns_answer);
        }
    }

    free(dns_header);
    free(dns_question);
}

static void forward()
{
    // 转发查询到8.8.8.8
    if (sendto(remote_sockfd, buffer, n, 0, (struct sockaddr*)&remote_addr, sizeof(remote_addr)) == SOCKET_ERROR) {
        printf("发送到远程DNS失败: %d\n", WSAGetLastError());
        return;
    }

    // 接收来自8.8.8.8的响应
    n = recvfrom(remote_sockfd, buffer, BUFFER_SIZE, 0, NULL, NULL);
    if (n == SOCKET_ERROR) {
        printf("接收远程DNS响应失败: %d\n", WSAGetLastError());
        return;
    }

    char* ip_str = inet_ntoa(remote_addr.sin_addr);
    printf("收到来自 %s:%d 的响应\n", ip_str, ntohs(remote_addr.sin_port));

    print_dns_message();

    // 将响应返回给原始客户端
    if (sendto(sockfd, buffer, n, 0, (struct sockaddr*)&client_addr, client_len) == SOCKET_ERROR)
        printf("返回响应给客户端失败: %d\n", WSAGetLastError());
}

static void handle_client_request()
{
    forward();
}

void run_dns_relay()
{
    for (;;) {
        // 接收DNS查询
        n = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&client_addr, &client_len);
        if (n == SOCKET_ERROR) {
            printf("接收数据失败: %d\n", WSAGetLastError());
            continue;
        }

        char* ip_str = inet_ntoa(client_addr.sin_addr);
        printf("收到来自 %s:%d 的DNS查询\n", ip_str, ntohs(client_addr.sin_port));

        print_dns_message();

        handle_client_request();
    }
}

void close_dns_relay()
{
    closesocket(sockfd);
    closesocket(remote_sockfd);
    WSACleanup();
}
