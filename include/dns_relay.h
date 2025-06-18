#pragma once
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#pragma comment(lib, "ws2_32.lib")

void init_dns_relay();

void run_dns_relay();

void close_dns_relay();
