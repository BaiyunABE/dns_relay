#include "../include/dns_relay.h"

int main() {

    init_dns_relay();

    run_dns_relay();

    close_dns_relay();

    return 0;
}
