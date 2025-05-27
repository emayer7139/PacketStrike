#include "scanner.h"

CRITICAL_SECTION print_lock;
FILE *log_fp = NULL;
volatile int scanning_active = 1;
volatile int responded_count = 0;

int main() {
    // Initialize WinSock (version 2.2)
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed. Error: %d\n", GetLastError());
        return 1;
    }

    // Detach and re-attach to a fresh console
    FreeConsole();
    AllocConsole();
    FILE* dummy;
    freopen_s(&dummy, "CONOUT$", "w", stdout);
    freopen_s(&dummy, "CONOUT$", "w", stderr);
    freopen_s(&dummy, "CONIN$", "r", stdin);

    // Initialize curses mode (NO COLORS, just plain text)
    initscr();
    noecho();
    cbreak();
    keypad(stdscr, TRUE);
    // Don't hide cursor, avoids glitches in Windows Terminal

    // Detect the active network interface and IPv4 network
    struct in_addr local_ip = {0}, net_mask = {0}, net_addr = {0};
    char iface_name[128] = "Unknown";
    ULONG family = AF_INET;
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS;
    ULONG bufSize = 16384;
    IP_ADAPTER_ADDRESSES *adapter_buf = (IP_ADAPTER_ADDRESSES*) malloc(bufSize);
    if (adapter_buf == NULL) {
        mvprintw(0, 0, "Memory allocation error.");
        getch();
        endwin();
        WSACleanup();
        return 1;
    }
    ULONG ret = GetAdaptersAddresses(family, flags, NULL, adapter_buf, &bufSize);
    IP_ADAPTER_ADDRESSES *adapter = NULL;
    if (ret == NO_ERROR) {
        IP_ADAPTER_ADDRESSES *ptr = adapter_buf;
        IP_ADAPTER_ADDRESSES *bestAdapter = NULL;
        for (; ptr != NULL; ptr = ptr->Next) {
            if (ptr->OperStatus != IfOperStatusUp) continue;
            if (ptr->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
            if (ptr->FirstUnicastAddress == NULL) continue;
            if (ptr->FirstGatewayAddress != NULL) {
                bestAdapter = ptr;
                break;
            }
            if (bestAdapter == NULL)
                bestAdapter = ptr;
        }
        adapter = bestAdapter;
    }
    if (adapter == NULL) {
        mvprintw(0, 0, "No active IPv4 network interface found. Press any key to exit.");
        getch();
        endwin();
        WSACleanup();
        return 1;
    }
    if (adapter->FriendlyName) {
        wcstombs(iface_name, adapter->FriendlyName, sizeof(iface_name));
        iface_name[sizeof(iface_name)-1] = '\0';
    } else if (adapter->Description) {
        wcstombs(iface_name, adapter->Description, sizeof(iface_name));
        iface_name[sizeof(iface_name)-1] = '\0';
    }
    IP_ADAPTER_UNICAST_ADDRESS *unicast = adapter->FirstUnicastAddress;
    SOCKADDR_IN *sa_in = (SOCKADDR_IN*) unicast->Address.lpSockaddr;
    local_ip = sa_in->sin_addr;
    UINT prefixLength = unicast->OnLinkPrefixLength;
    uint32_t mask_host_order;
    if (prefixLength == 0) {
        mask_host_order = 0;
    } else if (prefixLength >= 32) {
        mask_host_order = 0xFFFFFFFF;
    } else {
        mask_host_order = (~0u << (32 - prefixLength));
    }
    net_mask.s_addr = htonl(mask_host_order);
    uint32_t ip_host = ntohl(local_ip.s_addr);
    uint32_t mask_host = mask_host_order;
    uint32_t net_host = ip_host & mask_host;
    net_addr.s_addr = htonl(net_host);

    // Main menu loop
    int ch;
    while (1) {
        clear();
        mvprintw(0, 0, "PacketStrike - Network Scanner");
        mvprintw(2, 0, "Active Interface: %s", iface_name);
        mvprintw(3, 0, "Local IPv4: %s/%u", inet_ntoa(local_ip), prefixLength);
        mvprintw(5, 0, "Select scanning mode:");
        mvprintw(6, 2, "1 - ICMP Ping Sweep");
        mvprintw(7, 2, "2 - TCP SYN Scan (half-open) [stub]");
        mvprintw(8, 2, "3 - ARP Scan (local network)");
        mvprintw(10, 0, "Press number of choice (or Q to quit): ");
        refresh();

        ch = getch();
        if (ch == 'q' || ch == 'Q') {
            endwin();
            WSACleanup();
            return 0;
        }
        if (ch != '1' && ch != '2' && ch != '3') {
            continue;
        }
        int mode = ch - '0';

        clear();
        mvprintw(0, 0, "Output options:");
        mvprintw(1, 2, "1 - Show results on screen");
        mvprintw(2, 2, "2 - Show on screen and save to log file");
        mvprintw(4, 0, "Select output option: ");
        refresh();
        int out_ch = 0;
        do {
            out_ch = getch();
        } while (out_ch != '1' && out_ch != '2' && out_ch != 'q' && out_ch != 'Q');
        if (out_ch == 'q' || out_ch == 'Q') {
            continue;
        }
        bool save_to_file = (out_ch == '2');
        if (save_to_file) {
            log_fp = fopen("PacketStrike_scan.txt", "w");
            if (!log_fp) {
                mvprintw(6, 0, "Warning: Could not open log file. Proceeding without file output.");
                save_to_file = false;
                log_fp = NULL;
                getch();
            }
        }

        InitializeCriticalSection(&print_lock);
        scanning_active = 1;
        responded_count = 0;

        clear();
        mvprintw(0, 0, "Interface: %s (%s/%u)", iface_name, inet_ntoa(local_ip), prefixLength);
        switch (mode) {
            case 1:
                mvprintw(1, 0, "Mode: ICMP Ping Sweep");
                refresh();
                run_icmp_ping_sweep(net_addr, net_mask);
                break;
            case 2:
                mvprintw(1, 0, "Mode: TCP SYN Scan");
                refresh();
                run_tcp_syn_scan(net_addr, net_mask);
                break;
            case 3:
                mvprintw(1, 0, "Mode: ARP Scan");
                refresh();
                run_arp_scan(net_addr, net_mask);
                break;
        }

        if (mode == 1 || mode == 3) {
            mvprintw(3, 0, "Scan complete. Hosts responding: %ld", responded_count);
        } else {
            mvprintw(3, 0, "Scan complete.");
        }
        mvprintw(5, 0, "Press any key to return to menu...");
        refresh();
        getch();

        if (log_fp) {
            fclose(log_fp);
            log_fp = NULL;
        }
        DeleteCriticalSection(&print_lock);
    }

    endwin();
    WSACleanup();
    return 0;
}
