#include "scanner.h"

// ICMP header structure (8 bytes for Echo Request/Reply)
#pragma pack(push, 1)
typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
} ICMPHeader;
#pragma pack(pop)

// Size of ICMP payload data (in bytes)
#define ICMP_DATA_SIZE 32

// Compute checksum for ICMP packet (header + data)
static uint16_t calculate_checksum(const uint16_t *buf, int bytes) {
    unsigned long sum = 0;
    while (bytes > 1) {
        sum += *buf++;
        bytes -= 2;
    }
    if (bytes == 1) {
        uint8_t leftOver = *(const uint8_t*)buf;
        sum += leftOver;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    uint16_t checksum = (uint16_t)(~sum);
    return checksum;
}

// Shared data for threads
static uint32_t *g_targets = NULL;
static int g_target_count = 0;
static volatile LONG g_nextIndex = -1;

// Thread procedure for sending one ping and waiting for reply
DWORD WINAPI PingThreadProc(LPVOID param) {
    SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock == INVALID_SOCKET) {
        EnterCriticalSection(&print_lock);
        mvprintw(5, 0, "Error: Cannot create raw socket (requires Admin privileges).\n");
        if (log_fp) fprintf(log_fp, "Error: Cannot create raw socket (Admin rights needed).\n");
        refresh();
        LeaveCriticalSection(&print_lock);
        return 1;
    }

    int timeout = 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = 0;

    while (scanning_active) {
        LONG index = InterlockedIncrement(&g_nextIndex);
        if (index >= g_target_count) {
            break;
        }
        uint32_t target_ip = g_targets[index];

        // Build IP string for debugging
        char ip_str[16];
        sprintf(ip_str, "%d.%d.%d.%d",
            (target_ip >> 24) & 0xFF, (target_ip >> 16) & 0xFF,
            (target_ip >> 8) & 0xFF, target_ip & 0xFF);

        // Show every target attempt!
        EnterCriticalSection(&print_lock);
        mvprintw(4 + index % 40, 0, "Trying: %s                 ", ip_str);
        refresh();
        LeaveCriticalSection(&print_lock);

        // Build ICMP Echo Request packet
        ICMPHeader icmp;
        char data[ICMP_DATA_SIZE];
        icmp.type = 8;
        icmp.code = 0;
        icmp.id   = (uint16_t)(GetCurrentThreadId() & 0xFFFF);
        icmp.seq  = (uint16_t)(index & 0xFFFF);
        for (int i = 0; i < ICMP_DATA_SIZE; ++i) data[i] = (char)('A' + (i % 26));
        icmp.checksum = 0;
        char sendbuf[sizeof(ICMPHeader) + ICMP_DATA_SIZE];
        memcpy(sendbuf, &icmp, sizeof(ICMPHeader));
        memcpy(sendbuf + sizeof(ICMPHeader), data, ICMP_DATA_SIZE);
        uint16_t csum = calculate_checksum((uint16_t*)sendbuf, sizeof(sendbuf));
        ((ICMPHeader*)sendbuf)->checksum = csum;

        dest.sin_addr.s_addr = htonl(target_ip);

        int sendResult = sendto(sock, sendbuf, sizeof(sendbuf), 0, (struct sockaddr*)&dest, sizeof(dest));
        if (sendResult == SOCKET_ERROR) {
            // Print **why** the send failed
            int err = WSAGetLastError();
            EnterCriticalSection(&print_lock);
            mvprintw(45 + index % 30, 0, "Send failed for %s: WSAErr=%d           ", ip_str, err);
            refresh();
            LeaveCriticalSection(&print_lock);
            if (log_fp) fprintf(log_fp, "Send failed for %s: WSAErr=%d\n", ip_str, err);
            continue;
        }

        char recvbuf[1024];
        struct sockaddr_in source;
        int sourceLen = sizeof(source);
        int recvLen = recvfrom(sock, recvbuf, sizeof(recvbuf), 0, (struct sockaddr*)&source, &sourceLen);
        if (recvLen != SOCKET_ERROR && recvLen >= sizeof(ICMPHeader) + 20) {
            unsigned int ipHeaderLen = (recvbuf[0] & 0x0F) * 4;
            if (recvLen >= ipHeaderLen + sizeof(ICMPHeader)) {
                ICMPHeader *icmph = (ICMPHeader*)(recvbuf + ipHeaderLen);
                if (icmph->type == 0 && icmph->code == 0) {
                    uint32_t reply_ip = ntohl(source.sin_addr.s_addr);
                    if (reply_ip == target_ip) {
                        EnterCriticalSection(&print_lock);
                        responded_count++;
                        mvprintw(5 + responded_count, 0, "Host %s is \x1b[32mup\x1b[0m\n", ip_str);
                        if (log_fp) fprintf(log_fp, "Host %s is up\n", ip_str);
                        refresh();
                        LeaveCriticalSection(&print_lock);
                    }
                }
            }
        }
    }
    closesocket(sock);
    return 0;
}

void run_icmp_ping_sweep(struct in_addr net_addr, struct in_addr net_mask) {
    uint32_t net = ntohl(net_addr.s_addr);
    uint32_t mask = ntohl(net_mask.s_addr);
    if (mask == 0 || mask == 0xFFFFFFFF) {
        mvprintw(3, 0, "Cannot perform ping sweep on the given network.\n");
        refresh();
        return;
    }
    uint32_t first_ip = (net & mask) + 1;
    uint32_t broadcast = net | ~mask;
    uint32_t last_ip = broadcast - 1;
    if (last_ip < first_ip) {
        mvprintw(3, 0, "No hosts to scan in this network.\n");
        refresh();
        return;
    }
    g_target_count = last_ip - first_ip + 1;
    g_targets = (uint32_t*) malloc(g_target_count * sizeof(uint32_t));
    if (!g_targets) {
        mvprintw(3, 0, "Memory allocation error.\n");
        refresh();
        return;
    }
    for (uint32_t ip = first_ip, i = 0; ip <= last_ip; ++ip, ++i) {
        g_targets[i] = ip;
    }
    g_nextIndex = -1;
    responded_count = 0;

    int thread_count = (g_target_count < 64) ? g_target_count : 64;
    HANDLE *threads = (HANDLE*) malloc(thread_count * sizeof(HANDLE));
    if (!threads) {
        free(g_targets);
        mvprintw(3, 0, "Memory allocation error.\n");
        refresh();
        return;
    }
    for (int i = 0; i < thread_count; ++i) {
        threads[i] = CreateThread(NULL, 0, PingThreadProc, NULL, 0, NULL);
        if (threads[i] == NULL) {
            thread_count = i;
            break;
        }
    }
    bool aborted = false;
    while (1) {
        DWORD waitRes = WaitForMultipleObjects(thread_count, threads, TRUE, 100);
        if (waitRes == WAIT_OBJECT_0) {
            break;
        }
        int ch = getch();
        if (ch == 'q' || ch == 'Q') {
            scanning_active = 0;
            aborted = true;
        }
    }
    WaitForMultipleObjects(thread_count, threads, TRUE, INFINITE);
    for (int i = 0; i < thread_count; ++i) {
        if (threads[i] != NULL) CloseHandle(threads[i]);
    }
    free(threads);
    free(g_targets);

    if (aborted) {
        EnterCriticalSection(&print_lock);
        mvprintw(3, 0, "Scan aborted by user.\n");
        if (log_fp) fprintf(log_fp, "Scan aborted by user.\n");
        refresh();
        LeaveCriticalSection(&print_lock);
    }
}
