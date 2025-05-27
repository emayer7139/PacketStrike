#include "scanner.h"

// Shared data for ARP threads
static uint32_t *a_targets = NULL;
static int a_target_count = 0;
static volatile LONG a_nextIndex = -1;

// Thread procedure for ARP scanning one IP
DWORD WINAPI ArpThreadProc(LPVOID param) {
    // Buffer to hold MAC address (6 bytes for Ethernet)
    ULONG macAddr[2];  // Allocate 2 ULONGs (8 bytes) to hold 6-byte MAC and padding
    ULONG macLen = 6;
    while (scanning_active) {
        LONG index = InterlockedIncrement(&a_nextIndex);
        if (index >= a_target_count) break;
        uint32_t target_ip = a_targets[index];
        IPAddr destIp = htonl(target_ip);
        IPAddr srcIp = 0; // 0 = use any local interface (we could specify local IP to ensure correct NIC)
        DWORD result = SendARP(destIp, srcIp, macAddr, &macLen);
        if (result == NO_ERROR) {
            // Got a MAC address, meaning host is present
            EnterCriticalSection(&print_lock);
            responded_count++;
            mvprintw(5 + responded_count, 0, "Host %d.%d.%d.%d is \x1b[32mup\x1b[0m (ARP)\n",
                     (target_ip >> 24) & 0xFF, (target_ip >> 16) & 0xFF,
                     (target_ip >> 8) & 0xFF, target_ip & 0xFF);
            if (log_fp) {
                fprintf(log_fp, "Host %d.%d.%d.%d is up (ARP)\n",
                        (target_ip >> 24) & 0xFF, (target_ip >> 16) & 0xFF,
                        (target_ip >> 8) & 0xFF, target_ip & 0xFF);
            }
            refresh();
            LeaveCriticalSection(&print_lock);
        }
        // If SendARP fails (e.g., ERROR_BAD_NET_NAME for no reply), the host is likely down or unreachable.
        // Loop to next target...
    }
    return 0;
}

void run_arp_scan(struct in_addr net_addr, struct in_addr net_mask) {
    // Determine target range (same logic as ICMP)
    uint32_t net = ntohl(net_addr.s_addr);
    uint32_t mask = ntohl(net_mask.s_addr);
    if (mask == 0 || mask == 0xFFFFFFFF) {
        mvprintw(3, 0, "Cannot perform ARP scan on this network.\n");
        refresh();
        return;
    }
    uint32_t first_ip = (net & mask) + 1;
    uint32_t broadcast = net | ~mask;
    uint32_t last_ip = broadcast - 1;
    if (last_ip < first_ip) {
        mvprintw(3, 0, "No hosts to scan.\n");
        refresh();
        return;
    }
    // Build target list
    a_target_count = last_ip - first_ip + 1;
    a_targets = (uint32_t*) malloc(a_target_count * sizeof(uint32_t));
    if (!a_targets) {
        mvprintw(3, 0, "Memory allocation error.\n");
        refresh();
        return;
    }
    for (uint32_t ip = first_ip, i = 0; ip <= last_ip; ++ip, ++i) {
        a_targets[i] = ip;
    }
    a_nextIndex = -1;
    responded_count = 0;

    // Launch threads (similar to ping, up to 64 threads)
    int thread_count = (a_target_count < 64) ? a_target_count : 64;
    HANDLE *threads = (HANDLE*) malloc(thread_count * sizeof(HANDLE));
    if (!threads) {
        free(a_targets);
        mvprintw(3, 0, "Memory allocation error.\n");
        refresh();
        return;
    }
    for (int i = 0; i < thread_count; ++i) {
        threads[i] = CreateThread(NULL, 0, ArpThreadProc, NULL, 0, NULL);
        if (threads[i] == NULL) {
            thread_count = i;
            break;
        }
    }

    // Monitor threads and allow abort
    bool aborted = false;
    while (1) {
        DWORD waitRes = WaitForMultipleObjects(thread_count, threads, TRUE, 100);
        if (waitRes == WAIT_OBJECT_0) {
            break; // all done
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
    free(a_targets);

    if (aborted) {
        EnterCriticalSection(&print_lock);
        mvprintw(3, 0, "ARP scan aborted by user.\n");
        if (log_fp) fprintf(log_fp, "ARP scan aborted by user.\n");
        refresh();
        LeaveCriticalSection(&print_lock);
    }
}
