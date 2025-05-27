#ifndef PACKETSTRIKE_SCANNER_H
#define PACKETSTRIKE_SCANNER_H

// Standard Library and Windows headers
#define _WIN32_WINNT 0x0601  // target Windows 7 or later
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stdbool.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <string.h>
#include <iphlpapi.h>
#include <synchapi.h>

// PDCurses (always just <curses.h> for PDCurses!)
#include <curses.h>  // PDCurses header - make sure the include path is set correctly

// Link with necessary Windows libraries
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
// pdcurses.lib must be provided during linking

// Global synchronization and logging handles (defined in main.c)
extern CRITICAL_SECTION print_lock;
extern FILE *log_fp;
extern volatile int scanning_active;
extern volatile int responded_count;

// Scan mode function prototypes
void run_icmp_ping_sweep(struct in_addr net_addr, struct in_addr net_mask);
void run_arp_scan(struct in_addr net_addr, struct in_addr net_mask);
void run_tcp_syn_scan(struct in_addr net_addr, struct in_addr net_mask);

#endif // PACKETSTRIKE_SCANNER_H
