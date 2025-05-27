# PacketStrike

**PacketStrike** is a fast, multi-threaded IP and port scanner for Windows, written in C.  
It uses raw sockets for high-performance ICMP (ping), ARP, and TCP SYN scanning, and displays results in a terminal user interface (TUI) powered by [PDCurses](https://github.com/wmcbrine/PDCurses).

**PacketStrike is built for speed, visibility, and direct console operation — think Nmap meets fast, native Windows scanning.**

---

## Features

- ⚡ **Extremely Fast:** Multi-threaded sweep across /24 or larger subnets.
- 🎯 **Scan Types:** ICMP (Ping), ARP, and TCP SYN scanning supported.
- 🖥️ **Terminal UI:** Runs in the Windows terminal/console with a curses-like interface.
- 👷 **Low-level Access:** Uses raw sockets for maximum scanning flexibility (requires Admin).
- 📝 **Logging:** Optional logging to file.
- 🛡️ **Minimal Dependencies:** Pure C, portable, uses PDCurses for TUI only.

---

## Requirements

- Windows 7 or later (tested on Windows 10/11).
- **MSVC (Microsoft Visual C/C++ Compiler)** – Build using Developer Command Prompt or from Visual Studio.
- **Admin privileges** — Raw sockets require elevation for ICMP/TCP SYN scanning.
- [PDCurses](https://github.com/wmcbrine/PDCurses) (included in repo, or place in `PDCurses/` in your project root).

---

## Build Instructions

### 1. **Clone or Download**

```sh
git clone https://github.com/YOUR_USER/PacketStrike.git
cd PacketStrike
```

2. Install PDCurses
Download the PDCurses source.

Copy all *.h headers into PacketStrike/PDCurses/.

Build the PDCurses library:

Open Developer Command Prompt for VS.
```
cd PacketStrike\PDCurses\wincon
```

Run:
```
sh
Copy
Edit
nmake -f Makefile.vc
```

Result: pdcurses.lib should appear in PDCurses\wincon\

3. Build PacketStrike
In your main project folder:

```
sh
Copy
Edit
cl /MT /O2 ^
   /I"PDCurses" ^
   main.c ping_scan.c arp_scan.c tcp_scan.c ^
   ws2_32.lib Iphlpapi.lib user32.lib gdi32.lib advapi32.lib ^
   PDCurses\wincon\pdcurses.lib ^
   /link /SUBSYSTEM:CONSOLE /OUT:PacketStrike.exe
```

Note:

All .c files and headers must be present in the directory.

Use the correct paths for your setup.

Usage
```
PacketStrike.exe --icmp --subnet 10.20.0.0/24
PacketStrike.exe --arp --subnet 192.168.1.0/24
PacketStrike.exe --syn --subnet 172.16.10.0/24 --port 22,80,443
```
Common Flags:

Flag	Description
--icmp	Run ICMP ping sweep
--arp	Run ARP scan
--syn	Run TCP SYN scan
--iface	Specify interface (e.g., Ethernet)
--subnet	Target subnet in CIDR (e.g., 10.20.0.0/24)
--rate	Packets/sec for batch sweep (default: fast)
--timeout	Timeout for replies (e.g., 500ms, 1s)
--port	TCP ports for SYN scan (e.g., 80,443,22)

Example:
```
PacketStrike.exe --icmp --subnet 10.20.1.0/24 --timeout 1s
```
