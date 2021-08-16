<h1 align="center">
	<img src="https://cdn0.iconfinder.com/data/icons/tidee-health/24/015_007_first_aid_kit_chest-512.png" width="150px"><br>
    kit - A network utility that has several features.
</h1>
<p align="center">
	kit is a network utility, that contains several tools, including a packet-sniffer. To use the packet-sniffer, make sure you're root.
</p>

<p align="center">
	<a href="https://deno.land" target="_blank">
    	<img src="https://img.shields.io/badge/Version-1.0.0-7DCDE3?style=for-the-badge" alt="Version">
     </a>
	<a href="https://deno.land" target="_blank">
    	<img src="https://img.shields.io/badge/Deno-1.0.0+-7DCDE3?style=for-the-badge" alt="Node">
     </a>
</p>

## Setup
```
sudo apt-get install libpcap-dev
gcc -o kit kit.c -lpcap
./kit
```

## Configuring Port-Range
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <pcap.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

// Go to this part of the file and change your port-range, if you want!
#define PORT_START 1
#define PORT_END 1204
#define PORT 1335
```

## Usage
```
┌───────┬───────────────────────────────────────┬───────────────┐
│ Flags │              Description              │ Usage Example │
├───────┼───────────────────────────────────────┼───────────────┤
│ -h    │ Displays the available flags          │ -h            │
│ -i    │ Displays the available interfaces     │ -i            │
│ -m    │ Displays the network mask             │ -m            │
│ -s    │ Starts a packet sniffer               │ -s            │
│ -b    │ Starts a bind-shell                   │ -b            │
│ -t    │ Starts a TCP server                   │ -t 127.0.0.1  │
│ -p    │ Does a port scan against the given IP │ -p 127.0.0.1  │
└───────┴───────────────────────────────────────┴───────────────┘
```

## Screenshots
![image](https://user-images.githubusercontent.com/86132648/128873348-bdf1348c-b69c-4f7a-b171-06b0831d3c22.png)

## Credits
```
https://github.com/0x1CA3
```

### Contributions 🎉
###### All contributions are accepted, simply open an Issue / Pull request.
