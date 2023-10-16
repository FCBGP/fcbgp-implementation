#include "libsysmgr.h"

#define SYS_PROC_PATH_NET_UDP SYS_PROC_PATH "net/udp"
#define SYS_PROC_PATH_NET_TCP SYS_PROC_PATH "net/tcp"

#define CONNECTION_ESTABLISHED      "ESTABLISHED"
#define CONNECTION_SYN_SENT         "SYN_SENT"
#define CONNECTION_SYN_RECV         "SYN_RECV"
#define CONNECTION_FIN_WAIT1        "FIN_WAIT1"
#define CONNECTION_FIN_WAIT2        "FIN_WAIT2"
#define CONNECTION_TIME_WAIT        "TIME_WAIT"
#define CONNECTION_CLOSED           "CLOSED"
#define CONNECTION_CLOSED_WAIT      "CLOSED_WAIT"
#define CONNECTION_LAST_ACK         "LAST_ACK"
#define CONNECTION_LISTEN           "LISTEN"
#define CONNECTION_CLOSING          "CLOSING"
#define CONNECTION_UNKNOWN          "UNKNONWN"

static const char *parse_connstate(int what)
{
    const char *state = NULL;

    switch (what) {
    case 1:
        state = CONNECTION_ESTABLISHED;
        break;
    case 2:
        state = CONNECTION_SYN_SENT;
        break;
    case 3:
        state = CONNECTION_SYN_RECV;
        break;
    case 4:
        state = CONNECTION_FIN_WAIT1;
        break;
    case 5:
        state = CONNECTION_FIN_WAIT2;
        break;
    case 6:
        state = CONNECTION_TIME_WAIT;
        break;
    case 7:
        state = CONNECTION_CLOSED;
        break;
    case 8:
        state = CONNECTION_CLOSED_WAIT;
        break;
    case 9:
        state = CONNECTION_LAST_ACK;
        break;
    case 10:
        state = CONNECTION_LISTEN;
        break;
    case 11:
        state = CONNECTION_CLOSING;
        break;
    default:
        state = CONNECTION_UNKNOWN;
        break;
    }

    return state;
}

/*
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   1: 00000000:0801 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 11995 2 f4da7500
   1: 00000000:8001 00000000:0000 07 00000000:00000000 00:00000000 00000000   110        0 11904 2 f4da7300
  55: 00000000:0337 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 12016 2 f4da7700
  69: 00000000:0045 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 11893 2 f0627d80
 111: 00000000:006F 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 8922 2 f53fc680
 117: 00000000:02F5 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 11894 2 f4da7100
*/
#define PROC_NET_TCPUDP_FMT     "%d:%s %s %02x"
static int sys_tcpudpinfo_get(const char *file, sys_tcpinfo_t ** ptcpudpinfos)
{
    int cnt = 0;
    FILE *fp = NULL;
    char buf[256] = { 0, };

    sys_tcpinfo_t *tail = NULL;
    sys_tcpinfo_t *head = NULL;
    sys_tcpinfo_t *tcpudpinfo = NULL;

    fp = fopen(file, "r");
    if (fp == NULL) {
        return -ENOENT;
    }

    /* Skip header */
    fgets(buf, sizeof(buf), fp);

    while (fgets(buf, sizeof(buf), fp)) {
        unsigned int state;
        char local[16] = {0, };
        char remote[16] = {0, };
        char *l_port, *r_port, *l_ip, *r_ip, *ptr;

        tcpudpinfo = calloc(1, sizeof(sys_tcpinfo_t));
        if (!tcpudpinfo) {
            return -ENOMEM;
        }

        if (sscanf(buf, PROC_NET_TCPUDP_FMT, &tcpudpinfo->slot, local, remote, &state) != 4) {
            free(tcpudpinfo);
            continue;
        }

        l_ip = local;
        r_ip = remote;

        if ((ptr = strchr(local, ':')) != NULL)
            *ptr++ = '\0';
        l_port = ptr;

        if ((ptr = strchr(remote, ':')) != NULL)
            *ptr++ = '\0';
        r_port = ptr;

        tcpudpinfo->laddr = parse_hex32(l_ip);
        tcpudpinfo->lport = parse_hex16(l_port);
        tcpudpinfo->raddr = parse_hex32(r_ip);
        tcpudpinfo->rport = parse_hex16(r_port);
        tcpudpinfo->state = parse_connstate(state);

        if (tail) {
            tail->next = tcpudpinfo;
            tail = tcpudpinfo;
        } else {
            head = tcpudpinfo;
            tail = tcpudpinfo;
        }

        cnt++;
    }

    *ptcpudpinfos = head;
    fclose(fp);
    return cnt;
}

int sys_udpinfo_get(sys_udpinfo_t ** pudpinfos)
{
    return sys_tcpudpinfo_get(SYS_PROC_PATH_NET_UDP, pudpinfos);
}

int sys_tcpinfo_get(sys_tcpinfo_t ** ptcpinfos)
{
    return sys_tcpudpinfo_get(SYS_PROC_PATH_NET_TCP, ptcpinfos);
}

int sys_tcpinfo_free(sys_tcpinfo_t *tcpinfos)
{
    sys_tcpinfo_t *cur = NULL;
    sys_tcpinfo_t *next = NULL;

    if (tcpinfos == NULL) {
        return 0;
    }

    cur = tcpinfos;
    while (cur) {
        next = cur->next;
        free(cur);
        cur = next;
    }

    return 0;
}

int sys_udpinfo_free(sys_udpinfo_t *udpinfos)
{
    sys_udpinfo_t *cur = NULL;
    sys_udpinfo_t *next = NULL;

    if (udpinfos == NULL) {
        return 0;
    }

    cur = udpinfos;
    while (cur) {
        next = cur->next;
        free(cur);
        cur = next;
    }

    return 0;
}

