/********************************************************************************
 * File Name:    test_msg_bgpd.c
 * Author:       basilguo@163.com
 * Version:      0.0.1
 * Created Time: 2024-08-16 07:08:34
 * Description:
 * Usage:
 *  1. enable FCS 10.
 *  2. run this.
 *******************************************************************************/

#ifdef __cplusplus
extern "C"
{
#endif

#include "defines.h"
#include "pyutils.h"
#include "sigutils.h"

#define FC_MSG_BM_FIX_LEN 24

    static EC_KEY *prikey10 = NULL, *pubkey10 = NULL;
    static EC_KEY *prikey20 = NULL, *pubkey20 = NULL;
    static char ski10[20], ski20[20];

    static int env_init()
    {
        int ret = 0;
        char *fpath = "/etc/frr/assets/10.key";
        ret = fc_read_eckey_from_file(fpath, 0 /* is_pubkey */, prikey10);
        FC_ASSERT_RET(ret);

        fpath = "/etc/frr/assets/10.cert";
        ret = fc_read_eckey_from_file(fpath, 1 /* is_pubkey */, pubkey10);
        FC_ASSERT_RET(ret);

        fpath = "/etc/frr/assets/20.key";
        ret = fc_read_eckey_from_file(fpath, 0 /* is_pubkey */, prikey20);
        FC_ASSERT_RET(ret);

        fpath = "/etc/frr/assets/20.cert";
        ret = fc_read_eckey_from_file(fpath, 1 /* is_pubkey */, pubkey20);
        FC_ASSERT_RET(ret);

        return 0;
    }

    static int sock_finish(int sockfd)
    {
        if (sockfd >= 0)
        {
            close(sockfd);
        }
        return 0;
    }

    static int sock_init(int *sockfd, int srv_port, const char *srv_straddr)
    {
        int ret = 0;

        *sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (*sockfd < 0)
        {
            perror("socket()");
            exit(-1);
        }

        struct sockaddr_in sockaddr;
        sockaddr.sin_family = AF_INET;
        sockaddr.sin_port = htons(*srv_port);
        if (inet_pton(AF_INET, srv_straddr, &sockaddr.sin_addr) == NULL)
        {
            perror("inet_pton()");
        }

        ret = connect(sockfd, (struct sockaddr *)&sockaddr,
                      sizeof(sockaddr));
        if (ret != 0)
        {
            perror("connect()");
            sock_finish(*sockfd);
        }

        return 0;
    }

    static int send_msg(int sockfd, const char *buf, int buflen)
    {
        int txlen = 0, len = 0;
        while (len < buflen)
        {
            txlen = send(sockfd, buf + len, buflen - len, 0);
            len += txlen;
        }
        printf("Send to %d total size: %dB\n", sockfd, buflen);

        return 0;
    }

    static int test_msg_bgpd_ip4(int sockfd, FC_msg_hdr_t *hdr, FC_msg_bm_t *bm)
    {
        int ret = 0, buflen = 0;
        char *buf = NULL;
        u8 val8 = 0;
        u16 val16 = 0;
        u32 val32 = 0;

        buf = calloc(BUFSIZ, sizeof(char));
        FC_ASSERT_PTR(buf);
        buflen = FC_MSG_BM_FIX_LEN;

        memcpy(buf, &bm, buflen);

        // src_ip
        val32 = htonl(0x0A000000);
        memcpy(buf + buflen, &val32, sizeof(u32));
        buflen += sizeof(u32);
        val8 = 0x18;
        memcpy(buf + buflen, &val8, sizeof(u8));
        buflen += sizeof(u8);
        // dst_ip
        val32 = htonl(0x14000000);
        memcpy(buf + buflen, &val32, sizeof(u32));
        buflen += sizeof(u32);
        val8 = 0x18;
        memcpy(buf + buflen, &val8, sizeof(u8));
        buflen += sizeof(u8);

        // fclist
        for (int i = 0; i < 1; ++i)
        {
            // pasn
            val32 = 0;
            memcpy(buf + buflen, &val32, sizeof(u32));
            buflen += sizeof(u32);
            // casn
            val32 = 20;
            memcpy(buf + buflen, &val32, sizeof(u32));
            buflen += sizeof(u32);
            // nasn
            val32 = 10;
            memcpy(buf + buflen, &val32, sizeof(u32));
            buflen += sizeof(u32);
            // ski
            // algo id
            // flags
            // siglen
            // sig
        }

        // ski -- not needed
        // signature -- not needed

        val16 = htons(buflen);
        memcpy(buf + 2, &val16, sizeof(u16));

        ret = send_msg(sockfd, buf, buflen);

        if (buf != NULL)
        {
            free(buf);
            buf = NULL;
        }

        return ret;
    }

    int main(int argc, char *argv[])
    {
        int sockfd = 0, ret = 0, choice = 0, len = 0;

        ret = env_init();
        ret = sock_init(&sockfd, 23160, "127.0.0.1");

        FC_msg_hdr_t hdr = {
            .version = 1,
            .type = 2,
            .length = 0, // TBD
        };

        FC_msg_bm_t bm = {
            .bmversion = 1,
            .ipversion = 4,
            .flags = 0,
            .algoid = 1,
            .src_ip_num = htons(1),
            .dst_ip_num = htons(1),
            .fc_num = htons(1),
            .siglen = 0, // TBD
            .local_asn = htonl(10),
            .version = 0,
            .subversion = 0,
        };

        while (choice != 0)
        {
            printf("1. Send ip4 prefix from bgpd10 to fcserver10\n");
            printf("2. Send ip6 prefix from bgpd10 to fcserver10\n");
            printf("3. Send ip4 prefix from fcserver20 to fcserver10\n");
            printf("4. Send ip6 prefix from fcserver20 to fcserver10\n");
            printf("5. Add topo information to fcserver10\n");
            printf("6. Delete topo information from fcserver10\n");
            printf("Enter your choice: ");
            scanf("%d", &choice);
            switch (choice)
            {
            case 0:
                printf("Bye~\n");
                break;
            case 1:
                test_msg_bgpd_ip4(sockfd, &hdr, &bm);
                break;
            case 2:
                test_msg_bgpd_ip6(sockfd, &hdr, &bm);
                break;
            case 3:
                test_msg_bc_ip4(sockfd, &hdr, &bm);
                break;
            case 4:
                test_msg_bc_ip6(sockfd, &hdr, &bm);
                break;
            case 5:
                test_msg_topo_add(sockfd);
                break;
            case 6:
                test_msg_topo_del(sockfd);
                break;
            default:
                fprintf(stderr, "Wrong input. Try again\n");
                break;
            }
        }

        ret = sock_finish(sockfd);

        return 0;
    }

#ifdef __cplusplus
}
#endif
