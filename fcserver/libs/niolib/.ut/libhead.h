#ifndef _LIB_HEAD_H__
#define _LIB_HEAD_H__

#define SYN 2

typedef struct psd_hdr
{
	uint32_t saddr; //源地址
	uint32_t daddr; //目的地址
	uint8_t mbz;
    uint8_t ptcl; //协议类型
	uint16_t tcpl; //TCP长度

}PSD_HEADER;

//定义TCP报头
typedef struct _tcphdr
{
	unsigned short th_sport; //16位源端口
	unsigned short th_dport; //16位目的端口
	unsigned int th_seq; //32位序列号
	unsigned int th_ack; //32位确认号
	unsigned char th_lenres; //4位首部长度/4位保留字
	unsigned char th_flag; //6位标志位
	unsigned short th_win; //16位窗口大小
	unsigned short th_sum; //16位校验和
	unsigned short th_urp; //16位紧急数据偏移量

} TCP_HEADER;


//定义IP报头
typedef struct _iphdr
{
	unsigned char h_lenver ; //长度加版本号
	unsigned char tos;
	unsigned short total_len;
	unsigned short ident;
	unsigned short frag_and_flags;
	unsigned char ttl;
	unsigned char proto;
	unsigned short checksum;
	unsigned int sourceIP;
	unsigned int destIP;

} IP_HEADER;

#endif
