#ifndef _LIB_HEAD_H__
#define _LIB_HEAD_H__

#define SYN 2

typedef struct psd_hdr
{
	uint32_t saddr; //Դ��ַ
	uint32_t daddr; //Ŀ�ĵ�ַ
	uint8_t mbz;
    uint8_t ptcl; //Э������
	uint16_t tcpl; //TCP����

}PSD_HEADER;

//����TCP��ͷ
typedef struct _tcphdr
{
	unsigned short th_sport; //16λԴ�˿�
	unsigned short th_dport; //16λĿ�Ķ˿�
	unsigned int th_seq; //32λ���к�
	unsigned int th_ack; //32λȷ�Ϻ�
	unsigned char th_lenres; //4λ�ײ�����/4λ������
	unsigned char th_flag; //6λ��־λ
	unsigned short th_win; //16λ���ڴ�С
	unsigned short th_sum; //16λУ���
	unsigned short th_urp; //16λ��������ƫ����

} TCP_HEADER;


//����IP��ͷ
typedef struct _iphdr
{
	unsigned char h_lenver ; //���ȼӰ汾��
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
