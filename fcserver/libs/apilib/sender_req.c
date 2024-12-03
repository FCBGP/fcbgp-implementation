#include "libapi.h"
#include "libdiag.h"
#include "libmbs.h"
#include "libreq.h"
#include "reqapi.h"

req_ctx_t* g_sender_req = NULL;

int sender_req_init(void)
{
    g_sender_req = req_create("senderreq", SENDERD_ADDRESS);
    if (g_sender_req == NULL)
    {
        DIAG_ERROR("create sender req failed.\n");
        return -ENOMEM;
    }

    return 0;
}

void sender_req_fini(void) { req_destroy(g_sender_req); }

int sender_version_req(req_ctx_t* req)
{
    char* command = SENDER_COMMAND_VERSION;

    if (req == NULL)
    {
        return -EINVAL;
    }

    mpack_write_str(&req->encoder, command, strlen(command));

    return req_request(req);
}

static void sender_meta_init(sender_meta_t* meta)
{
    meta->file = NULL;
    meta->ipver = NULL;
    meta->srcip = NULL;
    meta->dstip = NULL;
    meta->proto = NULL;
    meta->count = -1;
    meta->interval = -1;
}

void sender_meta_free(sender_meta_t* meta)
{
    mbsfree(meta->file);
    meta->file = NULL;
    mbsfree(meta->ipver);
    meta->ipver = NULL;
    mbsfree(meta->srcip);
    meta->srcip = NULL;
    mbsfree(meta->dstip);
    meta->dstip = NULL;
    mbsfree(meta->proto);
    meta->proto = NULL;
}

int sender_meta_pack(mpack_ctx_t* mpctx, sender_meta_t* meta)
{

    mpack_write_str(mpctx, meta->file, mbslen(meta->file));
    mpack_write_str(mpctx, meta->ipver, mbslen(meta->ipver));
    mpack_write_str(mpctx, meta->srcip, mbslen(meta->srcip));
    mpack_write_str(mpctx, meta->dstip, mbslen(meta->dstip));
    mpack_write_str(mpctx, meta->proto, mbslen(meta->proto));
    mpack_write_u16(mpctx, meta->count);
    mpack_write_u16(mpctx, meta->interval);

    return 0;
}

int sender_send_req(req_ctx_t* req, char* file, char* ipver, char* srcip,
                    char* dstip, char* proto, int count, int interval)
{
    char* command = SENDER_COMMAND_SEND;
    if (req == NULL)
    {
        return -EINVAL;
    }

    sender_meta_t sendmsg;
    sender_meta_init(&sendmsg);
    sender_meta_set_file(&sendmsg, file);
    sender_meta_set_ipver(&sendmsg, ipver);
    sender_meta_set_srcip(&sendmsg, srcip);
    sender_meta_set_dstip(&sendmsg, dstip);
    sender_meta_set_count(&sendmsg, count);
    sender_meta_set_interval(&sendmsg, interval);

    mpack_write_str(&req->encoder, command, strlen(command));
    sender_meta_pack(&req->encoder, &sendmsg);

    sender_meta_free(&sendmsg);

    return req_request(req);
}
