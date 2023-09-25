#include "libdiag.h"
#include "libsessmgr.h"

static sess_ctx_t *g_sess_ctx = NULL;

static sess_node_t *sess_node_create(void)
{
    sess_node_t *node = malloc(sizeof(sess_node_t));
    if (node == NULL) {
        return NULL;
    }

    memset(node, 0, sizeof(sess_node_t));
    return node;
}

static int sess_node_destroy(sess_node_t *node)
{
    if (node) {
        free(node);
    }

    return 0;
}

static int sess_random_read(char *buffer, int len)
{
    int ret;
    FILE *fp = NULL;

    fp = fopen("/dev/urandom", "rb");
    if (!fp) {
        return -ENOENT;
    }

    ret = fread(buffer, 1, len, fp);
    if (ret != len) {
        fclose(fp);
        return -EIO;
    }

    fclose(fp);
    return 0;
}

static int sess_token_gen(sess_node_t *node)
{
    int i;
    int len = (sizeof(node->token) - 1) / 2;
    char buffer[128] = {0, };

    sess_random_read(buffer, sizeof(buffer));

    for (i=0; i<len; i++) {
        snprintf(node->token + i * 2, sizeof(node->token) - i * 2, "%02X", buffer[i] & 0xFF);
    }

    node->token[i * 2] = '\0';
    return 0;
}

int sess_mgr_init(void)
{
    g_sess_ctx = malloc(sizeof(sess_ctx_t));
    if (g_sess_ctx == NULL) {
        return -ENOMEM;
    }

    INIT_LIST_HEAD(&g_sess_ctx->head);
    mutex_init(&g_sess_ctx->mutex);
    g_sess_ctx->sessidx = 0;
    g_sess_ctx->sesscnt = 0;
    return 0;
}

void sess_mgr_clear(void)
{
    sess_node_t *node, *tmp;

    mutex_lock(&g_sess_ctx->mutex);
    list_for_each_entry_safe(node, tmp, &g_sess_ctx->head, node) {
        list_del(&node->node);
        sess_node_destroy(node);
    }
    g_sess_ctx->sesscnt = 0;
    mutex_unlock(&g_sess_ctx->mutex);
}

void sess_mgr_fini(void)
{
    if (g_sess_ctx) {
        sess_mgr_clear();
        mutex_destroy(&g_sess_ctx->mutex);
        free(g_sess_ctx);
        g_sess_ctx = NULL;
    }
    return;
}

int sess_mgr_insert(mpack_ctx_t *encoder, char *username, char *sipaddr, uint16_t sport, int timeout, int type)
{
    sess_node_t *node;

    if (type >= SESS_TYPE_MAX) {
        return -EINVAL;
    }

    mutex_lock(&g_sess_ctx->mutex);
    list_for_each_entry(node, &g_sess_ctx->head, node) {
        if (strcmp(node->username, username) == 0) {
            if (node->type == type) {
                node->sport = sport;
                node->timeout = timeout;
                node->expired = timeout + time(NULL);
                strncpy(node->sipaddr, sipaddr, sizeof(node->sipaddr));

                sess_token_gen(node);
                sess_node_pack(encoder, node, 1);
                DIAG_DEBUG("username %s type %d update token to %s\n", node->username, node->type, node->token);
                mutex_unlock(&g_sess_ctx->mutex);
                return 0;
            }
        }
    }

    node = sess_node_create();
    if (node == NULL) {
        mutex_unlock(&g_sess_ctx->mutex);
        return -ENOMEM;
    }

    node->type = type;
    node->sport = sport;
    node->sessid = g_sess_ctx->sessidx++;
    node->timeout = timeout;
    node->expired = timeout + time(NULL);
    strncpy(node->sipaddr, sipaddr, sizeof(node->sipaddr));
    strncpy(node->username, username, sizeof(node->username));

    sess_token_gen(node);
    sess_node_pack(encoder, node, 1);
    DIAG_DEBUG("username %s type %d gen new token %s\n", node->username, node->type, node->token);
    list_add_tail(&node->node, &g_sess_ctx->head);

    g_sess_ctx->sesscnt++;
    mutex_unlock(&g_sess_ctx->mutex);

    return 0;
}

int sess_mgr_delete(int sessid)
{
    sess_node_t *node, *tmp;

    mutex_lock(&g_sess_ctx->mutex);
    list_for_each_entry_safe(node, tmp, &g_sess_ctx->head, node) {
        if (node->sessid == sessid) {
            list_del(&node->node);
            sess_node_destroy(node);
            g_sess_ctx->sesscnt--;
            mutex_unlock(&g_sess_ctx->mutex);
            return 0;
        }
    }
    mutex_unlock(&g_sess_ctx->mutex);

    return -ENOENT;
}

int sess_mgr_refresh(char *username, int type)
{
    sess_node_t *node;

    mutex_lock(&g_sess_ctx->mutex);
    list_for_each_entry(node, &g_sess_ctx->head, node) {
        if (strcmp(node->username, username) == 0) {
            if (node->type == type) {
                node->expired = node->timeout + time(NULL);
                mutex_unlock(&g_sess_ctx->mutex);
                return 0;
            }
        }
    }
    mutex_unlock(&g_sess_ctx->mutex);

    return -ENOENT;
}

void sess_mgr_logout(char *username, int type)
{
    // level: AUDIT_LEVEL_INFO
    // source: AUDIT_SOURCE_SESSMGRD
    // evid: WEBD_EVENT_USER_TIMEOUT
    vasystem("auditcmd /audit/insert evid 0xF102 level 1 source 4 message '%s#%s'", username, (type == 0) ? "CLI" : "WebUI");
}

int sess_mgr_timeout(void)
{
    int cnt = 0;
    sess_node_t *node, *tmp;

    mutex_lock(&g_sess_ctx->mutex);
    list_for_each_entry_safe(node, tmp, &g_sess_ctx->head, node) {
        if (sess_node_timeout(node)) {
            list_del(&node->node);
            DIAG_INFO("username %s type %d was timeout!\n", node->username, node->type);
            sess_mgr_logout(node->username, node->type);
            sess_node_destroy(node);
            g_sess_ctx->sesscnt--;
            cnt++;
        }
    }
    mutex_unlock(&g_sess_ctx->mutex);

    return cnt;
}

int sess_mgr_list(mpack_ctx_t *encoder)
{
    sess_node_t *node;

    mutex_lock(&g_sess_ctx->mutex);
    mpack_write_array(encoder, g_sess_ctx->sesscnt);
    list_for_each_entry(node, &g_sess_ctx->head, node) {
        sess_node_pack(encoder, node, 0);
    }
    mutex_unlock(&g_sess_ctx->mutex);
    return 0;
}

int sess_mgr_find_user(mpack_ctx_t *encoder, char *username, int type)
{
    sess_node_t *node;

    mutex_lock(&g_sess_ctx->mutex);
    list_for_each_entry(node, &g_sess_ctx->head, node) {
        if (strcmp(node->username, username) == 0) {
            if (node->type == type) {
                node->expired = node->timeout + time(NULL);
                sess_node_pack(encoder, node, 0);
                mutex_unlock(&g_sess_ctx->mutex);
                return 0;
            }
        }
    }
    mutex_unlock(&g_sess_ctx->mutex);

    return -ENOENT;
}

int sess_mgr_find_token(mpack_ctx_t *encoder, char *token)
{
    sess_node_t *node;

    mutex_lock(&g_sess_ctx->mutex);
    list_for_each_entry(node, &g_sess_ctx->head, node) {
        if (strcmp(node->token, token) == 0) {
            node->expired = node->timeout + time(NULL);
            sess_node_pack(encoder, node, 0);
            mutex_unlock(&g_sess_ctx->mutex);
            return 0;
        }
    }
    mutex_unlock(&g_sess_ctx->mutex);

    return -ENOENT;
}

