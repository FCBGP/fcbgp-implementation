#include "errno.h"
#include "libcut.h"
#include "liblistener.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "sys/types.h"
#include "sys/wait.h"
#include "unistd.h"

#define NUM_PIPES 3

static int pipevs[NUM_PIPES][2];
static int preempt_cnt = 0;
static int marked_cnt = 0;
static int read_cnt = 0;
static int timeout_cnt = 0;

listenerset_t g_listener_set;

static void exit_handler(void)
{
    if (preempt_cnt != 9)
    {
        cut_printf("invalid preempt_cnt: %d\n", preempt_cnt);
        abort();
    }
    if (marked_cnt != 3)
    {
        cut_printf("invalid marked_cnt: %d\n", marked_cnt);
        abort();
    }
    if (read_cnt != 3)
    {
        cut_printf("invalid read_cnt: %d\n", read_cnt);
        abort();
    }
    if (timeout_cnt != 3)
    {
        cut_printf("invalid timeout_cnt: %d\n", timeout_cnt);
        abort();
    }
    return;
}

static int listener_handler(listener_t* listener, listen_event_t type)
{
    static int loop_watch = 0;
    if (loop_watch > 25)
    {
        cut_printf("too many loops--something's wrong\n");
        exit(1);
    }
    ++loop_watch;
    if (type & LISTEN_EVENT_PREEMPT)
    {
        cut_printf("preempt for %d\n", listener->fd);
        ++preempt_cnt;
        return 0;
    }
    if (type & LISTEN_EVENT_MARKED)
    {
        cut_printf("marked for %d\n", listener->fd);
        ++marked_cnt;
        return 0;
    }
    if (type & LISTEN_EVENT_READ)
    {
        char buf[10];
        ssize_t n = read(listener->fd, buf, sizeof(buf));
        listenerset_mark(&g_listener_set);
        if (n > 0)
        {
            cut_printf("read %lu bytes from %d\n", (unsigned long)n,
                       listener->fd);
            ++read_cnt;
            return 0;
        }
        if (n < 0)
        {
            cut_printf("read: %m\n");
            exit(1);
        }
    }
    if (type & LISTEN_EVENT_TIMEOUT)
    {
        cut_printf("timeout for %d\n", listener->fd);
        ++timeout_cnt;
    }
    close(listener->fd);
    listener_remove(listener);
    cut_printf("remove listener %d\n", listener->fd);
    return 0;
}

static void do_child_process(void)
{
    int i;
    if (atexit(exit_handler) != 0)
    {
        cut_printf("unable to add atexit handler: %m\n");
        exit(1);
    }
    for (i = 0; i < NUM_PIPES; i++)
    {
        cut_printf("add listener %d\n", pipevs[i][0]);
        listenerset_add(&g_listener_set, pipevs[i][0], listener_handler,
                        LISTEN_EVENT_READ | LISTEN_EVENT_TIMEOUT |
                            LISTEN_EVENT_PREEMPT | LISTEN_EVENT_MARKED,
                        NULL, 1);
    }

    if (listenerset_loop(&g_listener_set) < 0)
    {
        cut_printf("listenerset_loop: %m\n");
        exit(1);
    }
    exit(0);
}

int main_test(int argc, char* argv[])
{
    int i;
    pid_t child_pid;

    cut_printf("try to create pipes.\n");
    for (i = 0; i < NUM_PIPES; i++)
    {
        if (pipe(pipevs[i]) < 0)
        {
            cut_printf("Failed! pipe: %m\n");
            return CUT_FAILED;
        }
    }

    cut_printf("try to fork child process.\n");
    if ((child_pid = fork()) == 0)
    {
        char* sleep_str;
        sleep_str = getenv("LISTENER_SLEEP\n");
        if (sleep_str)
        {
            cut_printf("sleeping %d seconds\n", atoi(sleep_str));
            sleep(atoi(sleep_str));
        }
        do_child_process();
    }
    else
    {
        char* buf = "test";
        int status;
        cut_printf("child_pid=%d\n", (int)child_pid);
        for (i = 0; i < NUM_PIPES; i++)
        {
            if (write(pipevs[i][1], buf, strlen(buf)) != strlen(buf))
            {
                cut_printf("Failed! write: %m\n");
                return CUT_FAILED;
            }
        }
        if (wait(&status) < 0)
        {
            cut_printf("Failed! wait: %m\n");
            return CUT_FAILED;
        }
        if (WIFEXITED(status))
        {
            if (WEXITSTATUS(status) != 0)
            {
                cut_printf("pid %d stopped with exit status %d\n",
                           (int)child_pid, WEXITSTATUS(status));
                return CUT_FAILED;
            }
        }
        else if (WIFSIGNALED(status))
        {
            cut_printf("pid %d stopped with signal %d\n", (int)child_pid,
                       WTERMSIG(status));
            return CUT_FAILED;
        }
    }

    return CUT_PASSED;
}

void cut_define(void* ctx)
{
    cut_set_name(ctx, "listener");
    cut_add_test(ctx, 1, "main_test", main_test, NULL,
                 "listener test main entry");
}

int main(int argc, char* argv[])
{
    listenerset_init(&g_listener_set);
    RUN_CUT("listener", argc, argv, cut_define);
    return 0;
}
