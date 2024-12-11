#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "readline/history.h"
#include "readline/readline.h"

char* stripwhite(char* string)
{
    register char *s, *t;

    for (s = string; whitespace(*s); s++)
        ;

    if (*s == 0)
        return (s);

    t = s + strlen(s) - 1;
    while (t > s && whitespace(*t))
        t--;
    *++t = '\0';

    return s;
}

static char** app_complete_line(const char* text, int start, int end)
{
    char** matches = NULL;

    matches = rl_completion_matches(text, rl_filename_completion_function);

    return matches;
}

int main(int argc, char* argv[])
{
    int ret = -1;
    char* line = NULL;
    char* nline = NULL;
    char prompt[1024] = {
        0,
    };

    rl_attempted_completion_function = app_complete_line;

    snprintf(prompt, sizeof(prompt), "%s>", "libcmd");
    while (1)
    {
        line = readline(prompt);
        if (line == NULL)
        {
            fprintf(stdout, "\n");
            continue;
        }

        nline = stripwhite(line);
        if (nline[0] == '\0' || nline[0] == '#')
        {
            free(line);
            continue;
        }

        if (nline[0] == '!')
        {
            system(nline + 1);
            free(line);
            continue;
        }

        if (strcmp(nline, "quit") == 0 || strcmp(nline, "exit") == 0)
        {
            free(line);
            ret = 0;
            break;
        }

        add_history(nline);
        printf("input line: <%s>\n", nline);
        free(line);
    }

    return ret;
}
