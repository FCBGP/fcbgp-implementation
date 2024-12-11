#include "libsysmgr.h"

#define SYS_ETC_PATH_MTAB SYS_ETC_PATH "mtab"

/*
 * dev/mapper/VolGroup-lv_root / ext4 rw 0 0
 *  proc /proc proc rw 0 0
 *  sysfs /sys sysfs rw 0 0
 *  devpts /dev/pts devpts rw,gid=5,mode=620 0 0
 *  tmpfs /dev/shm tmpfs rw,rootcontext="system_u:object_r:tmpfs_t:s0" 0 0
 *  /dev/sda5 /boot ext4 rw 0 0
 *  /dev/mapper/VolGroup-lv_home /home ext4 rw 0 0
 *  none /proc/sys/fs/binfmt_misc binfmt_misc rw 0 0
 */

int sys_diskinfo_get(sys_diskinfo_t** pdiskinfos)
{
    int cnt = 0;
    FILE* fp = NULL;
    char buf[256] = {
        0,
    };
    char disk_layout[32] = {
        0,
    };
    char disk_perm[8] = {
        0,
    };
    char temp[2] = {
        0,
    };

    sys_diskinfo_t* tail = NULL;
    sys_diskinfo_t* head = NULL;
    sys_diskinfo_t* diskinfo = NULL;

    struct statfs disk_stat;

    fp = fopen(SYS_ETC_PATH_MTAB, "r");
    if (fp == NULL)
    {
        return -ENOENT;
    }

    while (fgets(buf, sizeof(buf), fp))
    {
        diskinfo = calloc(1, sizeof(sys_diskinfo_t));
        if (!diskinfo)
        {
            return -ENOMEM;
        }

        if (sscanf(buf, "%s %s %s %s %s %s", diskinfo->filesystem,
                   diskinfo->mounted_on, disk_layout, disk_perm, &temp[0],
                   &temp[1]) != 6)
        {
            free(diskinfo);
            continue;
        }

        statfs(diskinfo->mounted_on, &disk_stat);

        diskinfo->blocks = disk_stat.f_blocks * disk_stat.f_bsize / 1024;
        diskinfo->used =
            (disk_stat.f_blocks - disk_stat.f_bfree) * disk_stat.f_bsize / 1024;
        diskinfo->available = disk_stat.f_bavail * disk_stat.f_bsize / 1024;

        if (disk_stat.f_blocks)
        {
            diskinfo->usage_rate = disk_stat.f_bavail / disk_stat.f_blocks + 1;
        }
        else
        {
            diskinfo->usage_rate = 0;
        }

        diskinfo->next = NULL;
        if (tail)
        {
            tail->next = diskinfo;
            tail = diskinfo;
        }
        else
        {
            head = diskinfo;
            tail = diskinfo;
        }

        cnt++;
    }

    *pdiskinfos = head;
    fclose(fp);
    return cnt;
}

int sys_diskinfo_free(sys_diskinfo_t* diskinfos)
{
    sys_diskinfo_t* cur = NULL;
    sys_diskinfo_t* next = NULL;

    if (diskinfos == NULL)
    {
        return 0;
    }

    cur = diskinfos;
    while (cur)
    {
        next = cur->next;
        free(cur);
        cur = next;
    }

    return 0;
}
