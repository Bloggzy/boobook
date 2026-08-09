# Windows USB and Peripheral Device Registry Reference

## Purpose

This document provides technical and forensic context for interpreting USB and related peripheral-device information in the Windows Registry. It is intended to support development of a forensic tool that identifies, parses, correlates and reports devices previously or currently known to a Windows system.

The central principle is:

> Windows does not classify every USB-connected device beneath `USBSTOR`. Device records are distributed across Plug and Play enumerators, device setup classes, device interfaces, software-enumerated endpoints and service-specific Registry locations.

One physical device may therefore produce multiple Registry device nodes, potentially under several enumerators and classes.

---

## 1. Windows Plug and Play device model

Windows represents hardware through a Plug and Play device tree. Each individual node in that tree is called a **device node**, commonly abbreviated to **devnode**.

The primary Registry location is:

```text
HKLM\SYSTEM\CurrentControlSet\Enum
```

On an offline forensic image, `CurrentControlSet` is not a real stored control set. A parser should determine the active control set from:

```text
HKLM\SYSTEM\Select
```

Relevant values include:

```text
Current
Default
LastKnownGood
Failed
```

For example, if `Select\Current` is `1`, the active key is usually:

```text
HKLM\SYSTEM\ControlSet001
```

A forensic tool should normally examine all available `ControlSet00x` keys, preserve which control set supplied each record, and separately identify the control set marked current at acquisition time.

---

## 2. Device instance identifier structure

A Windows device instance identifier generally follows this structure:

```text
<Enumerator>\<Device ID>\<Instance ID>
```

Example:

```text
USBSTOR\Disk&Ven__USB&Prod__SanDisk_3.2Gen1&Rev_1.00\4C530001230101117194
```

The components are:

| Component | Example | Meaning |
|---|---|---|
| Enumerator | `USBSTOR` | The bus driver or system component that discovered and enumerated the device node |
| Device ID | `Disk&Ven__USB&Prod__SanDisk_3.2Gen1&Rev_1.00` | Identifier describing the device type, vendor, product and revision |
| Instance ID | `4C530001230101117194` | Identifier distinguishing this instance from other devices with the same device ID |

The Plug and Play manager assigns a device instance ID to each devnode. It is intended to uniquely identify that device node within the system.

A device instance ID identifies a **devnode**, not necessarily an entire physical device. A multifunction device can have multiple devnodes and therefore multiple device instance IDs.

---

## 3. Enumerator versus device function

The first component beneath `Enum` is normally an **enumerator**. It describes how Windows discovered or instantiated the devnode. It does not always describe the human-facing function of the physical device.

Common enumerators include:

```text
ACPI
BTH
BTHENUM
BTHLEDEVICE
DISPLAY
HID
HTREE
PCI
ROOT
SCSI
STORAGE
SWD
USB
USBPRINT
USBSTOR
```

Examples:

- `USB` generally represents physical USB devices, interfaces, hubs or composite-device functions.
- `USBSTOR` represents logical units exposed through the USB mass-storage driver stack.
- `HID` represents Human Interface Device functions.
- `USBPRINT` represents USB printer functions.
- `BTHENUM` represents services exposed by Bluetooth Classic devices.
- `BTHLEDEVICE` represents Bluetooth Low Energy devices or services.
- `SWD` represents software-enumerated devices, including many user-facing endpoints.
- `SCSI` can contain storage devices exposed through SCSI-like storage stacks, including some USB-attached storage implementations.

A separate property, usually the device **setup class**, describes the functional driver-installation category, such as `DiskDrive`, `Keyboard`, `Mouse`, `Printer`, `Media` or `Net`.

---

## 4. Device identification strings

Windows uses several related identifiers:

### 4.1 Device ID

A device has one device ID reported by its enumerator.

Example:

```text
USB\VID_0781&PID_5583
```

### 4.2 Hardware IDs

A device may have multiple hardware IDs, ordered from most specific to less specific.

Examples:

```text
USB\VID_0781&PID_5583&REV_0100
USB\VID_0781&PID_5583
```

### 4.3 Compatible IDs

Compatible IDs are less-specific identifiers used to match a generic or class driver.

Examples might include:

```text
USB\Class_08&SubClass_06&Prot_50
USB\Class_08&SubClass_06
USB\Class_08
```

### 4.4 Device instance ID

The device instance ID combines the enumerator, device ID and instance-specific portion.

Example:

```text
USB\VID_0781&PID_5583\4C530001230101117194
```

These values should not be treated as interchangeable.

---

## 5. Standard USB identifiers

Standard USB hardware identifiers commonly use:

```text
USB\VID_vvvv&PID_pppp
```

Optional components include:

```text
REV_rrrr
MI_nn
```

Example:

```text
USB\VID_046D&PID_C534&REV_2901
USB\VID_046D&PID_C534&MI_00
```

| Element | Meaning |
|---|---|
| `VID_046D` | USB vendor identifier |
| `PID_C534` | USB product identifier |
| `REV_2901` | Device revision |
| `MI_00` | Interface number within a USB composite device |

`VID` and `PID` values originate from USB descriptors. They are not cryptographically verified identities and may be programmed, changed, duplicated or spoofed by device firmware.

A forensic tool should not treat VID/PID as proof of manufacturer or model without corroboration.

---

## 6. USB mass-storage devices and `USBSTOR`

### 6.1 Example

```text
USBSTOR\Disk&Ven__USB&Prod__SanDisk_3.2Gen1&Rev_1.00
```

Yes, `Disk` indicates a **direct-access storage device**, such as a USB flash drive, external HDD or external SSD.

The identifier can be read approximately as:

```text
USBSTOR\
    Disk
    &Ven__USB
    &Prod__SanDisk_3.2Gen1
    &Rev_1.00
```

| Component | Meaning |
|---|---|
| `USBSTOR` | Device was enumerated by the USB storage driver stack |
| `Disk` | SCSI peripheral device type interpreted as direct-access disk |
| `Ven_` | Vendor field derived from storage inquiry data |
| `Prod_` | Product field derived from storage inquiry data |
| `Rev_` | Revision field derived from storage inquiry data |

`USBSTOR.SYS` derives these identifiers from the device's SCSI inquiry data. They are not necessarily identical to the USB descriptor strings in the corresponding `Enum\USB` record.

### 6.2 Common `USBSTOR` device-type prefixes

The type following `USBSTOR\` is based on the SCSI peripheral device type reported through the storage stack.

Common values include:

| Prefix | Meaning | Typical device |
|---|---|---|
| `Disk` | Direct-access block device | USB flash drive, HDD, SSD, memory card |
| `CdRom` | Optical device | USB CD, DVD or Blu-ray drive |
| `Floppy` | Floppy-type device | USB floppy drive |
| `Tape` | Sequential-access device | Tape drive |
| `Changer` | Media changer | Tape library or optical jukebox |
| `Other` | Other or vendor-specific storage | Unusual storage implementation |

Additional uncommon SCSI-derived type strings may exist. A parser should not assume the above list is exhaustive.

### 6.3 Related devnodes

A USB storage device commonly has several related records:

```text
Enum\USB\VID_xxxx&PID_xxxx\...
Enum\USBSTOR\Disk&Ven_...&Prod_...&Rev_...\...
Enum\SCSI\Disk&Ven_...&Prod_...&Rev_...\...
Enum\STORAGE\Volume\...
```

Not every system or device will contain all of these forms.

A useful conceptual hierarchy is:

```text
Physical USB device
    └── USB mass-storage function
          └── Storage logical unit / disk
                └── Partition
                      └── Volume
```

The physical device, logical disk and mounted volume are separate entities and should be represented separately by a forensic tool.

---

## 7. USB serial numbers and instance IDs

The final component of a USB or USBSTOR device instance path is often treated as the device serial number, but interpretation requires care.

Example:

```text
USBSTOR\Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\4C530001230101117194
```

Possible cases include:

1. **Device-supplied serial number**
   - The USB device supplies a serial-number string descriptor.
   - Windows can use it as part of a stable instance identifier.

2. **Storage-stack identifier**
   - The storage device exposes identifying data through SCSI inquiry or storage descriptors.

3. **Windows-generated or location-dependent identifier**
   - If no suitable unique serial is supplied, Windows may generate an identifier that can include location-related information.
   - Such identifiers may change when the device is attached through a different port, hub or controller.

4. **Composite device variation**
   - Interface-specific child devnodes may use suffixes or generated identifiers that differ from the parent device.

A parser should inspect values and flags such as:

```text
Capabilities
ContainerID
ParentIdPrefix
HardwareID
CompatibleIDs
LocationInformation
LocationPaths
```

It should not automatically assert that every final path component is a globally unique hardware serial number.

---

## 8. Device setup classes

A device setup class groups devices installed and managed in a similar way. Setup class information may appear in device-instance values such as:

```text
Class
ClassGUID
Driver
```

Common classes include:

| Function | Typical setup class |
|---|---|
| Disk device | `DiskDrive` |
| Storage volume | `Volume` |
| Human Interface Device | `HIDClass` |
| Keyboard | `Keyboard` |
| Mouse | `Mouse` |
| Printer | `Printer` |
| Audio/video hardware | `Media` |
| User-facing audio endpoint | `AudioEndpoint` |
| Network adapter | `Net` |
| Serial or parallel port | `Ports` |
| Camera | `Camera` |
| Imaging device | `Image` |
| Bluetooth device | `Bluetooth` |
| Portable device | `WPD` or related portable-device class |

A setup class is not the same thing as an enumerator. For example:

- Enumerator: `USB`
- Setup class: `Net`
- Meaning: a network adapter transported over USB

---

## 9. Class-driver Registry keys

Driver-installation information is commonly linked from a devnode's `Driver` value to:

```text
HKLM\SYSTEM\CurrentControlSet\Control\Class\{Class-GUID}\NNNN
```

Example network-adapter class GUID:

```text
{4D36E972-E325-11CE-BFC1-08002BE10318}
```

A devnode may contain:

```text
Driver = {4D36E972-E325-11CE-BFC1-08002BE10318}\0007
```

The corresponding key is:

```text
HKLM\SYSTEM\CurrentControlSet\Control\Class\
{4D36E972-E325-11CE-BFC1-08002BE10318}\0007
```

This relationship can provide:

- driver description;
- provider;
- service;
- INF section;
- adapter configuration;
- class-specific settings;
- network connection identifiers.

The numbered subkey is not a persistent universal identity and should only be interpreted within the examined system and control set.

---

## 10. USB keyboards

A USB keyboard commonly produces:

```text
Enum\USB\VID_xxxx&PID_xxxx\...
Enum\HID\VID_xxxx&PID_xxxx&MI_nn\...
```

Relevant classes may include:

```text
HIDClass
Keyboard
```

A single keyboard can expose several HID top-level collections, including:

- ordinary keyboard input;
- multimedia keys;
- consumer controls;
- system-control buttons;
- vendor-specific configuration interfaces.

Consequently, one physical keyboard may create several `HID` devnodes.

A `HID` record alone does not prove that a device is a keyboard. The parser should examine:

```text
Class
ClassGUID
DeviceDesc
FriendlyName
HardwareID
CompatibleIDs
Service
ContainerID
Parent
HID usage page and usage, where available
```

---

## 11. USB mice and pointing devices

A USB mouse commonly produces:

```text
Enum\USB\VID_xxxx&PID_xxxx\...
Enum\HID\VID_xxxx&PID_xxxx&MI_nn\...
```

Relevant classes may include:

```text
HIDClass
Mouse
```

A gaming mouse may expose:

- mouse movement and buttons;
- keyboard-like programmable buttons;
- consumer-control functions;
- vendor-specific HID interfaces;
- firmware or onboard-memory interfaces.

The functional category should be inferred from multiple properties rather than from the `HID` enumerator alone.

---

## 12. Proprietary wireless keyboards and mice

A 2.4 GHz keyboard or mouse using a proprietary USB receiver is generally seen by Windows as a USB device.

Common records include:

```text
Enum\USB\VID_xxxx&PID_xxxx\...
Enum\HID\VID_xxxx&PID_xxxx&MI_nn\...
```

The receiver may expose several HID interfaces. The keyboard or mouse paired to that receiver may not have a distinct Windows Plug and Play identity.

Forensic implications:

- the Registry may reliably identify the receiver but not the individual wireless peripheral;
- one receiver may service several paired devices;
- the absence of a separate mouse or keyboard serial does not mean only one peripheral was used;
- vendor software may retain additional pairing information outside the standard PnP keys.

---

## 13. USB printers

USB printers may appear under:

```text
Enum\USB
Enum\USBPRINT
```

A typical functional identifier resembles:

```text
USBPRINT\<Manufacturer-and-model-derived-string>\<Instance>
```

Relevant setup class:

```text
Printer
```

Additional print-spooler configuration is commonly stored under:

```text
HKLM\SYSTEM\CurrentControlSet\Control\Print\Printers
```

These locations serve different purposes:

- `Enum\USB` represents the USB device or interface;
- `Enum\USBPRINT` represents the USB printer function;
- `Control\Print\Printers` represents installed printer queues and spooler configuration.

A multifunction printer may also expose:

- scanner or imaging function;
- fax function;
- memory-card reader;
- storage function;
- vendor-specific HID or management interface.

A tool should correlate records by parent relationships, container IDs, VID/PID, instance information and device descriptions.

---

## 14. Scanners, webcams and imaging devices

USB imaging devices normally have a physical node under:

```text
Enum\USB
```

Possible functional classes include:

```text
Camera
Image
Media
Biometric
```

A webcam may expose:

- video-capture interface;
- microphone;
- privacy switch;
- status/control HID;
- vendor-specific extension unit.

A scanner integrated into a multifunction printer may be a separate interface beneath the same USB composite parent.

---

## 15. USB audio devices

A USB speaker, headset, microphone or audio interface commonly has a physical entry under:

```text
Enum\USB
```

Relevant functional classes include:

```text
Media
AudioEndpoint
```

Additional endpoint records are commonly found under:

```text
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture
```

A headset can create separate records for:

- speaker or headphone render endpoint;
- microphone capture endpoint;
- audio-control interface;
- HID media buttons;
- vendor configuration interface;
- composite USB parent.

The `MMDevices` records represent user-facing audio endpoints rather than the physical USB transport device.

A forensic tool should preserve that distinction.

---

## 16. USB network adapters

USB Ethernet, Wi-Fi and cellular adapters normally have a physical node beneath:

```text
Enum\USB
```

Their setup class is normally:

```text
Net
```

Driver and adapter configuration may be found beneath:

```text
HKLM\SYSTEM\CurrentControlSet\Control\Class\
{4D36E972-E325-11CE-BFC1-08002BE10318}
```

TCP/IP interface configuration commonly appears beneath:

```text
HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces
```

A parser should not assume that a TCP/IP interface GUID is the USB device ID. Correlation may require:

- the devnode `Driver` value;
- class-key `NetCfgInstanceId`;
- network connection records;
- service name;
- PnP instance ID;
- interface GUID;
- friendly name;
- MAC address;
- network profiles.

Possible USB network-device categories include:

- Ethernet adapter;
- Wi-Fi adapter;
- USB tethering interface;
- mobile broadband modem;
- RNDIS device;
- CDC-NCM device;
- vendor-specific network interface.

---

## 17. Mobile phones and portable devices

A phone connected over USB may expose several interfaces:

```text
USB\VID_xxxx&PID_xxxx
USB\VID_xxxx&PID_xxxx&MI_00
USB\VID_xxxx&PID_xxxx&MI_01
USB\VID_xxxx&PID_xxxx&MI_02
```

Possible functions include:

- Media Transfer Protocol (MTP);
- Picture Transfer Protocol (PTP);
- USB tethering;
- modem;
- diagnostic serial port;
- Android Debug Bridge;
- vendor-management interface;
- mass storage on older devices.

Modern phones using MTP do not normally appear under `USBSTOR`, because MTP does not expose the phone's storage as a raw block device.

Possible enumerators and classes include:

```text
USB
SWD
WPD
Ports
Modem
Net
```

Portable-device details may also exist under user-specific or software-specific locations. A forensic tool should avoid treating all file-transfer-capable USB devices as USB mass-storage devices.

---

## 18. USB-to-serial adapters

USB-to-serial adapters usually appear physically under:

```text
Enum\USB
```

Relevant setup class:

```text
Ports
```

Typical friendly names include:

```text
USB Serial Port (COM3)
FTDI USB Serial Port
Prolific USB-to-Serial Comm Port
```

Relevant values or locations can include:

```text
Device Parameters\PortName
HKLM\SYSTEM\CurrentControlSet\Control\COM Name Arbiter
```

The assigned COM port can change over time or between systems.

---

## 19. USB hubs

USB hubs are generally found beneath:

```text
Enum\USB
```

Examples include:

```text
USB\ROOT_HUB20
USB\ROOT_HUB30
USB\VID_xxxx&PID_xxxx
```

Hubs can be:

- root hubs integrated into a host controller;
- external standalone hubs;
- hubs embedded in monitors;
- hubs embedded in docking stations;
- internal hubs used to connect integrated laptop devices.

The presence of a USB hub record does not itself demonstrate that a user attached a removable peripheral. Location and parent relationships are important.

---

## 20. USB composite devices

A composite USB device is one physical device exposing multiple USB interfaces.

Interface-specific IDs commonly include:

```text
USB\VID_xxxx&PID_xxxx&MI_00
USB\VID_xxxx&PID_xxxx&MI_01
USB\VID_xxxx&PID_xxxx&MI_02
```

Examples include:

- docking stations;
- headsets;
- webcams with microphones;
- multifunction printers;
- keyboards with media controls;
- mobile phones;
- security tokens;
- smart-card readers.

A docking station may expose:

- USB hub;
- Ethernet adapter;
- audio interface;
- card reader;
- display-control interface;
- HID buttons;
- serial interface.

Searching only `USBSTOR` would identify only any storage function and miss most of the device.

---

## 21. Bluetooth architecture

Bluetooth devices are not classified as `USBSTOR` merely because the Bluetooth radio is connected over USB.

There are two layers:

1. **Local Bluetooth radio**
   - May itself be an internal or external USB device.
   - Can appear under `Enum\USB`.

2. **Remote Bluetooth devices and services**
   - Enumerated through Bluetooth-specific stacks.
   - Commonly appear under `BTHENUM`, `BTHLEDEVICE` and related locations.

---

## 22. Bluetooth Classic devices

Relevant Registry paths commonly include:

```text
HKLM\SYSTEM\CurrentControlSet\Enum\BTH
HKLM\SYSTEM\CurrentControlSet\Enum\BTHENUM
```

`BTHENUM` hardware IDs are commonly based on a Bluetooth service GUID and may include vendor/product information.

General forms include:

```text
BTHENUM\{ServiceGUID}_VID&nnnnnnnn
BTHENUM\{ServiceGUID}_VID&nnnnnnnn_PID&nnnn
BTHENUM\{ServiceGUID}_LOCALMFG&nnnn
BTHENUM\{ServiceGUID}
```

A Bluetooth Classic headset may create separate service/devnode records for:

- A2DP stereo audio;
- AVRCP media controls;
- Hands-Free Profile;
- speaker endpoint;
- microphone endpoint;
- HID control functions.

The `BTHENUM` records can therefore describe individual **services**, not just one record per physical Bluetooth device.

---

## 23. Bluetooth Low Energy devices

Bluetooth LE-related device records may appear beneath:

```text
HKLM\SYSTEM\CurrentControlSet\Enum\BTHLEDEVICE
```

A BLE device can expose multiple GATT services. Windows can represent the device and its primary services as device objects.

Potential examples include:

- BLE mouse;
- BLE keyboard;
- fitness sensor;
- environmental sensor;
- proximity device;
- security token;
- phone integration service.

A single physical BLE device may therefore generate several related records.

---

## 24. Bluetooth pairing records

Bluetooth pairing-related information is commonly present beneath:

```text
HKLM\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices
```

Subkey names may correspond to Bluetooth device addresses, often formatted as hexadecimal characters without colon separators.

Possible information can include:

- remote Bluetooth address;
- device name;
- pairing or authentication material;
- service information;
- link keys or other security-related values, depending on Windows version and device type.

Interpretation caution:

- a retained record can indicate that Windows knew of or paired with a device;
- it does not necessarily prove an active connection at a specific time;
- absence may result from clean-up, reinstallation, profile removal, control-set differences or unsupported device behaviour.

---

## 25. Bluetooth keyboards and mice

A Bluetooth keyboard or mouse can leave records beneath:

```text
BTHENUM
BTHLEDEVICE
HID
```

The Bluetooth enumerator represents the transport or service. The `HID` devnode represents the input function.

This differs from a proprietary 2.4 GHz receiver, which is generally recorded as:

```text
USB
HID
```

A dual-mode mouse can therefore leave two different artefact sets:

- USB/HID records when used through its proprietary receiver;
- Bluetooth/HID records when used through Bluetooth.

These should not automatically be counted as two physical devices.

---

## 26. Container IDs

A **Container ID** is used to group multiple devnodes that Windows considers parts of the same physical device.

A device instance may contain a value such as:

```text
ContainerID = {GUID}
```

Example physical USB headset:

```text
USB composite parent
USB audio function
HID media-control function
speaker endpoint
microphone endpoint
```

These devnodes may share one container ID.

Container IDs are particularly useful when correlating:

- multifunction USB devices;
- composite devices;
- Bluetooth services;
- audio endpoints;
- printer/scanner combinations;
- docks;
- cameras with microphones.

Limitations:

- container-ID assignment depends on bus and device behaviour;
- Windows may generate container IDs heuristically;
- malformed firmware or driver behaviour can produce imperfect grouping;
- a container ID is system metadata, not cryptographic proof of physical identity;
- container IDs may differ between installations or systems.

A tool should use container IDs as strong correlation evidence, not as the only correlation mechanism.

---

## 27. Parent-child relationships

Modern Windows versions expose parent relationships through device properties. Registry representations can vary by version.

Useful properties include:

```text
Parent
ParentIdPrefix
ContainerID
LocationPaths
LocationInformation
BusReportedDeviceDesc
```

The relationship may be conceptually represented as:

```text
USB composite device
├── HID keyboard interface
├── HID consumer-control interface
├── USB audio interface
└── USB storage interface
```

A forensic parser should build a graph, rather than treating each Registry subkey as an unrelated flat record.

Recommended graph node types:

```text
Physical device container
PnP devnode
USB interface
Storage logical unit
Disk
Partition
Volume
Mount point
Drive letter
User interaction artefact
Driver/service
Network interface
Audio endpoint
Bluetooth service
```

Recommended graph edges:

```text
parent_of
child_of
member_of_container
enumerated_by
uses_driver
uses_service
exposes_interface
maps_to_disk
contains_partition
contains_volume
mounted_as
associated_with_user
shares_identifier
possibly_same_physical_device
```

---

## 28. Important devnode values

A device-instance Registry key may include some of the following:

```text
DeviceDesc
FriendlyName
Mfg
Class
ClassGUID
Driver
Service
HardwareID
CompatibleIDs
Capabilities
ConfigFlags
ContainerID
ParentIdPrefix
LocationInformation
LocationPaths
BusReportedDeviceDesc
UINumber
Address
Problem
StatusFlags
```

Not every value is present for every device or Windows version.

### Forensic interpretation

| Value | Use |
|---|---|
| `DeviceDesc` | Driver-provided description, sometimes using an indirect resource string |
| `FriendlyName` | User-facing or driver-provided friendly name |
| `Mfg` | Manufacturer description, potentially an indirect string |
| `Class` | Setup class name |
| `ClassGUID` | Setup class GUID |
| `Driver` | Link to the installed class-driver subkey |
| `Service` | Kernel driver or service associated with the device |
| `HardwareID` | Ordered list of hardware identifiers |
| `CompatibleIDs` | Generic identifiers used for driver matching |
| `Capabilities` | PnP capability bitmask |
| `ContainerID` | Groups related devnodes into a physical-device container |
| `ParentIdPrefix` | Correlation with child or parent nodes in some device stacks |
| `LocationInformation` | Human-readable attachment location |
| `LocationPaths` | Structured bus topology paths |
| `BusReportedDeviceDesc` | Description reported by the bus |
| `Address` | Bus-specific address or function value |
| `Problem` | Device Manager problem code, where present |

Indirect resource strings such as:

```text
@usb.inf,%usb\composite.devicedesc%;USB Composite Device
```

should be preserved verbatim. Resolving them requires access to the relevant binary or INF resources and may not be practical in an offline parser.

---

## 29. Time information in the `Enum` tree

Registry key last-write timestamps are frequently used in USB forensics, but must be interpreted cautiously.

A key timestamp may reflect:

- initial device installation;
- driver update;
- property refresh;
- device re-enumeration;
- operating-system upgrade;
- configuration change;
- another write unrelated to physical connection time.

It must not automatically be labelled as a first-connected or last-connected time.

Some Windows versions maintain device property timestamps beneath subkeys such as:

```text
Properties\{Property-Set-GUID}\Property-ID
```

These binary property records can contain FILETIME values associated with installation, first connection, last connection, last removal or related PnP state. Exact property keys and semantics vary by Windows release.

A tool should:

1. identify the Windows version;
2. parse documented property keys where possible;
3. preserve raw values;
4. label inferred timestamps with their source and confidence;
5. avoid presenting a Registry key last-write time as a connection event without qualification.

---

## 30. Storage correlation artefacts

For USB mass-storage analysis, useful Registry and file-system artefacts include:

### 30.1 USB physical device

```text
HKLM\SYSTEM\ControlSet00x\Enum\USB
```

### 30.2 USB mass-storage logical unit

```text
HKLM\SYSTEM\ControlSet00x\Enum\USBSTOR
```

### 30.3 SCSI/storage device nodes

```text
HKLM\SYSTEM\ControlSet00x\Enum\SCSI
HKLM\SYSTEM\ControlSet00x\Enum\STORAGE
```

### 30.4 Mounted device mappings

```text
HKLM\SYSTEM\MountedDevices
```

This can correlate volume GUIDs, drive letters and storage signatures.

### 30.5 Per-user mount history

```text
HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
```

This can establish that a particular user profile had awareness of a mounted volume or network resource.

### 30.6 Windows Portable Devices

Depending on Windows version:

```text
HKLM\SOFTWARE\Microsoft\Windows Portable Devices
HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows Portable Devices
```

These locations may contain friendly names and mappings for portable or storage devices.

### 30.7 Device installation logs

```text
C:\Windows\INF\setupapi.dev.log
```

This log can contain device-installation and driver-binding events.

### 30.8 Event logs

Potentially relevant logs include:

```text
Microsoft-Windows-DriverFrameworks-UserMode/Operational
Microsoft-Windows-Kernel-PnP/Configuration
Microsoft-Windows-Kernel-PnP/Device Configuration
Microsoft-Windows-Partition/Diagnostic
Microsoft-Windows-Storage-ClassPnP/Operational
Microsoft-Windows-Ntfs/Operational
System
```

Availability and enabled state vary by Windows version and configuration.

### 30.9 User activity artefacts

Potentially useful correlation sources include:

- Shell Items and PIDLs;
- LNK files;
- Jump Lists;
- RecentDocs;
- ShellBags;
- Open/Save MRUs;
- Office MRUs;
- application logs;
- browser upload/download history;
- Defender or EDR telemetry;
- DLP and Microsoft Purview audit records;
- `$MFT`;
- `$UsnJrnl`;
- `$LogFile`;
- prefetch;
- thumbnail cache;
- Recycle Bin.

These artefacts answer different questions from PnP enumeration. A device being known to Windows does not by itself prove that files were transferred.

---

## 31. Device category reference table

| Physical device | Likely enumerators or locations | Likely functional class |
|---|---|---|
| USB flash drive | `USB`, `USBSTOR`, `SCSI`, `STORAGE` | `DiskDrive`, `Volume` |
| External USB HDD/SSD | `USB`, `USBSTOR`, `SCSI`, `STORAGE` | `DiskDrive`, `Volume` |
| USB optical drive | `USB`, `USBSTOR` | `CDROM` |
| USB keyboard | `USB`, `HID` | `Keyboard`, `HIDClass` |
| USB mouse | `USB`, `HID` | `Mouse`, `HIDClass` |
| Proprietary wireless receiver | `USB`, `HID` | `Keyboard`, `Mouse`, `HIDClass` |
| USB printer | `USB`, `USBPRINT` | `Printer` |
| USB scanner | `USB` | `Image`, `Camera` |
| USB webcam | `USB`, possibly `SWD` | `Camera`, `Media`, `AudioEndpoint` |
| USB headset | `USB`, `HID`, `SWD` | `Media`, `AudioEndpoint`, `HIDClass` |
| USB microphone | `USB`, `SWD` | `Media`, `AudioEndpoint` |
| USB Ethernet adapter | `USB` | `Net` |
| USB Wi-Fi adapter | `USB` | `Net` |
| USB Bluetooth radio | `USB`, `BTH` | `Bluetooth` |
| Bluetooth headset | `BTHENUM`, `SWD` | `Bluetooth`, `Media`, `AudioEndpoint` |
| Bluetooth keyboard/mouse | `BTHENUM` or `BTHLEDEVICE`, `HID` | `Keyboard`, `Mouse`, `HIDClass` |
| BLE sensor | `BTHLEDEVICE` | Bluetooth/GATT-related classes |
| USB-to-serial adapter | `USB` | `Ports` |
| MTP phone | `USB`, `SWD`, portable-device nodes | `WPD`, `Net`, `Ports`, `Modem` |
| USB composite dock | `USB` plus function-specific nodes | `Net`, `Media`, `HIDClass`, `DiskDrive`, etc. |
| USB hub | `USB` | `USB` |
| Smart-card reader | `USB`, sometimes `HID` | `SmartCardReader` |
| Security token | `USB`, `HID`, smart-card nodes | `HIDClass`, `SmartCardReader`, biometric/security class |

---

## 32. Recommended forensic tool data model

A useful normalised record could include:

```yaml
source_hive:
source_control_set:
registry_path:
registry_key_last_write:
enumerator:
device_id:
instance_id:
device_instance_id:
parent_device_instance_id:
container_id:
class:
class_guid:
driver_key:
service:
device_description:
friendly_name:
manufacturer:
bus_reported_description:
hardware_ids:
compatible_ids:
location_information:
location_paths:
capabilities:
config_flags:
problem_code:
usb_vid:
usb_pid:
usb_revision:
usb_interface_number:
storage_type:
storage_vendor:
storage_product:
storage_revision:
candidate_serial:
serial_interpretation:
bluetooth_address:
bluetooth_service_guid:
network_interface_guid:
volume_guids:
drive_letters:
user_sids:
first_seen_candidates:
last_seen_candidates:
raw_values:
parser_warnings:
confidence:
```

### Recommended confidence labels

```text
confirmed
strongly_supported
supported
possible
unknown
contradictory
```

### Example statements

Preferred:

> The Registry contains a `USBSTOR` devnode identifying a SanDisk-labelled direct-access storage device.

Avoid:

> The user connected this SanDisk USB drive at the Registry key's last-write time.

Preferred:

> The instance identifier resembles a device-supplied serial number, but this has not been independently verified.

Avoid:

> This is the device's guaranteed unique serial number.

---

## 33. Correlation strategy

A robust parser should correlate using several attributes:

1. Exact device instance ID.
2. Parent-child device relationship.
3. Shared container ID.
4. USB VID/PID and interface number.
5. Candidate serial or instance identifier.
6. Storage vendor/product/revision.
7. Driver-key relationship.
8. Service name.
9. Location path.
10. Volume GUID or storage signature.
11. Friendly name.
12. SetupAPI installation records.
13. Event-log records.
14. User-specific mount history.
15. Temporal proximity.

No single field should be assumed to be universally reliable.

---

## 34. Common analytical mistakes

### Mistake 1: Treating `USBSTOR` as all USB devices

`USBSTOR` covers USB mass-storage logical units, not every USB peripheral.

### Mistake 2: Treating every `HID` device as a keyboard or mouse

HID includes media controls, security tokens, vendor interfaces, game controllers and other devices.

### Mistake 3: Treating each devnode as a separate physical device

Composite and multifunction devices produce multiple devnodes.

### Mistake 4: Treating VID/PID as verified manufacturer identity

VID/PID data can be generic, erroneous, duplicated or altered.

### Mistake 5: Treating every instance ID as a reliable hardware serial

Windows can create generated or location-dependent identifiers.

### Mistake 6: Treating key last-write time as connection time

The timestamp records the last change to the key, not necessarily attachment.

### Mistake 7: Treating a paired Bluetooth record as evidence of connection at a particular time

Pairing, discovery, enumeration and active connection are different events.

### Mistake 8: Treating a mounted device as proof of file transfer

Mounting establishes availability, not specific access, copying or exfiltration.

### Mistake 9: Ignoring non-current control sets

Historical or alternate control sets may contain relevant records.

### Mistake 10: Ignoring software-enumerated endpoints

Audio, portable-device and Bluetooth functions may be represented under `SWD` or other non-USB enumerators.

---

## 35. Suggested parser workflow

```text
1. Load SYSTEM hive.
2. Read SYSTEM\Select and enumerate all ControlSet00x keys.
3. Parse Enum enumerators and all device-instance records.
4. Normalise device IDs and instance IDs without destroying raw strings.
5. Extract hardware IDs, compatible IDs, classes, services and driver links.
6. Parse USB VID, PID, revision and interface numbers where present.
7. Parse USBSTOR storage type, vendor, product and revision.
8. Build parent-child and container relationships.
9. Parse class-driver keys.
10. Parse MountedDevices and storage/volume mappings.
11. Load SOFTWARE hive and parse portable-device and MMDevices records.
12. Load user NTUSER.DAT hives and parse MountPoints2 and user artefacts.
13. Parse SetupAPI.dev.log.
14. Parse relevant event logs.
15. Produce physical-device groupings separately from raw devnodes.
16. Preserve alternate interpretations and confidence ratings.
17. Report provenance for every extracted fact.
```

---

## 36. Authoritative references

The following Microsoft documentation is useful for implementation and interpretation.

### Plug and Play identifiers

- **Device Identification Strings**  
  https://learn.microsoft.com/en-us/windows-hardware/drivers/install/device-identification-strings

- **Device Instance IDs**  
  https://learn.microsoft.com/en-us/windows-hardware/drivers/install/device-instance-ids

- **Device ID String**  
  https://learn.microsoft.com/en-us/windows-hardware/drivers/install/device-ids

- **Hardware IDs**  
  https://learn.microsoft.com/en-us/windows-hardware/drivers/install/hardware-ids

- **Overview of Device Setup Classes**  
  https://learn.microsoft.com/en-us/windows-hardware/drivers/install/overview-of-device-setup-classes

- **HKLM\SYSTEM\CurrentControlSet\Enum Registry Tree**  
  https://learn.microsoft.com/en-us/windows-hardware/drivers/install/hklm-system-currentcontrolset-enum-registry-tree

### USB identifiers and architecture

- **Identifiers for USB Devices**  
  https://learn.microsoft.com/en-us/windows-hardware/drivers/install/identifiers-for-usb-devices

- **Standard USB Identifiers**  
  https://learn.microsoft.com/en-us/windows-hardware/drivers/install/standard-usb-identifiers

- **Identifiers Generated by USBSTOR.SYS**  
  https://learn.microsoft.com/en-us/windows-hardware/drivers/install/identifiers-generated-by-usbstor-sys

- **Support for Interface Collections**  
  https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/support-for-interface-collections

- **USB Container IDs in Windows**  
  https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/usb-containerids-in-windows

- **How USB Devices Are Assigned Container IDs**  
  https://learn.microsoft.com/en-us/windows-hardware/drivers/install/how-usb-devices-are-assigned-container-ids

- **Container IDs Generated from a Bus-Specific Unique ID**  
  https://learn.microsoft.com/en-us/windows-hardware/drivers/install/container-ids-generated-from-a-bus-specific-unique-id

- **How Container IDs Are Generated from the Removable Device Capability**  
  https://learn.microsoft.com/en-us/windows-hardware/drivers/install/how-container-ids-are-generated-from-the-removable-device-capability

### Human Interface Devices

- **Introduction to HID Concepts**  
  https://learn.microsoft.com/en-us/windows-hardware/drivers/hid/

- **Top-Level Collections**  
  https://learn.microsoft.com/en-us/windows-hardware/drivers/hid/top-level-collections

### Bluetooth

- **Installing a Bluetooth Device**  
  https://learn.microsoft.com/en-us/windows-hardware/drivers/bluetooth/installing-a-bluetooth-device

- **Bluetooth Low Energy Overview**  
  https://learn.microsoft.com/en-us/windows-hardware/drivers/bluetooth/bluetooth-low-energy-overview

### Audio

- **USB Audio Class System Driver**  
  https://learn.microsoft.com/en-us/windows-hardware/drivers/audio/usb-audio-class-system-driver--usbaudio-sys-

- **Windows Audio Architecture**  
  https://learn.microsoft.com/en-us/windows-hardware/drivers/audio/windows-audio-architecture

### Device inspection utilities and APIs

- **PnPUtil Command Syntax**  
  https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/pnputil-command-syntax

- **DevCon**  
  https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/devcon

- **Retrieving a Device Instance Identifier**  
  https://learn.microsoft.com/en-us/windows-hardware/drivers/install/retrieving-a-device-instance-identifier

- **Enumerate Devices**  
  https://learn.microsoft.com/en-us/windows/apps/develop/devices-sensors/enumerate-devices

---

## 37. Scope and validation note

Windows device-enumeration behaviour varies with:

- Windows version and build;
- device firmware;
- USB class implementation;
- driver package;
- chipset and controller;
- device installation history;
- operating-system upgrades;
- whether the examination uses a live system or offline disk image.

The schemas and examples in this document should therefore be validated against representative Windows 10 and Windows 11 test systems, including:

- USB flash drives with and without serial numbers;
- external HDDs and SSDs;
- card readers;
- keyboards and mice;
- proprietary wireless receivers;
- Bluetooth Classic and BLE devices;
- printers and multifunction devices;
- USB headsets and webcams;
- USB network adapters;
- mobile phones using MTP;
- composite docking stations.

The tool should preserve raw Registry data and clearly distinguish:

```text
observed fact
parsed value
correlation
inference
confidence assessment
```
