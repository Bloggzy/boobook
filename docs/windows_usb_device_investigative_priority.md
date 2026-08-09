# Investigative Significance of USB Device Classes in Windows

## Purpose

This document provides a practical framework for prioritising USB-connected devices during digital forensic analysis of a Windows system.

It is intended to support a forensic artefact-processing tool that identifies, classifies and ranks USB devices based on their likely investigative value.

The classification should not rely solely on the Windows device class. A single physical USB device may expose multiple interfaces and may appear under several Windows enumerators, device classes or registry locations.

---

## Investigative Principle

USB-connected devices are generally more significant where they can:

- Store or transfer data
- Provide an alternative communications pathway
- Interact with another computing platform
- Create physical or electronic records
- Capture audio, video or images
- Provide authentication or privileged access
- Emulate trusted device classes
- Expose multiple interfaces as a composite device

Routine Human Interface Devices (HIDs), such as ordinary keyboards and mice, are usually lower priority. However, unusual, programmable or composite HID devices may be highly significant.

---

# Priority Tiers

## Tier 1 - High Investigative Value

### 1. Mass Storage Devices

Examples:

- USB flash drives
- External hard disk drives
- External solid-state drives
- Memory card readers
- USB-attached storage enclosures
- Encrypted USB storage devices

Potential relevance:

- Data exfiltration
- Data collection
- Malware introduction
- Offline storage
- Transfer of documents between systems
- Removal of corporate or sensitive information
- Introduction of forensic tools or unauthorised software

Typical Windows representations may include:

- `USB`
- `USBSTOR`
- `SCSI`
- Disk drives
- Storage volumes
- Volume interfaces
- Portable devices, depending on the device

Mass storage devices often leave comparatively rich forensic artefacts, including registry records, SetupAPI logs, event logs, mounted-device records, volume information, Shell Items, LNK files, Jump Lists and file-system activity.

---

### 2. Portable and Mobile Devices

Examples:

- Android phones
- Apple iPhones
- Tablets
- Digital cameras
- Media players
- Handheld computing devices

Potential relevance:

- File transfer using Media Transfer Protocol (MTP)
- Image transfer using Picture Transfer Protocol (PTP)
- Apple-specific synchronisation and pairing
- Device backups
- USB tethering
- Application-specific file transfer
- Debugging or developer access
- Data exfiltration through a mobile device

Typical Windows representations may include:

- Windows Portable Devices (WPD)
- MTP devices
- PTP devices
- USB composite devices
- Apple mobile-device drivers
- Network adapters when tethering is enabled
- Vendor-specific device classes

Portable devices should not be excluded merely because they do not appear under `USBSTOR`.

---

### 3. USB Network and Communications Devices

Examples:

- USB Ethernet adapters
- USB Wi-Fi adapters
- Mobile broadband dongles
- Cellular modems
- USB tethering interfaces
- USB network bridges

Potential relevance:

- Alternative internet connectivity
- Bypassing monitored corporate network paths
- Connecting to unauthorised wireless networks
- Use of personal hotspots
- Lateral movement
- Command-and-control communications
- Circumvention of network access controls
- Connection to isolated or external networks

A USB network device may appear primarily as a network adapter rather than as a conventional USB peripheral.

---

### 4. Composite Docks and Port Replicators

Examples:

- USB-C docks
- Thunderbolt docks
- Monitor-integrated docks
- Port replicators
- Multi-function hubs

Potential relevance:

A single physical dock may expose several child functions, including:

- Ethernet
- USB storage
- Display adapters
- Audio
- Serial interfaces
- Card readers
- Human Interface Devices
- Additional USB hubs

The forensic tool should attempt to associate child interfaces with their parent composite device where possible.

---

### 5. Optical Drives

Examples:

- External CD drives
- External DVD drives
- External Blu-ray drives
- USB optical writers

Potential relevance:

- Reading removable media
- Writing data to optical media
- Software installation
- Malware introduction
- Transfer of data using offline media
- Access to archived or historical records

Optical drives may appear as storage or SCSI-class devices.

---

### 6. Virtual or Emulated Storage Devices

Examples:

- Hardware security products exposing a virtual CD-ROM
- USB devices containing embedded installer media
- Encrypted devices exposing multiple logical interfaces
- Devices emulating both storage and HID functions
- Penetration-testing devices with multiple USB roles

Potential relevance:

- Hidden or misleading device capabilities
- Delivery of payloads or software
- Bypassing application-control mechanisms
- Automated execution
- Multi-stage attacks

These devices should be treated as potentially high-value where their interfaces do not align with their apparent physical purpose.

---

## Tier 2 - Significant in Particular Investigations

### 7. Printers and Multifunction Devices

Examples:

- USB printers
- Label printers
- Multifunction printers
- Printer-scanner combinations
- Receipt printers

Potential relevance:

- Unauthorised printing
- Physical disclosure of sensitive information
- Creation of paper copies
- Printing of documents before departure or termination
- Use of a non-corporate or home printer

The presence of a printer does not prove that a document was printed. Printer installation and print-job evidence should be analysed separately.

Relevant supporting artefacts may include:

- Printer registry keys
- PrintService event logs
- Spool files
- Printer driver installation records
- SetupAPI logs
- Recent document artefacts
- Application-specific print history

---

### 8. Scanners and Imaging Devices

Examples:

- Flatbed scanners
- Document scanners
- Barcode scanners
- Cameras
- Imaging devices
- Multifunction printer scanners

Potential relevance:

- Digitisation of paper records
- Creation of electronic copies
- Import of images or documents
- Capture of sensitive physical information
- Document conversion or archiving

Barcode scanners may present as HID devices and should be distinguished from ordinary keyboards where possible.

---

### 9. Serial and Specialist Communications Adapters

Examples:

- USB-to-serial adapters
- USB-to-RS232 adapters
- USB-to-RS485 adapters
- CAN bus adapters
- Diagnostic interfaces
- Industrial control interfaces
- Laboratory equipment interfaces
- Vehicle diagnostic devices

Potential relevance:

- Access to operational technology
- Interaction with industrial equipment
- Vehicle or embedded-system access
- Configuration changes
- Data extraction from specialist systems
- Use of unsupported or unauthorised hardware

These devices may be highly significant in engineering, industrial, laboratory, automotive or operational-technology investigations.

---

### 10. Authentication and Security Devices

Examples:

- Smart-card readers
- Hardware security keys
- FIDO or FIDO2 authenticators
- YubiKey-type devices
- USB cryptographic tokens
- Certificate-storage devices
- Hardware licence dongles

Potential relevance:

- User authentication
- Multi-factor authentication
- Privileged access
- Certificate use
- Digital signing
- Access to protected applications
- Attribution of activity
- Circumvention or delegation of authentication controls

These devices are not usually associated with bulk data transfer, but may be critical in access-control or identity investigations.

---

### 11. Audio, Video and Capture Devices

Examples:

- Webcams
- USB microphones
- USB headsets
- Audio interfaces
- Video capture cards
- HDMI capture devices
- Document cameras

Potential relevance:

- Audio recording
- Video recording
- Meeting capture
- Surveillance
- Recording of calls or presentations
- Capture of information displayed on another system
- Unauthorised collection of sensitive conversations

Audio output-only devices are generally lower priority than recording or capture devices.

---

### 12. Developer, Embedded and Programmable Devices

Examples:

- Arduino boards
- Raspberry Pi devices
- Microcontroller development boards
- JTAG programmers
- Firmware programmers
- Debug interfaces
- Smartphones in debugging mode
- Embedded-system consoles

Potential relevance:

- Code deployment
- Firmware extraction
- Firmware modification
- Debugging access
- Serial-console access
- Covert storage
- Automated interaction
- Connection to specialist or embedded systems

These devices may appear under serial, vendor-specific, HID, storage or composite classes.

---

### 13. USB Hubs and KVM Devices

Examples:

- Powered USB hubs
- Unpowered USB hubs
- Monitor-integrated hubs
- USB KVM switches
- Docking hubs

Potential relevance:

- Explaining downstream device connections
- Reconstructing physical USB topology
- Identifying use of multiple attached devices
- Associating devices with a common dock or workstation arrangement
- Explaining why child devices share related installation times or locations

Hubs are generally indirect evidence, but can be important when reconstructing how other devices were connected.

---

## Tier 3 - Usually Lower Investigative Value

### 14. Standard Human Interface Devices

Examples:

- Keyboards
- Mice
- Trackpads
- Standard game controllers
- Basic presentation remotes
- Conventional touch-input devices

Typical relevance:

- Device attribution
- Identifying unusual peripherals
- Establishing a workstation configuration
- Confirming use of a particular docking or desk arrangement

Ordinary keyboards and mice are usually numerous and low-value unless they are unusual, unauthorised, programmable or associated with suspicious activity.

---

### 15. Audio Output Devices

Examples:

- USB speakers
- Headphones
- Digital-to-analogue converters
- Standard USB headsets without recording capability

Typical relevance:

- Usually limited
- May assist with device attribution
- May indicate use of a particular workstation or dock
- May be relevant in audio-related investigations

---

### 16. Display-Related Devices

Examples:

- USB display adapters
- USB graphics adapters
- Presentation adapters
- USB-connected monitors
- DisplayLink devices

Typical relevance:

- Use of external displays
- Presentation activity
- Connection to meeting-room equipment
- Workstation configuration
- Possible display of information to an external screen

These devices generally provide limited evidence of the content displayed.

---

### 17. Power-Only and Charging Devices

Examples:

- Basic USB chargers
- Power accessories
- Charging-only cables
- Non-enumerating devices

Typical relevance:

- Usually little or no forensic value
- May not enumerate in Windows
- May leave no persistent device artefacts

A lack of USB artefacts does not prove that a physical charging connection did not occur.

---

### 18. Generic Bluetooth Adapters

Examples:

- USB Bluetooth dongles
- Integrated Bluetooth adapters exposed over USB internally

Typical relevance:

- The adapter itself is often less important than the Bluetooth devices paired through it
- May indicate an alternative peripheral or communications pathway
- May support use of wireless keyboards, mice, audio devices, phones or other peripherals

Bluetooth-pairing artefacts should be analysed separately from USB-enumeration artefacts.

---

# HID Devices That Require Additional Scrutiny

A device reporting itself as a HID should not automatically be treated as benign.

Potentially significant HID or HID-capable devices include:

- USB Rubber Ducky-type devices
- Bash Bunny-type devices
- Programmable keyboards
- Macro pads
- Malicious USB cables
- Automated keystroke-injection devices
- Hardware keyloggers
- Barcode scanners
- Devices combining HID and storage
- Devices combining HID and networking
- Wireless keyboard or mouse receivers associated with unknown devices
- Composite penetration-testing devices

Reasons for concern may include:

- Rapid automated keyboard input
- Unusual vendor or product identifiers
- Missing or inconsistent serial numbers
- Multiple child interfaces
- A mismatch between the reported class and apparent device purpose
- Vendor-specific interfaces
- Storage, network or serial functionality exposed alongside HID
- First connection shortly before suspicious activity

---

# Recommended Investigative Priority

For a general corporate investigation, the following default order is recommended:

1. Storage-capable devices
2. Phones, tablets and cameras
3. Network adapters and tethering devices
4. Printers, scanners and multifunction devices
5. Composite docks and multi-function devices
6. Optical drives and memory-card readers
7. Authentication and smart-card devices
8. Serial, industrial and developer interfaces
9. Unusual or programmable HID devices
10. Routine keyboards, mice, speakers and other common peripherals

The priority should be adjusted according to the allegation.

Examples:

- In a suspected data-exfiltration matter, storage, mobile and network devices should be prioritised.
- In a suspected unauthorised-printing matter, printers and multifunction devices should be treated as Tier 1.
- In an investigation involving network-control bypass, USB Ethernet, Wi-Fi and tethering devices should be treated as Tier 1.
- In an identity or privileged-access investigation, security keys and smart-card devices may be Tier 1.
- In an operational-technology investigation, serial, CAN bus and industrial interfaces may be Tier 1.

---

# Recommended Tool Classification Categories

A forensic USB artefact-processing tool could classify devices using the following investigative categories:

- `Storage`
- `MobileDevice`
- `Network`
- `PrinterScanner`
- `OpticalMedia`
- `AuthenticationToken`
- `SerialIndustrial`
- `AudioVideoCapture`
- `DockHubComposite`
- `DeveloperEmbedded`
- `PotentialOffensiveDevice`
- `StandardHID`
- `DisplayDevice`
- `AudioOutput`
- `BluetoothAdapter`
- `PowerOnly`
- `OtherPeripheral`
- `Unknown`

These categories should be separate from the raw Windows device class.

---

# Suggested Relevance Levels

## High

Examples:

- Mass storage
- Mobile devices
- USB network adapters
- USB tethering interfaces
- Suspicious composite devices
- Known penetration-testing devices
- Virtual storage devices
- Devices capable of data transfer or communications bypass

## Medium

Examples:

- Printers
- Scanners
- Cameras
- Smart-card readers
- Hardware authentication tokens
- Serial adapters
- Development boards
- Audio or video capture devices
- Optical drives
- Docks and hubs

## Low

Examples:

- Conventional keyboards
- Conventional mice
- Standard speakers
- Basic headsets
- Display adapters
- Routine Bluetooth adapters
- Common game controllers

## Review Required

Use this status where:

- The device class is unknown
- The vendor or product is unknown
- The VID or PID is unusual
- No serial number is present
- The serial number appears generic or duplicated
- The device exposes multiple interfaces
- The parent-child relationship is unclear
- The reported class conflicts with the apparent device purpose
- The device appears only in partial artefacts
- The device may be internally connected rather than externally attached
- The device is known to support programmable or offensive functionality

---

# Classification Considerations for a Forensic Tool

## Do Not Rely Solely on the Device Class

A physical USB device may appear under multiple Windows enumerators or classes, including:

- `USB`
- `USBSTOR`
- `SCSI`
- `HID`
- `HIDClass`
- `WPD`
- `SWD`
- `BTHUSB`
- Disk drives
- Storage volumes
- Network adapters
- Ports
- Printers
- Imaging devices
- Smart-card readers
- Audio devices
- Media devices
- Vendor-specific classes

The same physical device may therefore generate several logical records.

---

## Correlate Parent and Child Devices

Where possible, the tool should reconstruct relationships between:

- USB host controller
- Root hub
- External hub
- Composite parent device
- Child functions
- Storage disk
- Mounted volume
- Drive letter
- Portable-device object
- Network interface
- Printer object

This is especially important for:

- Composite devices
- Docks
- Mobile phones
- Multifunction printers
- Security tokens
- Penetration-testing devices

---

## Distinguish Physical Devices from Logical Interfaces

The tool should avoid treating every device node as a separate physical device.

A single physical device may expose:

- One composite parent
- One HID keyboard
- One HID mouse
- One storage interface
- One serial interface
- One network interface
- One vendor-specific interface

The preferred output should include both:

1. A physical-device record, where correlation is possible
2. One or more logical-interface records associated with that physical device

---

## Preserve Raw Evidence

The tool should retain the original values used to make a classification, including:

- Device instance ID
- Parent device instance ID
- Container ID
- Class GUID
- Device class
- Enumerator
- Service
- Driver
- Friendly name
- Device description
- Manufacturer
- Vendor ID
- Product ID
- Revision
- Serial number
- Compatible IDs
- Hardware IDs
- Location paths
- First installation time
- Last arrival time
- Last removal time
- Registry source
- Event-log source
- SetupAPI source
- Volume or mount-point information

Classification should be an enrichment layer and should not replace the underlying evidence.

---

# Suggested Device-Scoring Factors

The forensic tool could calculate a relevance score using weighted indicators.

## High-Value Indicators

- Device is storage-capable
- Device supports MTP or PTP
- Device provides a network interface
- Device is a printer or scanner
- Device exposes multiple classes
- Device is known to be programmable
- Device is known to emulate keyboard input
- Device includes a virtual CD-ROM
- Device is associated with a mounted volume
- Device is associated with file-access artefacts
- Device first appeared near the time of suspicious activity
- Device was connected by a relevant user
- Device is rare within the environment

## Suspicion or Review Indicators

- Missing serial number
- Generic serial number
- Duplicate serial number
- Unknown VID or PID
- VID/PID mismatch with reported product
- Unusual class combination
- Short-lived connection
- Repeated connection and removal
- Device connected outside normal hours
- Device connected shortly before or after sensitive file activity
- Device connected shortly before suspicious network activity
- Device classified as HID but also exposes storage or networking
- Device is known to have offensive-security capabilities

## Lower-Value Indicators

- Common enterprise keyboard or mouse
- Common integrated webcam
- Internal Bluetooth adapter
- Internal card reader
- Standard dock used regularly over a long period
- Device appears on most systems in the environment

A lower-value indicator should reduce priority, but should not automatically suppress the device from output.

---

# Suggested Output Fields

A processed device record could include:

```text
physical_device_id
device_instance_id
parent_device_instance_id
container_id
enumerator
windows_device_class
class_guid
investigative_category
relevance_level
relevance_score
classification_reason
vendor_id
product_id
revision
serial_number
manufacturer
product_name
friendly_name
service
driver
hardware_ids
compatible_ids
location_paths
is_composite
is_storage_capable
is_network_capable
is_mobile_device
is_printer
is_scanner
is_hid
is_programmable_or_suspicious
first_install_time
first_connection_time
last_connection_time
last_removal_time
associated_volume
associated_drive_letter
associated_user
evidence_sources
confidence
notes
```

---

# Confidence and Evidential Language

The forensic tool should distinguish between:

- Device identified
- Device installed
- Device enumerated
- Device connected
- Device mounted
- Volume assigned
- File accessed
- File copied
- File printed
- User-associated activity

For example:

- Registry evidence may show that a device was previously installed.
- Device-arrival events may show that a device was connected.
- Mounted-device artefacts may show that a volume was assigned.
- Shell or file-system artefacts may show that files were accessed.
- None of those facts alone necessarily prove that a particular file was copied to the device.

The tool should avoid overstating conclusions.

---

# Summary

The most important USB device categories in a typical Windows forensic investigation are:

1. Storage devices
2. Mobile and portable devices
3. Network and tethering devices
4. Printers and scanners
5. Composite docks and multi-function devices
6. Optical and removable-media devices
7. Authentication devices
8. Serial, industrial and developer devices
9. Unusual or programmable HID devices

Routine keyboards and mice are generally lower priority, but HID classification alone is not sufficient to determine significance.

The tool should combine raw Windows device information, parent-child relationships, device capabilities, timing, user attribution and related artefacts to produce an explainable investigative classification.
