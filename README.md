# PacketVoid

PacketVoid is a network fault injector for Windows. It intercepts IPv4 TCP/UDP traffic with WinDivert and applies faults (drop, delay, duplicate, corrupt) to the packets that match rules you give on the command line.

> **Status:** rule parsing and the packet interception loop are working. The fault actions are being added one at a time (drop, then dup, corrupt, delay).

## Usage

```text
PacketVoid.exe --ACTION key=value,key=value [--ACTION key=value,...]
```

Every action is followed by exactly one parameter string. Rules are written as `key=value` pairs separated by commas, with **no spaces**. You can pass several `--ACTION` groups in one run, and each one becomes its own rule.

The program must be run as **Administrator**, because WinDivert loads a kernel driver. Stop it with **Ctrl+C**.

## Actions

| Flag | What it does | Action-specific key |
|---|---|---|
| `--drop` | Silently discards matching packets. | `rate` |
| `--delay` | Holds matching packets and sends them later. | `ms` |
| `--dup` | Sends each matching packet twice. | `rate` |
| `--corrupt` | Modifies bytes in matching packets. | `rate` |

## Parameters

Parameters that choose which packets a rule applies to work with every action. If you leave one out, it matches everything. `rate` and `ms` control how strongly the fault is applied and only work with the actions listed.

| Key | Valid for | Values | Default | Meaning |
|---|---|---|---|---|
| `ip` | all actions | IPv4 address, e.g. `192.168.1.10` | any | Matches packets where this address is the source or the destination. |
| `port` | all actions | `0` to `65535` | any | Matches packets where this port is the source or the destination. |
| `proto` | all actions | `tcp`, `udp`, `icmp` | any | Restricts the rule to one protocol. |
| `dir` | all actions | `in`, `out`, `both` | `both` | `in` = arriving at this machine, `out` = leaving it. |
| `rate` | `--drop`, `--dup`, `--corrupt` | `0` to `100` | `100` | Percentage of matching packets the fault is applied to. Write a plain number (`50`), not `50%`. |
| `ms` | `--delay` | `0` or more | `0` | Delay in milliseconds. A `--delay` without `ms` does nothing. |

Using a key with an action it doesn't belong to (for example `--drop ms=100`) is rejected with an error.

## Examples

```text
PacketVoid.exe --drop rate=50,proto=tcp,port=80,dir=in
PacketVoid.exe --delay ms=200,ip=192.168.1.10
PacketVoid.exe --dup rate=25,proto=udp
PacketVoid.exe --drop rate=10,port=443 --delay ms=150,proto=udp
```

1. Drops half of the incoming TCP packets to or from port 80.
2. Delays all traffic to or from `192.168.1.10` by 200 ms.
3. Duplicates a quarter of all UDP packets.
4. Two rules at once: 10% loss on port 443 and a 150 ms delay on UDP.

## Example Test Run

This test drops all TCP traffic on port 80 and shows that a plain-HTTP request stops working, then recovers when you stop the program.

1. Open a terminal **as Administrator** and make sure `WinDivert.dll` and `WinDivert64.sys` are next to `PacketVoid.exe`.
2. Check that the request works before you start:
   ```text
   curl -I http://example.com
   ```
   You should see an `HTTP/1.1 200 OK` response.
3. Start the injector with a rule that drops every TCP packet on port 80:
   ```text
   PacketVoid.exe --drop rate=100,proto=tcp,port=80
   ```
   You should see the startup messages and a line for each intercepted packet.
4. In a second terminal, repeat the request:
   ```text
   curl -I --max-time 5 http://example.com
   ```
   The request should hang and time out, because the connection can never be established.
5. Press **Ctrl+C** in the injector window. It should print `Injector shut down gracefully.`
6. Run the `curl` command again. It should work normally.

To see partial loss instead of a total block, lower the rate (`rate=30`) and repeat the request a few times. Some will succeed after TCP retransmits the lost packets.

### Running from Visual Studio

Open **Project Properties → Debugging → Command Arguments** and enter the arguments without the program name:

```text
--drop rate=100,proto=tcp,port=80
```

Visual Studio itself must be started as Administrator for the injector to open the WinDivert driver.

## Known Limitations

- **IPv4 only.** IPv6 traffic is not intercepted.
- **TCP and UDP only** for now. ICMP is accepted as a `proto` value but is not yet intercepted.
- **Windows only.** WinDivert works at the IP layer, so Ethernet-level faults (such as ARP) are not possible.
- **`ip` and `port` match either side** of the packet. Separate source and destination options may be added later.
- If several rules match one packet, they are evaluated in the order you typed them.

## Dependency Setup: WinDivert

This project relies on the WinDivert kernel-mode packet filter to intercept and modify network traffic. To keep this repository lightweight and free of binary blobs, the pre-compiled library files are not tracked in version control.

You must manually download and link the WinDivert library before compiling this project in Visual Studio.

### Step 1: Download the Binaries
1. Navigate to the official WinDivert releases page: [https://github.com/basil00/WinDivert/releases](https://github.com/basil00/WinDivert/releases)
2. Expand the **Assets** dropdown for the latest stable release (e.g., version 2.2.2).
3. Download the pre-compiled binary archive. **Important:** Download the file ending in `-A.zip` (e.g., `WinDivert-2.2.2-A.zip`). Do *not* download the Source Code zip.

### Step 2: Organize the Project Directory
1. Inside the root of this repository (where the `.vcxproj` file is located), create a new folder named `vendor`.
2. Extract the contents of the downloaded `.zip` file into this `vendor` directory.
3. Verify your folder structure looks like this:
   ```text
   PacketVoid/
   ├── Program/
   │   ├── vendor/
   │   │   ├── WinDivert-2.2.2/
   │   │   │   ├── include/       (Contains windivert.h)
   │   │   │   ├── x64/           (Contains WinDivert.lib, .dll, and .sys)
   │   │   │   └── x86/
   │   ├── main.c
   │   └── injectorEngine.c
   ```

### Step 3: Place the Runtime Files
Copy `WinDivert.dll` and `WinDivert64.sys` from `vendor/WinDivert-2.2.2/x64/` into the folder that contains the built `PacketVoid.exe` (for example `x64/Debug/`). The program cannot start without them.