/home/timuhyo/Documents/Repo/memprtc_latest/README.md

## 🛡️ **memprtc - Memory Protection Module**

*because your processes deserve bodyguards*

```bash

memprtc - keeping those memory violators in CHECK since 2026 

```

### 🤔 **wtf is this?**

Ever had some sketchy process try to read/write memory it shouldn't touch? Yeah me too. memprtc is a Linux kernel module that lets you put a forcefield around any process. Think of it as a bodyguard for your sensitive programs - if anyone tries to mess with their memory, memprtc either:

- 🚫 Blocks the access
- 🔪 Terminates the attacker  
- 💀 Terminates the protected process (nuclear option)
- 📝 Just logs it and vibes

### ✨ **what makes it special?**

Unlike those basic security tools that only log stuff, memprtc **actually blocks** the attacks at kernel level. We're talking:

- **process_vm_readv/writev**? blocked.
- **ptrace** debugging? not on my watch.
- **/proc/pid/mem** shenanigans? denied.
- **page faults** from malicious code? send them SIGSEGV lol.
- **signal bombing**? only if they're trusted.

### 🏗️ **how it works (this is AI generated since i can't sketch with UTF characters, sorry if this barely makes sense)**

```
┌─────────────────────────────────────────────────────────┐
│  userspace:                                             │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐                  │
│  │ init │ │ bash │ │ nginx │ │ gdb   │  <-- attackers  │
│  └──┬───┘ └──┬───┘ └──┬───┘ └──┬───┘     be like:     │
│     │        │        │        │          "imma read   │
└─────┼────────┼────────┼────────┼────────── that memory"│
      │        │        │        │                       │
┌─────┼────────┼────────┼────────┼───────────────────────┐
│kernel:                                                  │
│  ┌──▼────────▼────────▼────────▼──────────────┐       │
│  │         syscalls / page faults              │       │
│  └─────────────────┬──────────────────────────┘       │
│                    │                                   │
│  ┌─────────────────▼──────────────────────────┐       │
│  │         memprtc kprobes                      │       │
│  │  [process_vm] [ptrace] [mm_fault] [proc_mem]│       │
│  └─────────────────┬──────────────────────────┘       │
│                    │                                   │
│  ┌─────────────────▼──────────────────────────┐       │
│  │         "is this PID protected?"           │       │
│  │  ┌────────────┐  ┌────────────┐           │       │
│  │  │bloom filter│─▶│   IDR tree │  O(1)     │       │
│  │  │(fast no)   │  │(yes check) │  let's go │       │
│  │  └────────────┘  └─────┬──────┘           │       │
│  └─────────────────────────┼──────────────────┘       │
│                            │                           │
│  ┌─────────────────────────▼──────────────────┐       │
│  │         "are they trusted?"                 │       │
│  │  ┌────────────┐  ┌────────────┐           │       │
│  │  │ root?      │  │ same UID? │  whitelist │       │
│  │  │ same user? │  │ trusted   │  check     │       │
│  │  └────────────┘  └────────────┘           │       │
│  └─────────────────────────┬──────────────────┘       │
│                            │                           │
│  ┌─────────────────────────▼──────────────────┐       │
│  │         VIOLATION DETECTED                 │       │
│  │  ┌────────────────────────────────────┐    │       │
│  │  │ • log that nonsense                 │    │       │
│  │  │ • update stats                       │    │       │
│  │  │ • send to auditd if enabled          │    │       │
│  │  │ • scream into dmesg                   │    │       │
│  │  └────────────────────────────────────┘    │       │
│  └─────────────────────────┬──────────────────┘       │
│                            │                           │
│  ┌─────────────────────────▼──────────────────┐       │
│  │         ACTION TIME                         │       │
│  │  ┌────────────┐ ┌────────────┐ ┌─────────┐ │       │
│  │  │ block      │ │ kill attacker│ │ kill   │ │       │
│  │  │ (EACCES)   │ │ (SIGKILL)   │ │protected│ │       │
│  │  └────────────┘ └────────────┘ └─────────┘ │       │
│  └──────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────┘
```

### 🚀 **quick start**

```bash
# build the thing
make clean && make

# load it with default settings
sudo insmod memprtc.ko

# see if it's alive
lsmod | grep memprtc
dmesg | tail

# protect a process (PID 1234)
echo "protect 1234" | sudo tee /dev/memprtc

# check what's protected
cat /dev/memprtc

# add a trusted process (PID 5678 can access PID 1234 with read+write)
echo "trust 1234 5678 0x03" | sudo tee /dev/memprtc

# watch violations in real time (mount debugfs first)
sudo mount -t debugfs none /sys/kernel/debug
watch -n 1 cat /sys/kernel/debug/memprtc/violations

# unload when done
sudo rmmod memprtc
```

### ⚙️ **module parameters** (for the tweakers)

```bash
# load with custom settings
sudo insmod memprtc.ko trust_root=0 log_level=2 max_protected=512

# check current params
systool -v -m memprtc
```

| param | what it does | default |
|-------|--------------|---------|
| `trust_root` | trust root processes? | 1 (true) |
| `trust_same_user` | trust same UID? | 1 (true) |
| `audit_violations` | send to audit log? | 0 (false) |
| `log_level` | 0=errors, 1=warnings, 2=verbose | 1 |
| `max_protected` | max protected processes | 1024 |

### 🎮 **interfaces** (pick your poison)

#### **device file** (`/dev/memprtc`)
```bash
# simple commands for the CLI warriors
echo "protect 1234" > /dev/memprtc
echo "unprotect 1234" > /dev/memprtc
echo "trust 1234 5678 0xFF" > /dev/memprtc
cat /dev/memprtc  # read status
```

#### **ioctl** (for the C programmers)
```c
int fd = open("/dev/memprtc", O_RDWR);
struct protection_request req = {
    .pid = 1234,
    .flags = PROTECT_ALL,
    .action = ACTION_BLOCK_AND_LOG,
    .comment = "my precious",
};
ioctl(fd, MEMPRTC_PROTECT_PID, &req);
```

#### **sysfs** (`/sys/class/memprtc/`)
```bash
cat /sys/class/memprtc/protected_pids  # list protected PIDs
cat /sys/class/memprtc/stats            # get statistics
cat /sys/class/memprtc/config           # view config
```

#### **debugfs** (`/sys/kernel/debug/memprtc/`) - *the fun one*
```bash
# mount if needed
mount -t debugfs none /sys/kernel/debug

# watch the chaos
cat /sys/kernel/debug/memprtc/violations   # violation history
cat /sys/kernel/debug/memprtc/protected     # detailed protected list
watch -n 1 cat /sys/kernel/debug/memprtc/violations  # live update
```

### 🎯 **protection flags** (mix and match)

```c
PROTECT_FULL      // everything (0x0001)
PROTECT_READ      // prevent reads (0x0002)
PROTECT_WRITE     // prevent writes (0x0004)
PROTECT_PTRACE    // no debugging (0x0008)
PROTECT_PROC_MEM  // no /proc/pid/mem (0x0010)
PROTECT_SIGNAL    // no SIGKILL/STOP (0x0020)
PROTECT_FORK      // protect children (0x0040)
PROTECT_DEBUG     // allow debuggers (0x0080)
PROTECT_MMAP      // protect mmap (0x0100)
PROTECT_ALL       // ALL THE THINGS (0xFFFF)
```

### ⚡ **actions on violation**

```c
ACTION_TERMINATE_PROTECTED  // kill my process (nuclear)
ACTION_TERMINATE_ATTACKER    // kill the attacker (based)
ACTION_BLOCK_ONLY            // just say no (EACCES)
ACTION_LOG_ONLY              // watch and learn
ACTION_TERMINATE_BOTH        // everyone dies ☠️
ACTION_BLOCK_AND_LOG         // block and tell mom
```

### 🧪 **test it yourself**

```bash
# terminal 1 - victim
cd test
make
./test_victim
# prints: "Victim PID: 1234, secret at 0xDEADBEEF"

# terminal 2 - protect it
echo "protect 1234" | sudo tee /dev/memprtc

# terminal 3 - attacker (watch it fail)
./test_attacker 1234 0xDEADBEEF
# should get permission denied

# check the logs
sudo cat /sys/kernel/debug/memprtc/violations
dmesg | grep memprtc
```

### 📊 **performance** (numbers go brrr)

| operation | time | notes |
|-----------|------|-------|
| non-protected PID check | ~10ns | bloom filter says "nah" |
| protected PID lookup | ~50ns | IDR tree O(1) |
| violation handling | ~1-2μs | logging + action |
| memory used | ~100KB + 8KB per protected PID | bloom filter + IDR |

### 🐛 **wtf it doesn't work**

```bash
# check kernel version
uname -r

# make sure headers are installed
pacman -S linux-headers  # on arch
apt install linux-headers-$(uname -r)  # on debian

# check dmesg for errors
dmesg | tail -50 | grep memprtc

# try loading with debug output
sudo insmod memprtc.ko log_level=2

# verify debugfs is mounted
mount | grep debugfs || sudo mount -t debugfs none /sys/kernel/debug

# still broken? open an issue
```

### 🏗️ **building from source** (for cool people (if you download the binary directly you are absolutely cool too))

```bash
git clone https://github.com/yourusername/memprtc.git
cd memprtc
make
sudo make install
make status  # see if it's happy
```

### 📈 **what's next?** (v4.0 dreams)

- [ ] eBPF integration (because it's cool)
- [ ] container awareness (docker/podman who?)
- [ ] persistent storage (save violations to disk)
- [ ] netlink notifications (real-time alerts)
- [ ] LSM integration (go mainstream)
- [ ] web dashboard (because everything needs one)

### 👨‍💻 **who made this**

a 18yo who got tired of processes messing with each other's memory

- github: [@rhys1xh](https://github.com/rhys1xh)
- discord: rhys1xh
- email: timucindanaci@web.de

### 📜 **license**

GPL v2 - because sharing is caring

```
This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.
```

### 🙏 **shoutouts**

- kernel newbies wiki (saved my ### multiple times)
- stack overflow (where would i be without you steve)
- arch wiki (for not immediately flaming me)
- my laptop for surviving all the kernel panics (i literally counted every panic and im currently at 152 since i was too lazy to install qemu, im serious, im not, even, kidding.)

---

**memprtc - keeping your memory safe since 2025** 🛡️

```bash
# remember kids: with great power comes great responsibility (i abused all the power without responsibility)
# also don't blame me if this crashes your system
# (it shouldn't, but idk though.. it worked on my laptop soo..... ..... )
```
