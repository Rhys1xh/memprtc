// SPDX-License-Identifier: GPL-2.0
/*
 * memprtc - Memory Protection Module
 * 
 * (Latest version, letzter Stand für den Zeitkomplexitäts-Fix (IOCTL Teil))
 * O(1) lookups, architecture independence, and access prevention.
 *
 * Copyright (C) 2026 Timucin Danaci 
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/pid.h>
#include <linux/mm.h>
#include <linux/kprobes.h>
#include <linux/rcupdate.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/timekeeping.h>
#include <linux/idr.h>
#include <linux/hashtable.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/atomic.h>
#include <linux/kref.h>
#include <linux/debugfs.h>
#include <linux/audit.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/seqlock.h>
#include <linux/namei.h>
#include <linux/fs_struct.h>

#include "memprtc.h"
#include "internal.h"

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Timucin Danaci");
MODULE_DESCRIPTION("MEMPRTC - The Ultimate Memory Protection Kernel Module of the Future! " MEMPRTC_VERSION);
MODULE_VERSION(MEMPRTC_VERSION);

/* ==================== MODULE PARAMETERS ==================== */
static bool trust_root = true;
static bool trust_same_user = true;
static bool audit_violations = false;
static uint log_level = 1;
static uint max_protected = MEMPRTC_MAX_PROTECTED;

module_param(trust_root, bool, 0644);
MODULE_PARM_DESC(trust_root, "Trust root processes (default: true)");

module_param(trust_same_user, bool, 0644);
MODULE_PARM_DESC(trust_same_user, "Trust processes with same UID (default: true)");

module_param(audit_violations, bool, 0644);
MODULE_PARM_DESC(audit_violations, "Send violations to audit log (default: false)");

module_param(log_level, uint, 0644);
MODULE_PARM_DESC(log_level, "Log level: 0=errors, 1=warnings, 2=verbose (default: 1)");

module_param(max_protected, uint, 0644);
MODULE_PARM_DESC(max_protected, "Maximum protected processes (default: 1024)");

/* Global module state - defined here */
struct memprtc_state *g_state;
EXPORT_SYMBOL_GPL(g_state);

/* ==================== FORWARD DECLARATIONS ==================== */
static struct protected_entry *get_protected_entry_fast(pid_t pid);
static void put_protected_entry(struct protected_entry *entry);
static bool is_trusted(struct protected_entry *entry, struct task_struct *attacker, int access_type);
static void handle_violation(struct protected_entry *entry, struct task_struct *attacker,
                            unsigned long addr, int access_type, const char *detail);
static void log_violation(struct violation_record *viol);
static void protected_entry_release(struct kref *kref);
static int protect_pid(struct protection_request *req);
static int unprotect_pid(pid_t pid);
static int add_trusted_relation(struct trusted_relation *rel);
static int remove_trusted_relation(struct trusted_relation *rel);

/* ==================== SIMPLE BLOOM FILTER IMPLEMENTATION ==================== */

/* Simple hash functions */
static unsigned int bloom_hash1(const void *data, int len)
{
    unsigned int hash = 0;
    const unsigned char *str = data;
    int i;
    
    for (i = 0; i < len; i++)
        hash = hash * 31 + str[i];
    return hash;
}

static unsigned int bloom_hash2(const void *data, int len)
{
    unsigned int hash = 0;
    const unsigned char *str = data;
    int i;
    
    for (i = 0; i < len; i++)
        hash = hash * 131 + str[i];
    return hash;
}

static unsigned int bloom_hash3(const void *data, int len)
{
    unsigned int hash = 5381;
    const unsigned char *str = data;
    int i;
    
    for (i = 0; i < len; i++)
        hash = ((hash << 5) + hash) + str[i];
    return hash;
}

static struct simple_bloom *bloom_create(unsigned int size_bits, unsigned int hash_count)
{
    struct simple_bloom *bloom;
    unsigned int bitmap_size = BITS_TO_LONGS(size_bits) * sizeof(long);
    
    bloom = kzalloc(sizeof(*bloom), GFP_KERNEL);
    if (!bloom)
        return NULL;
    
    bloom->bits = kzalloc(bitmap_size, GFP_KERNEL);
    if (!bloom->bits) {
        kfree(bloom);
        return NULL;
    }
    
    bloom->size = size_bits;
    bloom->hash_count = hash_count;
    spin_lock_init(&bloom->lock);
    
    return bloom;
}

static void bloom_add(struct simple_bloom *bloom, const void *data, int len)
{
    unsigned int h1, h2, h3;
    unsigned long flags;
    
    if (!bloom || !bloom->bits)
        return;
    
    h1 = bloom_hash1(data, len) % bloom->size;
    h2 = bloom_hash2(data, len) % bloom->size;
    h3 = bloom_hash3(data, len) % bloom->size;
    
    spin_lock_irqsave(&bloom->lock, flags);
    
    set_bit(h1, bloom->bits);
    set_bit(h2, bloom->bits);
    if (bloom->hash_count > 2)
        set_bit(h3, bloom->bits);
    
    spin_unlock_irqrestore(&bloom->lock, flags);
}

static bool bloom_contains(struct simple_bloom *bloom, const void *data, int len)
{
    unsigned int h1, h2, h3;
    unsigned long flags;
    bool result;
    
    if (!bloom || !bloom->bits)
        return true;  /* Fall back to safe path */
    
    h1 = bloom_hash1(data, len) % bloom->size;
    h2 = bloom_hash2(data, len) % bloom->size;
    h3 = bloom_hash3(data, len) % bloom->size;
    
    spin_lock_irqsave(&bloom->lock, flags);
    
    result = test_bit(h1, bloom->bits) && 
             test_bit(h2, bloom->bits) &&
             (bloom->hash_count <= 2 || test_bit(h3, bloom->bits));
    
    spin_unlock_irqrestore(&bloom->lock, flags);
    
    return result;
}

static void bloom_free(struct simple_bloom *bloom)
{
    if (bloom) {
        kfree(bloom->bits);
        kfree(bloom);
    }
}

/* ==================== FAST LOOKUP FUNCTIONS ==================== */

/* Fast path: check if PID might be protected using Bloom filter */
static inline bool might_be_protected(pid_t pid)
{
    if (!g_state || !g_state->fast_filter)
        return true;  /* Fall back to safe path */
    
    return bloom_contains(g_state->fast_filter, &pid, sizeof(pid));
}

/* O(1) protected entry lookup with RCU and seqlock */
static struct protected_entry *get_protected_entry_fast(pid_t pid)
{
    struct protected_entry *entry;
    
    if (!g_state)
        return NULL;
    
    /* Fast negative check using Bloom filter */
    if (!might_be_protected(pid))
        return NULL;
    
    rcu_read_lock();
    entry = idr_find(&g_state->protected_idr, pid);
    if (entry) {
        unsigned int seq;
        bool active;
        
        /* Check active state atomically with seqlock */
        do {
            seq = read_seqbegin(&entry->seqlock);
            active = entry->active;
        } while (read_seqretry(&entry->seqlock, seq));
        
        if (active && kref_get_unless_zero(&entry->refcount)) {
            rcu_read_unlock();
            return entry;
        }
    }
    rcu_read_unlock();
    return NULL;
}

static void put_protected_entry(struct protected_entry *entry)
{
    if (entry)
        kref_put(&entry->refcount, protected_entry_release);
}

/* ==================== TRUSTED PROCESS CHECK ==================== */

static bool is_trusted(struct protected_entry *entry, struct task_struct *attacker, int access_type)
{
    struct trusted_entry *trusted;
    bool trusted_found = false;
    kuid_t attacker_uid;
    
    if (!attacker || !entry || !g_state)
        return false;
    
    /* Fast path: check global config first */
    if (g_state->config.trust_root && capable(CAP_SYS_PTRACE))
        return true;
    
    if (g_state->config.trust_same_user) {
        attacker_uid = task_uid(attacker);
        if (uid_eq(attacker_uid, task_uid(entry->task)))
            return true;
    }
    
    /* If no trusted entries, skip the list traversal */
    if (entry->trusted_count == 0)
        return false;
    
    /* Check per-entry trusted list */
    rcu_read_lock();
    list_for_each_entry_rcu(trusted, &entry->trusted_list, list) {
        if (trusted->trusted_pid == attacker->pid) {
            if (trusted->allowed_ops & access_type) {
                trusted_found = true;
                break;
            }
        }
    }
    rcu_read_unlock();
    
    return trusted_found;
}

/* ==================== VIOLATION HANDLING ==================== */

/* Circular buffer logging */
static void log_violation(struct violation_record *viol)
{
    int head, next;
    unsigned long flags;
    
    if (!g_state)
        return;
    
    spin_lock_irqsave(&g_state->log.lock, flags);
    
    head = atomic_read(&g_state->log.head);
    next = (head + 1) % MEMPRTC_LOG_SIZE;
    
    /* Overwrite oldest if full */
    if (next == atomic_read(&g_state->log.tail)) {
        atomic_inc(&g_state->log.tail);
    }
    
    memcpy(&g_state->log.entries[head], viol, sizeof(*viol));
    atomic_set(&g_state->log.head, next);
    
    spin_unlock_irqrestore(&g_state->log.lock, flags);
}

static void handle_violation(struct protected_entry *entry, struct task_struct *attacker,
                            unsigned long addr, int access_type, const char *detail)
{
    struct violation_record viol;
    unsigned long flags;
    enum violation_action action = entry->action;
    struct pid *attacker_pid;
    
    if (!entry || !attacker || !g_state)
        return;
    
    /* Check if attacker is trusted */
    if (is_trusted(entry, attacker, access_type))
        return;
    
    /* Prepare violation record */
    memset(&viol, 0, sizeof(viol));
    viol.timestamp_ns = ktime_get_real_ns();
    viol.protected_pid = entry->pid;
    viol.attacker_pid = attacker->pid;
    viol.access_addr = addr;
    viol.access_type = access_type;
    viol.action_taken = action;
    
    get_task_comm(viol.attacker_comm, attacker);
    get_task_comm(viol.protected_comm, entry->task);
    
    if (detail)
        strscpy(viol.access_detail, detail, sizeof(viol.access_detail));
    
    /* Log the violation */
    log_violation(&viol);
    
    /* Update statistics */
    spin_lock_irqsave(&g_state->stats_lock, flags);
    g_state->stats.violations_detected++;
    g_state->stats.last_violation_jiffies = jiffies;
    g_state->stats.last_attacking_pid = attacker->pid;
    g_state->stats.last_protected_pid = entry->pid;
    g_state->stats.last_access_address = addr;
    g_state->stats.last_action_taken = action;
    get_task_comm(g_state->stats.last_attacker_comm, attacker);
    get_task_comm(g_state->stats.last_protected_comm, entry->task);
    
    /* Update action-specific counters */
    switch (action) {
        case ACTION_TERMINATE_PROTECTED:
            g_state->stats.processes_terminated++;
            break;
        case ACTION_TERMINATE_ATTACKER:
            g_state->stats.attackers_terminated++;
            break;
        case ACTION_TERMINATE_BOTH:
            g_state->stats.processes_terminated++;
            g_state->stats.attackers_terminated++;
            break;
        case ACTION_BLOCK_ONLY:
        case ACTION_BLOCK_AND_LOG:
            g_state->stats.accesses_blocked++;
            break;
        default:
            break;
    }
    spin_unlock_irqrestore(&g_state->stats_lock, flags);
    
    /* Send to audit log if enabled */
    if (g_state->config.audit_violations) {
        audit_log(current->audit_context, GFP_ATOMIC,
                 AUDIT_AVC, "memprtc violation protected=%d attacker=%d addr=%lx type=%d",
                 entry->pid, attacker->pid, addr, access_type);
    }
    
    /* Log to kernel with configured log level */
    if (g_state->config.log_level >= 1) {
        pr_alert("memprtc: VIOLATION: %s (PID %d) %s protected %s (PID %d) at 0x%lx - action: %d\n",
                 viol.attacker_comm, viol.attacker_pid,
                 access_type == ACCESS_READ ? "READ" : 
                 access_type == ACCESS_WRITE ? "WRITE" : 
                 access_type == ACCESS_PTRACE ? "PTRACE" : 
                 access_type == ACCESS_PROC_MEM ? "PROC_MEM" : 
                 access_type == ACCESS_SIGNAL ? "SIGNAL" : "OTHER",
                 viol.protected_comm, viol.protected_pid, addr, action);
    }
    
    /* Take action based on configuration */
    switch (action) {
        case ACTION_TERMINATE_PROTECTED:
            write_seqlock(&entry->seqlock);
            entry->active = false;
            write_sequnlock(&entry->seqlock);
            
            kill_pid(entry->pid_struct, SIGKILL, 1);
            break;
            
        case ACTION_TERMINATE_ATTACKER:
            attacker_pid = find_get_pid(attacker->pid);
            if (attacker_pid) {
                kill_pid(attacker_pid, SIGKILL, 1);
                put_pid(attacker_pid);
            }
            break;
            
        case ACTION_TERMINATE_BOTH:
            write_seqlock(&entry->seqlock);
            entry->active = false;
            write_sequnlock(&entry->seqlock);
            
            kill_pid(entry->pid_struct, SIGKILL, 1);
            
            attacker_pid = find_get_pid(attacker->pid);
            if (attacker_pid) {
                kill_pid(attacker_pid, SIGKILL, 1);
                put_pid(attacker_pid);
            }
            break;
            
        case ACTION_BLOCK_ONLY:
        case ACTION_BLOCK_AND_LOG:
            /* Action already counted in stats, actual blocking handled by kprobe return value */
            break;
            
        default:
            /* LOG_ONLY etc - already logged */
            break;
    }
}

/* ==================== ARCHITECTURE-SPECIFIC EXTRACTORS ==================== */

static pid_t get_pid_from_di(struct pt_regs *regs)
{
#if defined(CONFIG_X86_64)
    return (pid_t)regs->di;
#elif defined(CONFIG_ARM64)
    return (pid_t)regs->regs[0];
#else
    return (pid_t)regs->di;
#endif
}

static unsigned long get_addr_from_si(struct pt_regs *regs)
{
#if defined(CONFIG_X86_64)
    return regs->si;
#elif defined(CONFIG_ARM64)
    return regs->regs[1];
#else
    return regs->si;
#endif
}

/* ==================== KPROBE HANDLERS WITH ACCESS PREVENTION ==================== */

struct kprobe_handler_context {
    pid_t (*get_target_pid)(struct pt_regs *);
    unsigned long (*get_address)(struct pt_regs *);
    int access_type;
    const char *desc;
    bool needs_address;
};

static struct kprobe_handler_context process_vm_ctx = {
    .get_target_pid = get_pid_from_di,
    .get_address = NULL,
    .access_type = ACCESS_READ | ACCESS_WRITE,
    .desc = "process_vm",
    .needs_address = false
};

static struct kprobe_handler_context ptrace_ctx = {
    .get_target_pid = get_pid_from_di,
    .get_address = get_addr_from_si,
    .access_type = ACCESS_PTRACE,
    .desc = "ptrace",
    .needs_address = true
};

static int generic_access_handler(struct kprobe_handler_context *ctx, struct pt_regs *regs)
{
    pid_t target_pid;
    struct protected_entry *entry;
    int ret = 0;
    
    if (!ctx || !ctx->get_target_pid)
        return 0;
    
    target_pid = ctx->get_target_pid(regs);
    
    entry = get_protected_entry_fast(target_pid);
    if (!entry)
        return 0;
    
    if (!is_trusted(entry, current, ctx->access_type)) {
        unsigned long addr = ctx->needs_address && ctx->get_address ? 
                             ctx->get_address(regs) : 0;
        
        handle_violation(entry, current, addr, ctx->access_type, ctx->desc);
        
        /* Block access based on action */
        if (entry->action == ACTION_BLOCK_ONLY || 
            entry->action == ACTION_BLOCK_AND_LOG) {
            regs->ax = -EACCES;
            ret = 1;
        }
    }
    
    put_protected_entry(entry);
    return ret;
}

static int handler_process_vm(struct kprobe *p, struct pt_regs *regs)
{
    return generic_access_handler(&process_vm_ctx, regs);
}

static int handler_ptrace(struct kprobe *p, struct pt_regs *regs)
{
    return generic_access_handler(&ptrace_ctx, regs);
}

static int handler_mm_fault(struct kprobe *p, struct pt_regs *regs)
{
    struct vm_area_struct *vma;
    struct mm_struct *mm;
    unsigned long address;
    struct protected_entry *entry;
    struct task_struct *task;
    int write_access;
    
#if defined(CONFIG_X86_64)
    address = regs->di;
    vma = (struct vm_area_struct *)regs->si;
    write_access = regs->dx & FAULT_FLAG_WRITE;
#else
    address = regs->di;
    vma = (struct vm_area_struct *)regs->si;
    write_access = 0;
#endif
    
    if (!vma || !vma->vm_mm)
        return 0;
    
    mm = vma->vm_mm;
    
    rcu_read_lock();
    for_each_process(task) {
        if (task->mm == mm) {
            entry = get_protected_entry_fast(task->pid);
            if (entry) {
                int access_type = write_access ? ACCESS_WRITE : ACCESS_READ;
                
                if (!is_trusted(entry, current, access_type)) {
                    handle_violation(entry, current, address, access_type, "page_fault");
                    
                    if (entry->action == ACTION_BLOCK_ONLY ||
                        entry->action == ACTION_BLOCK_AND_LOG) {
                        send_sig(SIGSEGV, current, 0);
                    }
                }
                put_protected_entry(entry);
            }
            break;
        }
    }
    rcu_read_unlock();
    
    return 0;
}

static int handler_proc_mem(struct kprobe *p, struct pt_regs *regs)
{
    struct file *file;
    pid_t target_pid = 0;
    struct protected_entry *entry;
    char *path_buf;
    int ret = 0;
    
#if defined(CONFIG_X86_64)
    file = (struct file *)regs->di;
#else
    file = (struct file *)regs->di;
#endif
    
    if (!file || !file->f_path.dentry)
        return 0;
    
    path_buf = (char *)__get_free_page(GFP_KERNEL);
    if (!path_buf)
        return 0;
    
    if (!d_path(&file->f_path, path_buf, PAGE_SIZE)) {
        free_page((unsigned long)path_buf);
        return 0;
    }
    
    if (strstr(path_buf, "/proc/") && strstr(path_buf, "/mem")) {
        char *pid_start = strstr(path_buf, "/proc/") + 6;
        char *pid_end = strchr(pid_start, '/');
        
        if (pid_end) {
            *pid_end = '\0';
            if (kstrtoint(pid_start, 10, &target_pid) < 0)
                target_pid = 0;
            *pid_end = '/';
        }
    }
    
    if (target_pid) {
        entry = get_protected_entry_fast(target_pid);
        if (entry) {
            if (entry->flags & PROTECT_PROC_MEM) {
                if (!is_trusted(entry, current, ACCESS_PROC_MEM)) {
                    handle_violation(entry, current, 0, ACCESS_PROC_MEM, "proc_mem");
                    
                    if (entry->action == ACTION_BLOCK_ONLY ||
                        entry->action == ACTION_BLOCK_AND_LOG) {
                        regs->ax = -EACCES;
                        ret = 1;
                    }
                }
            }
            put_protected_entry(entry);
        }
    }
    
    free_page((unsigned long)path_buf);
    return ret;
}

static int handler_remote_vm(struct kprobe *p, struct pt_regs *regs)
{
    struct task_struct *target_task;
    struct protected_entry *entry;
    int ret = 0;
    
#if defined(CONFIG_X86_64)
    target_task = (struct task_struct *)regs->di;
#else
    target_task = (struct task_struct *)regs->di;
#endif
    
    if (!target_task)
        return 0;
    
    entry = get_protected_entry_fast(target_task->pid);
    if (entry) {
        if (!is_trusted(entry, current, ACCESS_READ | ACCESS_WRITE)) {
            unsigned long addr = get_addr_from_si(regs);
            handle_violation(entry, current, addr, ACCESS_READ | ACCESS_WRITE, "remote_vm");
            
            if (entry->action == ACTION_BLOCK_ONLY ||
                entry->action == ACTION_BLOCK_AND_LOG) {
                regs->ax = -EACCES;
                ret = 1;
            }
        }
        put_protected_entry(entry);
    }
    
    return ret;
}

static int handler_kill(struct kprobe *p, struct pt_regs *regs)
{
    pid_t target_pid;
    struct protected_entry *entry;
    int ret = 0;
    
#if defined(CONFIG_X86_64)
    target_pid = (pid_t)regs->di;
#else
    target_pid = (pid_t)regs->di;
#endif
    
    entry = get_protected_entry_fast(target_pid);
    if (entry) {
        if (entry->flags & PROTECT_SIGNAL) {
            if (!is_trusted(entry, current, ACCESS_SIGNAL)) {
                int sig = (int)regs->si;
                
                if (sig == SIGKILL || sig == SIGTERM || sig == SIGSTOP) {
                    handle_violation(entry, current, sig, ACCESS_SIGNAL, "signal");
                    
                    if (entry->action == ACTION_BLOCK_ONLY ||
                        entry->action == ACTION_BLOCK_AND_LOG) {
                        regs->ax = -EPERM;
                        ret = 1;
                    }
                }
            }
        }
        put_protected_entry(entry);
    }
    
    return ret;
}

/* ==================== SYMBOL RESOLUTION WITH FALLBACKS ==================== */

struct kprobe_definition {
    const char * const *symbols;
    kprobe_pre_handler_t handler;
};

static const char * const process_vm_symbols[] = {
    "__x64_sys_process_vm_readv",
    "__ia32_sys_process_vm_readv", 
    "__arm64_sys_process_vm_readv",
    "sys_process_vm_readv",
    NULL
};

static const char * const ptrace_symbols[] = {
    "__x64_sys_ptrace",
    "__ia32_sys_ptrace",
    "__arm64_sys_ptrace",
    "sys_ptrace",
    NULL
};

static const char * const mm_fault_symbols[] = {
    "handle_mm_fault",
    "__handle_mm_fault",
    "do_page_fault",
    NULL
};

static const char * const proc_mem_symbols[] = {
    "mem_write",
    "proc_mem_write",
    "mem_read",
    "proc_mem_read",
    NULL
};

static const char * const remote_vm_symbols[] = {
    "access_remote_vm",
    "__access_remote_vm",
    NULL
};

static const char * const kill_symbols[] = {
    "__x64_sys_kill",
    "__ia32_sys_kill",
    "__arm64_sys_kill",
    "sys_kill",
    NULL
};

static struct kprobe_definition kprobe_defs[] = {
    {
        .symbols = process_vm_symbols,
        .handler = handler_process_vm,
    },
    {
        .symbols = ptrace_symbols,
        .handler = handler_ptrace,
    },
    {
        .symbols = mm_fault_symbols,
        .handler = handler_mm_fault,
    },
    {
        .symbols = proc_mem_symbols,
        .handler = handler_proc_mem,
    },
    {
        .symbols = remote_vm_symbols,
        .handler = handler_remote_vm,
    },
    {
        .symbols = kill_symbols,
        .handler = handler_kill,
    },
    { .symbols = NULL }
};

static int register_kprobe_with_fallbacks(struct kprobe_definition *def, struct kprobe *kp)
{
    int ret = -EINVAL;
    int i;
    
    for (i = 0; def->symbols[i]; i++) {
        memset(kp, 0, sizeof(*kp));
        kp->symbol_name = def->symbols[i];
        kp->pre_handler = def->handler;
        
        ret = register_kprobe(kp);
        if (ret == 0) {
            pr_info("memprtc: Registered kprobe for %s\n", def->symbols[i]);
            return 0;
        }
    }
    
    return ret;
}

/* ==================== PROTECTION MANAGEMENT ==================== */

static void protected_entry_release(struct kref *kref)
{
    struct protected_entry *entry = container_of(kref, struct protected_entry, refcount);
    struct trusted_entry *trusted, *tmp;
    
    list_for_each_entry_safe(trusted, tmp, &entry->trusted_list, list) {
        list_del_rcu(&trusted->list);
        kfree_rcu(trusted, rcu);
    }
    
    if (entry->task)
        put_task_struct(entry->task);
    if (entry->pid_struct)
        put_pid(entry->pid_struct);
    kfree_rcu(entry, rcu);
}

static int protect_pid(struct protection_request *req)
{
    struct protected_entry *entry;
    struct pid *pid_struct;
    struct task_struct *task;
    unsigned long flags;
    int idr_ret;

    if (!req || !g_state)
        return -EINVAL;

    pid_struct = find_get_pid(req->pid);
    if (!pid_struct) {
        pr_err("memprtc: PID %d not found\n", req->pid);
        return -ESRCH;
    }

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        put_pid(pid_struct);
        pr_err("memprtc: Cannot get task for PID %d\n", req->pid);
        return -ESRCH;
    }

    entry = get_protected_entry_fast(req->pid);
    if (entry) {
        put_protected_entry(entry);
        put_task_struct(task);
        put_pid(pid_struct);
        pr_info("memprtc: PID %d already protected\n", req->pid);
        return -EEXIST;
    }

    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        put_task_struct(task);
        put_pid(pid_struct);
        return -ENOMEM;
    }

    kref_init(&entry->refcount);
    seqlock_init(&entry->seqlock);
    entry->pid = req->pid;
    entry->pid_struct = pid_struct;
    entry->task = task;
    entry->protected_since = jiffies;
    entry->flags = req->flags;
    entry->action = req->action;
    entry->active = true;
    atomic_set(&entry->violation_count, 0);
    INIT_LIST_HEAD(&entry->trusted_list);
    spin_lock_init(&entry->trusted_lock);
    strscpy(entry->comment, req->comment, MEMPRTC_MAX_COMMENT);

    idr_preload(GFP_KERNEL);
    spin_lock_irqsave(&g_state->idr_lock, flags);
    idr_ret = idr_alloc(&g_state->protected_idr, entry, req->pid, req->pid + 1, GFP_NOWAIT);
    spin_unlock_irqrestore(&g_state->idr_lock, flags);
    idr_preload_end();

    if (idr_ret < 0) {
        pr_err("memprtc: Failed to add PID %d to IDR\n", req->pid);
        kfree(entry);
        put_task_struct(task);
        put_pid(pid_struct);
        return idr_ret;
    }

    if (g_state->fast_filter)
        bloom_add(g_state->fast_filter, &req->pid, sizeof(req->pid));

    atomic_inc(&g_state->active_protections);

    pr_info("memprtc: Protected PID %d (%s) [flags=0x%lx, action=%d, total: %d]\n", 
            req->pid, task->comm, req->flags, req->action,
            atomic_read(&g_state->active_protections));

    return 0;
}

static int unprotect_pid(pid_t pid)
{
    struct protected_entry *entry;
    unsigned long flags;

    if (!g_state)
        return -EINVAL;

    entry = get_protected_entry_fast(pid);
    if (!entry)
        return -ESRCH;

    write_seqlock(&entry->seqlock);
    entry->active = false;
    write_sequnlock(&entry->seqlock);

    spin_lock_irqsave(&g_state->idr_lock, flags);
    idr_remove(&g_state->protected_idr, pid);
    spin_unlock_irqrestore(&g_state->idr_lock, flags);

    atomic_dec(&g_state->active_protections);
    
    put_protected_entry(entry);
    
    pr_info("memprtc: Unprotected PID %d [remaining: %d]\n", 
            pid, atomic_read(&g_state->active_protections));
    
    return 0;
}

static int add_trusted_relation(struct trusted_relation *rel)
{
    struct protected_entry *entry;
    struct trusted_entry *trusted;
    unsigned long flags;

    if (!g_state)
        return -EINVAL;

    entry = get_protected_entry_fast(rel->protected_pid);
    if (!entry)
        return -ESRCH;

    if (entry->trusted_count >= MEMPRTC_MAX_TRUSTED) {
        put_protected_entry(entry);
        return -ENOSPC;
    }

    trusted = kzalloc(sizeof(*trusted), GFP_KERNEL);
    if (!trusted) {
        put_protected_entry(entry);
        return -ENOMEM;
    }

    trusted->trusted_pid = rel->trusted_pid;
    trusted->allowed_ops = rel->allowed_ops;
    INIT_LIST_HEAD(&trusted->list);

    spin_lock_irqsave(&entry->trusted_lock, flags);
    list_add_rcu(&trusted->list, &entry->trusted_list);
    entry->trusted_count++;
    spin_unlock_irqrestore(&entry->trusted_lock, flags);

    put_protected_entry(entry);
    
    pr_info("memprtc: PID %d trusted for PID %d (ops=0x%lx)\n",
            rel->trusted_pid, rel->protected_pid, rel->allowed_ops);
    
    return 0;
}

static int remove_trusted_relation(struct trusted_relation *rel)
{
    struct protected_entry *entry;
    struct trusted_entry *trusted, *tmp;
    unsigned long flags;
    int found = 0;

    if (!g_state)
        return -EINVAL;

    entry = get_protected_entry_fast(rel->protected_pid);
    if (!entry)
        return -ESRCH;

    spin_lock_irqsave(&entry->trusted_lock, flags);
    list_for_each_entry_safe(trusted, tmp, &entry->trusted_list, list) {
        if (trusted->trusted_pid == rel->trusted_pid) {
            list_del_rcu(&trusted->list);
            entry->trusted_count--;
            kfree_rcu(trusted, rcu);
            found = 1;
            break;
        }
    }
    spin_unlock_irqrestore(&entry->trusted_lock, flags);

    put_protected_entry(entry);
    
    if (found) {
        pr_info("memprtc: Removed trusted relation: PID %d trusted for PID %d\n",
                rel->trusted_pid, rel->protected_pid);
        return 0;
    }
    
    return -ENOENT;
}

/* ==================== DEVICE INTERFACE ==================== */

static int memprtc_open(struct inode *inode, struct file *file)
{
    return 0;
}

static int memprtc_release(struct inode *inode, struct file *file)
{
    return 0;
}

static ssize_t memprtc_read(struct file *file, char __user *buf, size_t len, loff_t *off)
{
    char *local_buf;
    int ret;
    unsigned long flags;
    struct protected_entry *entry;
    int i = 0;
    size_t buf_size = 2048;

    if (*off > 0 || !g_state)
        return 0;

    local_buf = kmalloc(buf_size, GFP_KERNEL);
    if (!local_buf)
        return -ENOMEM;

    spin_lock_irqsave(&g_state->stats_lock, flags);
    ret = snprintf(local_buf, buf_size,
        "memprtc v%s\n"
        "================\n"
        "Active protections: %d\n"
        "Total violations: %lu\n"
        "Processes terminated: %lu\n"
        "Attackers terminated: %lu\n"
        "Accesses blocked: %lu\n"
        "Last violation: %lu jiffies ago\n"
        "\n"
        "Protected PIDs:\n",
        MEMPRTC_VERSION,
        atomic_read(&g_state->active_protections),
        g_state->stats.violations_detected,
        g_state->stats.processes_terminated,
        g_state->stats.attackers_terminated,
        g_state->stats.accesses_blocked,
        g_state->stats.last_violation_jiffies ? 
            jiffies - g_state->stats.last_violation_jiffies : 0);
    spin_unlock_irqrestore(&g_state->stats_lock, flags);

    rcu_read_lock();
    idr_for_each_entry(&g_state->protected_idr, entry, i) {
        unsigned int seq;
        bool active;
        
        do {
            seq = read_seqbegin(&entry->seqlock);
            active = entry->active;
        } while (read_seqretry(&entry->seqlock, seq));
        
        if (active && ret < buf_size - 100) {
            ret += snprintf(local_buf + ret, buf_size - ret,
                           "  %d: %s (flags=0x%lx, action=%d)\n",
                           entry->pid, entry->comment, entry->flags, entry->action);
        }
    }
    rcu_read_unlock();

    ret = simple_read_from_buffer(buf, len, off, local_buf, ret);
    kfree(local_buf);
    return ret;
}

static ssize_t memprtc_write(struct file *file, const char __user *buf, size_t len, loff_t *off)
{
    char cmd[256];
    struct protection_request req;
    pid_t pid;
    int ret;

    if (!g_state)
        return -EINVAL;

    if (len >= sizeof(cmd))
        return -EINVAL;

    if (copy_from_user(cmd, buf, len))
        return -EFAULT;
    
    cmd[len] = '\0';

    if (strncmp(cmd, "protect ", 8) == 0) {
        memset(&req, 0, sizeof(req));
        ret = kstrtoint(cmd + 8, 10, &req.pid);
        if (ret)
            return ret;
        req.flags = PROTECT_ALL;
        req.action = ACTION_BLOCK_AND_LOG;
        strscpy(req.comment, "CLI protected", sizeof(req.comment));
        ret = protect_pid(&req);
    } else if (strncmp(cmd, "unprotect ", 10) == 0) {
        ret = kstrtoint(cmd + 10, 10, &pid);
        if (ret)
            return ret;
        ret = unprotect_pid(pid);
    } else if (strncmp(cmd, "trust ", 6) == 0) {
        struct trusted_relation rel;
        char *p = cmd + 6;
        char *token;
        
        token = strsep(&p, " ");
        if (!token) return -EINVAL;
        ret = kstrtoint(token, 10, &rel.protected_pid);
        if (ret) return ret;
        
        token = strsep(&p, " ");
        if (!token) return -EINVAL;
        ret = kstrtoint(token, 10, &rel.trusted_pid);
        if (ret) return ret;
        
        token = strsep(&p, " ");
        if (!token) return -EINVAL;
        ret = kstrtoul(token, 0, &rel.allowed_ops);
        if (ret) return ret;
        
        ret = add_trusted_relation(&rel);
    } else {
        return -EINVAL;
    }

    return (ret == 0) ? len : ret;
}

static long memprtc_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    pid_t pid;
    struct protection_request *req;
    struct trusted_relation *rel;
    struct memprtc_status *status;
    struct memprtc_stats *stats;
    struct memprtc_config *config;
    struct violation_query *vq;
    struct protected_entry *entry;
    int i = 0;
    long ret = 0;

    if (!g_state)
        return -EINVAL;

    switch (cmd) {
        case MEMPRTC_PROTECT_PID_CASE:
            req = kmalloc(sizeof(*req), GFP_KERNEL);
            if (!req)
                return -ENOMEM;
            if (copy_from_user(req, (void __user *)arg, sizeof(*req))) {
                kfree(req);
                return -EFAULT;
            }
            ret = protect_pid(req);
            kfree(req);
            return ret;

        case MEMPRTC_UNPROTECT_PID_CASE:
            if (copy_from_user(&pid, (pid_t __user *)arg, sizeof(pid)))
                return -EFAULT;
            return unprotect_pid(pid);

        case MEMPRTC_ADD_TRUSTED_CASE:
            rel = kmalloc(sizeof(*rel), GFP_KERNEL);
            if (!rel)
                return -ENOMEM;
            if (copy_from_user(rel, (void __user *)arg, sizeof(*rel))) {
                kfree(rel);
                return -EFAULT;
            }
            ret = add_trusted_relation(rel);
            kfree(rel);
            return ret;

        case MEMPRTC_REMOVE_TRUSTED_CASE:
            rel = kmalloc(sizeof(*rel), GFP_KERNEL);
            if (!rel)
                return -ENOMEM;
            if (copy_from_user(rel, (void __user *)arg, sizeof(*rel))) {
                kfree(rel);
                return -EFAULT;
            }
            ret = remove_trusted_relation(rel);
            kfree(rel);
            return ret;

        case MEMPRTC_GET_STATUS_CASE:
            status = kmalloc(sizeof(*status), GFP_KERNEL);
            if (!status)
                return -ENOMEM;
            
            memset(status, 0, sizeof(*status));
            
            rcu_read_lock();
            idr_for_each_entry(&g_state->protected_idr, entry, i) {
                unsigned int seq;
                bool active;
                
                do {
                    seq = read_seqbegin(&entry->seqlock);
                    active = entry->active;
                } while (read_seqretry(&entry->seqlock, seq));
                
                if (active && status->count < MEMPRTC_MAX_PROTECTED) {
                    status->protected_pids[status->count] = entry->pid;
                    status->protection_flags[status->count++] = entry->flags;
                }
            }
            rcu_read_unlock();
            
            status->uptime_jiffies = jiffies - g_state->module_start_jiffies;
            spin_lock(&g_state->stats_lock);
            status->total_violations = g_state->stats.violations_detected;
            status->total_blocks = g_state->stats.accesses_blocked;
            spin_unlock(&g_state->stats_lock);

            if (copy_to_user((void __user *)arg, status, sizeof(*status))) {
                kfree(status);
                return -EFAULT;
            }
            kfree(status);
            return 0;

        case MEMPRTC_GET_STATS_CASE:
            stats = kmalloc(sizeof(*stats), GFP_KERNEL);
            if (!stats)
                return -ENOMEM;
            
            spin_lock(&g_state->stats_lock);
            memcpy(stats, &g_state->stats, sizeof(*stats));
            spin_unlock(&g_state->stats_lock);

            if (copy_to_user((void __user *)arg, stats, sizeof(*stats))) {
                kfree(stats);
                return -EFAULT;
            }
            kfree(stats);
            return 0;

        case MEMPRTC_SET_CONFIG_CASE:
            config = kmalloc(sizeof(*config), GFP_KERNEL);
            if (!config)
                return -ENOMEM;
            
            if (copy_from_user(config, (void __user *)arg, sizeof(*config))) {
                kfree(config);
                return -EFAULT;
            }
            spin_lock(&g_state->config_lock);
            memcpy(&g_state->config, config, sizeof(*config));
            spin_unlock(&g_state->config_lock);
            kfree(config);
            return 0;

        case MEMPRTC_GET_CONFIG_CASE:
            config = kmalloc(sizeof(*config), GFP_KERNEL);
            if (!config)
                return -ENOMEM;
            
            spin_lock(&g_state->config_lock);
            memcpy(config, &g_state->config, sizeof(*config));
            spin_unlock(&g_state->config_lock);
            
            if (copy_to_user((void __user *)arg, config, sizeof(*config))) {
                kfree(config);
                return -EFAULT;
            }
            kfree(config);
            return 0;

        case MEMPRTC_GET_VIOLATIONS_CASE:
            vq = kmalloc(sizeof(*vq), GFP_KERNEL);
            if (!vq)
                return -ENOMEM;

            if (copy_from_user(vq, (void __user *)arg, sizeof(*vq))) {
                kfree(vq);
                return -EFAULT;
            }
            
            memset(vq->records, 0, sizeof(vq->records));
            
            spin_lock(&g_state->log.lock);
            {
                int head = atomic_read(&g_state->log.head);
                int tail = atomic_read(&g_state->log.tail);
                int count = 0;
                int idx = tail;
                
                while (idx != head && count < vq->count && count < MEMPRTC_LOG_SIZE) {
                    memcpy(&vq->records[count], &g_state->log.entries[idx], 
                           sizeof(struct violation_record));
                    count++;
                    idx = (idx + 1) % MEMPRTC_LOG_SIZE;
                }
                vq->count = count;
            }
            spin_unlock(&g_state->log.lock);
            
            if (copy_to_user((void __user *)arg, vq, sizeof(*vq))) {
                kfree(vq);
                return -EFAULT;
            }
            kfree(vq);
            return 0;

        default:
            return -ENOTTY;
    }
}

/* File operations */
static struct file_operations memprtc_fops = {
    .owner = THIS_MODULE,
    .open = memprtc_open,
    .release = memprtc_release,
    .read = memprtc_read,
    .write = memprtc_write,
    .unlocked_ioctl = memprtc_ioctl,
};

/* ==================== SYSFS INTERFACE ==================== */

static ssize_t protected_pids_show(const struct class *class,
                                   const struct class_attribute *attr,
                                   char *buf)
{
    struct protected_entry *entry;
    ssize_t count = 0;
    int i = 0;

    if (!g_state)
        return 0;

    rcu_read_lock();
    idr_for_each_entry(&g_state->protected_idr, entry, i) {
        unsigned int seq;
        bool active;
        
        do {
            seq = read_seqbegin(&entry->seqlock);
            active = entry->active;
        } while (read_seqretry(&entry->seqlock, seq));
        
        if (active) {
            count += scnprintf(buf + count, PAGE_SIZE - count,
                              "%d ", entry->pid);
        }
    }
    rcu_read_unlock();

    count += scnprintf(buf + count, PAGE_SIZE - count, "\n");
    return count;
}

static ssize_t stats_show(const struct class *class,
                          const struct class_attribute *attr,
                          char *buf)
{
    unsigned long flags;
    ssize_t count;

    if (!g_state)
        return 0;

    spin_lock_irqsave(&g_state->stats_lock, flags);
    count = scnprintf(buf, PAGE_SIZE,
        "violations: %lu\n"
        "terminations: %lu\n"
        "attackers_terminated: %lu\n"
        "blocked: %lu\n"
        "active_protections: %d\n"
        "uptime_seconds: %lu\n",
        g_state->stats.violations_detected,
        g_state->stats.processes_terminated,
        g_state->stats.attackers_terminated,
        g_state->stats.accesses_blocked,
        atomic_read(&g_state->active_protections),
        (jiffies - g_state->module_start_jiffies) / HZ);
    spin_unlock_irqrestore(&g_state->stats_lock, flags);

    return count;
}

static ssize_t config_show(const struct class *class,
                           const struct class_attribute *attr,
                           char *buf)
{
    ssize_t count;

    if (!g_state)
        return 0;

    spin_lock(&g_state->config_lock);
    count = scnprintf(buf, PAGE_SIZE,
        "trust_root: %d\n"
        "trust_same_user: %d\n"
        "audit_violations: %d\n"
        "log_level: %u\n"
        "violation_timeout: %lu\n"
        "max_protected: %u\n",
        g_state->config.trust_root,
        g_state->config.trust_same_user,
        g_state->config.audit_violations,
        g_state->config.log_level,
        g_state->config.violation_timeout,
        g_state->config.max_protected);
    spin_unlock(&g_state->config_lock);

    return count;
}

static struct class_attribute memprtc_class_attrs[] = {
    __ATTR_RO(protected_pids),
    __ATTR_RO(stats),
    __ATTR_RO(config),
    __ATTR_NULL
};

/* ==================== DEBUGFS INTERFACE ==================== */

static int violations_show(struct seq_file *m, void *v)
{
    int head, tail, i;
    struct violation_record *entry;
    
    if (!g_state)
        return 0;
    
    seq_printf(m, "memprtc violation log (circular buffer size: %d)\n", MEMPRTC_LOG_SIZE);
    seq_printf(m, "%-20s %-8s %-8s %-16s %-12s %-10s %s\n",
               "Timestamp", "Protected", "Attacker", "Address", "Type", "Action", "Detail");
    
    head = atomic_read(&g_state->log.head);
    tail = atomic_read(&g_state->log.tail);
    
    i = tail;
    while (i != head) {
        entry = &g_state->log.entries[i];
        seq_printf(m, "%-20llu %-8d %-8d 0x%-14lx %-12s %-10d %s\n",
                   entry->timestamp_ns,
                   entry->protected_pid,
                   entry->attacker_pid,
                   entry->access_addr,
                   entry->access_type == ACCESS_READ ? "READ" :
                   entry->access_type == ACCESS_WRITE ? "WRITE" : 
                   entry->access_type == ACCESS_PTRACE ? "PTRACE" : 
                   entry->access_type == ACCESS_PROC_MEM ? "PROC_MEM" :
                   entry->access_type == ACCESS_SIGNAL ? "SIGNAL" : "OTHER",
                   entry->action_taken,
                   entry->access_detail);
        i = (i + 1) % MEMPRTC_LOG_SIZE;
    }
    
    return 0;
}

static int violations_open(struct inode *inode, struct file *file)
{
    return single_open(file, violations_show, NULL);
}

static const struct file_operations violations_fops = {
    .owner = THIS_MODULE,
    .open = violations_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int protected_list_show(struct seq_file *m, void *v)
{
    struct protected_entry *entry;
    int i = 0;
    
    if (!g_state)
        return 0;
    
    seq_printf(m, "%-8s %-16s %-8s %-10s %s\n",
               "PID", "Protected Since", "Flags", "Action", "Comment");
    
    rcu_read_lock();
    idr_for_each_entry(&g_state->protected_idr, entry, i) {
        unsigned int seq;
        bool active;
        
        do {
            seq = read_seqbegin(&entry->seqlock);
            active = entry->active;
        } while (read_seqretry(&entry->seqlock, seq));
        
        if (active) {
            unsigned long seconds = (jiffies - entry->protected_since) / HZ;
            seq_printf(m, "%-8d %-16lu %-8lx %-10d %s\n",
                       entry->pid,
                       seconds,
                       entry->flags,
                       entry->action,
                       entry->comment);
        }
    }
    rcu_read_unlock();
    
    return 0;
}

static int protected_list_open(struct inode *inode, struct file *file)
{
    return single_open(file, protected_list_show, NULL);
}

static const struct file_operations protected_list_fops = {
    .owner = THIS_MODULE,
    .open = protected_list_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

/* ==================== MODULE INIT & EXIT ==================== */

static int __init memprtc_init(void)
{
    int ret, i;
    dev_t dev_num;

    pr_info("memprtc: Loading ultimate version %s\n", MEMPRTC_VERSION);

    g_state = kzalloc(sizeof(*g_state), GFP_KERNEL);
    if (!g_state) {
        pr_err("memprtc: Failed to allocate module state\n");
        return -ENOMEM;
    }

    idr_init(&g_state->protected_idr);
    spin_lock_init(&g_state->idr_lock);
    spin_lock_init(&g_state->stats_lock);
    spin_lock_init(&g_state->config_lock);
    spin_lock_init(&g_state->log.lock);
    atomic_set(&g_state->log.head, 0);
    atomic_set(&g_state->log.tail, 0);
    atomic_set(&g_state->active_protections, 0);
    g_state->module_start_jiffies = jiffies;

    g_state->fast_filter = bloom_create(MEMPRTC_BLOOM_SIZE, 3);
    if (!g_state->fast_filter) {
        pr_warn("memprtc: Failed to allocate Bloom filter, using slow path\n");
    }

    /* Set default config from module parameters */
    g_state->config.trust_root = trust_root;
    g_state->config.trust_same_user = trust_same_user;
    g_state->config.audit_violations = audit_violations;
    g_state->config.log_level = log_level;
    g_state->config.max_protected = min(max_protected, (uint)MEMPRTC_MAX_PROTECTED);
    g_state->config.violation_timeout = 0;
    g_state->config.panic_on_critical = false;

    g_state->kprobes = kcalloc(ARRAY_SIZE(kprobe_defs), sizeof(struct kprobe), GFP_KERNEL);
    if (!g_state->kprobes) {
        ret = -ENOMEM;
        goto err_free_bloom;
    }

    for (i = 0; kprobe_defs[i].symbols; i++) {
        ret = register_kprobe_with_fallbacks(&kprobe_defs[i], &g_state->kprobes[i]);
        if (ret < 0) {
            pr_warn("memprtc: Failed to register kprobe %d, continuing\n", i);
        } else {
            g_state->kprobe_count++;
        }
    }

    ret = alloc_chrdev_region(&dev_num, 0, 1, MEMPRTC_DEVICE_NAME);
    if (ret < 0) {
        pr_err("memprtc: Failed to allocate device number\n");
        goto err_unregister_kprobes;
    }
    g_state->dev_num = dev_num;

    g_state->class = class_create(MEMPRTC_CLASS_NAME);
    if (IS_ERR(g_state->class)) {
        ret = PTR_ERR(g_state->class);
        pr_err("memprtc: Failed to create class\n");
        goto err_unregister_region;
    }

    for (i = 0; i < ARRAY_SIZE(memprtc_class_attrs) - 1; i++) {
        ret = class_create_file(g_state->class, &memprtc_class_attrs[i]);
        if (ret) {
            pr_err("memprtc: Failed to create attribute %d\n", i);
            while (--i >= 0)
                class_remove_file(g_state->class, &memprtc_class_attrs[i]);
            goto err_destroy_class;
        }
    }

    cdev_init(&g_state->cdev, &memprtc_fops);
    g_state->cdev.owner = THIS_MODULE;

    ret = cdev_add(&g_state->cdev, dev_num, 1);
    if (ret < 0) {
        pr_err("memprtc: Failed to add cdev\n");
        goto err_remove_class_files;
    }

    g_state->device = device_create(g_state->class, NULL, dev_num,
                                    NULL, MEMPRTC_DEVICE_NAME);
    if (IS_ERR(g_state->device)) {
        ret = PTR_ERR(g_state->device);
        pr_err("memprtc: Failed to create device\n");
        goto err_delete_cdev;
    }

    g_state->debugfs_dir = debugfs_create_dir("memprtc", NULL);
    if (!IS_ERR(g_state->debugfs_dir)) {
        debugfs_create_file("violations", 0444, g_state->debugfs_dir,
                           NULL, &violations_fops);
        debugfs_create_file("protected", 0444, g_state->debugfs_dir,
                           NULL, &protected_list_fops);
        debugfs_create_u32("active_protections", 0444, g_state->debugfs_dir,
                          (u32 *)&g_state->active_protections);
        debugfs_create_u64("total_violations", 0444, g_state->debugfs_dir,
                          (u64 *)&g_state->stats.violations_detected);
        debugfs_create_u64("total_blocks", 0444, g_state->debugfs_dir,
                          (u64 *)&g_state->stats.accesses_blocked);
    }

    pr_info("memprtc: Module loaded successfully\n");
    pr_info("memprtc: Use 'echo \"protect PID\" > /dev/%s' to protect a process\n",
            MEMPRTC_DEVICE_NAME);
    pr_info("memprtc: DebugFS available at /sys/kernel/debug/memprtc/\n");

    return 0;

err_delete_cdev:
    cdev_del(&g_state->cdev);
err_remove_class_files:
    for (i = 0; i < ARRAY_SIZE(memprtc_class_attrs) - 1; i++)
        class_remove_file(g_state->class, &memprtc_class_attrs[i]);
err_destroy_class:
    class_destroy(g_state->class);
err_unregister_region:
    unregister_chrdev_region(dev_num, 1);
err_unregister_kprobes:
    for (i = 0; i < g_state->kprobe_count; i++)
        unregister_kprobe(&g_state->kprobes[i]);
    kfree(g_state->kprobes);
err_free_bloom:
    if (g_state->fast_filter)
        bloom_free(g_state->fast_filter);
    idr_destroy(&g_state->protected_idr);
    kfree(g_state);
    g_state = NULL;
    return ret;
}

static void __exit memprtc_exit(void)
{
    struct protected_entry *entry;
    int i = 0;

    if (!g_state)
        return;

    pr_info("memprtc: Unloading module\n");

    for (i = 0; i < g_state->kprobe_count; i++)
        unregister_kprobe(&g_state->kprobes[i]);
    kfree(g_state->kprobes);

    debugfs_remove_recursive(g_state->debugfs_dir);

    spin_lock(&g_state->idr_lock);
    idr_for_each_entry(&g_state->protected_idr, entry, i) {
        idr_remove(&g_state->protected_idr, entry->pid);
        write_seqlock(&entry->seqlock);
        entry->active = false;
        write_sequnlock(&entry->seqlock);
        put_protected_entry(entry);
    }
    spin_unlock(&g_state->idr_lock);
    
    synchronize_rcu();

    device_destroy(g_state->class, g_state->dev_num);
    cdev_del(&g_state->cdev);
    
    for (i = 0; i < ARRAY_SIZE(memprtc_class_attrs) - 1; i++)
        class_remove_file(g_state->class, &memprtc_class_attrs[i]);
    
    class_destroy(g_state->class);
    unregister_chrdev_region(g_state->dev_num, 1);

    if (g_state->fast_filter)
        bloom_free(g_state->fast_filter);

    idr_destroy(&g_state->protected_idr);

    kfree(g_state);
    g_state = NULL;

    pr_info("memprtc: Module unloaded successfully\n");
}

module_init(memprtc_init);
module_exit(memprtc_exit);