#ifndef _MEMPRTC_H
#define _MEMPRTC_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define MEMPRTC_DEVICE_NAME "memprtc"
#define MEMPRTC_CLASS_NAME "memprtc"
#define MEMPRTC_VERSION "3.1.0"

/* ==================== CONSTANTS ==================== */

/* Maximum limits */
#define MEMPRTC_MAX_PROTECTED 1024
#define MEMPRTC_MAX_TRUSTED 64
#define MEMPRTC_LOG_SIZE 256
#define MEMPRTC_MAX_COMMENT 64
#define MEMPRTC_BLOOM_SIZE 8192

/* Protection flags */
#define PROTECT_FULL     0x0001
#define PROTECT_READ     0x0002
#define PROTECT_WRITE    0x0004
#define PROTECT_PTRACE   0x0008
#define PROTECT_PROC_MEM 0x0010
#define PROTECT_SIGNAL   0x0020
#define PROTECT_FORK     0x0040
#define PROTECT_DEBUG    0x0080
#define PROTECT_MMAP     0x0100
#define PROTECT_ALL      0xFFFF

/* Access types */
#define ACCESS_READ     0x01
#define ACCESS_WRITE    0x02
#define ACCESS_PTRACE   0x04
#define ACCESS_PROC_MEM 0x08 /* Für das Mapping unter dem Kernel I/O Stream in allen Regionen (Heap und Stack mit kmalloc)*/
#define ACCESS_SIGNAL   0x10
#define ACCESS_ALL      0xFF

/* Action on violation */
enum violation_action {
    ACTION_TERMINATE_PROTECTED = 0,
    ACTION_TERMINATE_ATTACKER,
    ACTION_BLOCK_ONLY,
    ACTION_LOG_ONLY,
    ACTION_TERMINATE_BOTH,
    ACTION_BLOCK_AND_LOG,
};

/* ==================== IOCTL COMMANDS ==================== */

#define MEMPRTC_MAGIC 0xDC
#define MEMPRTC_PROTECT_PID_NUM   1
#define MEMPRTC_UNPROTECT_PID_NUM 2
#define MEMPRTC_ADD_TRUSTED_NUM   3
#define MEMPRTC_REMOVE_TRUSTED_NUM 4
#define MEMPRTC_GET_STATUS_NUM    5
#define MEMPRTC_GET_STATS_NUM     6
#define MEMPRTC_SET_CONFIG_NUM    7
#define MEMPRTC_GET_CONFIG_NUM    8
#define MEMPRTC_GET_VIOLATIONS_NUM 9

/* For ioctl() system call */
#define MEMPRTC_PROTECT_PID _IOW(MEMPRTC_MAGIC, MEMPRTC_PROTECT_PID_NUM, struct protection_request)
#define MEMPRTC_UNPROTECT_PID _IOW(MEMPRTC_MAGIC, MEMPRTC_UNPROTECT_PID_NUM, pid_t)
#define MEMPRTC_ADD_TRUSTED _IOW(MEMPRTC_MAGIC, MEMPRTC_ADD_TRUSTED_NUM, struct trusted_relation)
#define MEMPRTC_REMOVE_TRUSTED _IOW(MEMPRTC_MAGIC, MEMPRTC_REMOVE_TRUSTED_NUM, struct trusted_relation)
#define MEMPRTC_GET_STATUS _IOR(MEMPRTC_MAGIC, MEMPRTC_GET_STATUS_NUM, struct memprtc_status)
#define MEMPRTC_GET_STATS _IOR(MEMPRTC_MAGIC, MEMPRTC_GET_STATS_NUM, struct memprtc_stats)
#define MEMPRTC_SET_CONFIG _IOW(MEMPRTC_MAGIC, MEMPRTC_SET_CONFIG_NUM, struct memprtc_config)
#define MEMPRTC_GET_CONFIG _IOR(MEMPRTC_MAGIC, MEMPRTC_GET_CONFIG_NUM, struct memprtc_config)
#define MEMPRTC_GET_VIOLATIONS _IOR(MEMPRTC_MAGIC, MEMPRTC_GET_VIOLATIONS_NUM, struct violation_query)

/* For case labels - guaranteed integer constants */
#define MEMPRTC_PROTECT_PID_CASE      ((MEMPRTC_MAGIC << 8) | MEMPRTC_PROTECT_PID_NUM)
#define MEMPRTC_UNPROTECT_PID_CASE    ((MEMPRTC_MAGIC << 8) | MEMPRTC_UNPROTECT_PID_NUM)
#define MEMPRTC_ADD_TRUSTED_CASE      ((MEMPRTC_MAGIC << 8) | MEMPRTC_ADD_TRUSTED_NUM)
#define MEMPRTC_REMOVE_TRUSTED_CASE   ((MEMPRTC_MAGIC << 8) | MEMPRTC_REMOVE_TRUSTED_NUM)
#define MEMPRTC_GET_STATUS_CASE       ((MEMPRTC_MAGIC << 8) | MEMPRTC_GET_STATUS_NUM)
#define MEMPRTC_GET_STATS_CASE        ((MEMPRTC_MAGIC << 8) | MEMPRTC_GET_STATS_NUM)
#define MEMPRTC_SET_CONFIG_CASE       ((MEMPRTC_MAGIC << 8) | MEMPRTC_SET_CONFIG_NUM)
#define MEMPRTC_GET_CONFIG_CASE       ((MEMPRTC_MAGIC << 8) | MEMPRTC_GET_CONFIG_NUM)
#define MEMPRTC_GET_VIOLATIONS_CASE   ((MEMPRTC_MAGIC << 8) | MEMPRTC_GET_VIOLATIONS_NUM)

/* ==================== STRUCTURES ==================== */

struct protection_request {
    pid_t pid;
    unsigned long flags;
    enum violation_action action;
    char comment[MEMPRTC_MAX_COMMENT];
};

struct trusted_relation {
    pid_t protected_pid;
    pid_t trusted_pid;
    unsigned long allowed_ops;
};

struct memprtc_config {
    bool trust_root;
    bool trust_same_user;
    bool audit_violations;
    unsigned int log_level;
    unsigned long violation_timeout;
    bool panic_on_critical;
    unsigned int max_protected;
};

struct memprtc_status {
    pid_t protected_pids[MEMPRTC_MAX_PROTECTED];
    unsigned long protection_flags[MEMPRTC_MAX_PROTECTED];
    int count;
    unsigned long uptime_jiffies;
    unsigned long total_violations;
    unsigned long total_blocks;
};

struct memprtc_stats {
    unsigned long violations_detected;
    unsigned long processes_terminated;
    unsigned long attackers_terminated;
    unsigned long accesses_blocked;
    unsigned long last_violation_jiffies;
    pid_t last_attacking_pid;
    pid_t last_protected_pid;
    unsigned long last_access_address;
    char last_attacker_comm[TASK_COMM_LEN];
    char last_protected_comm[TASK_COMM_LEN];
    enum violation_action last_action_taken;
};

struct violation_record {
    u64 timestamp_ns;
    pid_t protected_pid;
    pid_t attacker_pid;
    unsigned long access_addr;
    int access_type;
    enum violation_action action_taken;
    char attacker_comm[TASK_COMM_LEN];
    char protected_comm[TASK_COMM_LEN];
    char access_detail[32];
};

struct violation_query {
    u32 start_index;
    u32 count;
    struct violation_record records[MEMPRTC_LOG_SIZE];
};

#endif /* _MEMPRTC_H */