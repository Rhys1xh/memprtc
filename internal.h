#ifndef _MEMPRTC_INTERNAL_H
#define _MEMPRTC_INTERNAL_H

#include <linux/spinlock.h>
#include <linux/rculist.h>
#include <linux/pid.h>
#include <linux/atomic.h>
#include <linux/kref.h>
#include <linux/seqlock.h>
#include <linux/idr.h>
#include "memprtc.h"

/* Simple Bloom filter structure */
struct simple_bloom {
    unsigned long *bits;
    unsigned int size;      /* in bits */
    unsigned int hash_count;
    spinlock_t lock;
};

/* Trusted process entry */
struct trusted_entry {
    struct list_head list;
    pid_t trusted_pid;
    unsigned long allowed_ops;
    struct rcu_head rcu;
};

/* Protected process entry with refcounting and seqlock */
struct protected_entry {
    struct kref refcount;
    struct rcu_head rcu;
    seqlock_t seqlock;      /* <- Atomische Umwandlung von Integern (Wenn der nicht läuft crashed mein Laptop, vor dem Laden checken ob ich den Entry im Module Entry initialisiert hab!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!) */
    
    /* Core data */
    pid_t pid;
    struct pid *pid_struct;
    struct task_struct *task;
    unsigned long protected_since;
    
    /* Protection configuration */
    unsigned long flags;
    enum violation_action action;
    char comment[MEMPRTC_MAX_COMMENT];
    
    /* Trusted processes list - RCU protected */
    struct list_head trusted_list;
    spinlock_t trusted_lock;
    int trusted_count;
    
    /* State */
    bool active;
    atomic_t violation_count;
};

/* Circular log buffer */
struct violation_log {
    struct violation_record entries[MEMPRTC_LOG_SIZE];
    atomic_t head;
    atomic_t tail;
    spinlock_t lock;
};

/* Module state */
struct memprtc_state {
    /* Fast lookup structures */
    struct idr protected_idr;
    spinlock_t idr_lock;
    struct simple_bloom *fast_filter;  /* Custom bloom filter */
    
    /* Global configuration */
    struct memprtc_config config;
    spinlock_t config_lock;
    
    /* Statistics */
    struct memprtc_stats stats;
    spinlock_t stats_lock;
    
    /* Violation log */
    struct violation_log log;
    
    /* Kprobes array */
    struct kprobe *kprobes;
    int kprobe_count;
    
    /* Device state */
    dev_t dev_num;
    struct class *class;
    struct device *device;
    struct cdev cdev;
    
    /* Module status */
    atomic_t active_protections;
    unsigned long module_start_jiffies;
    
    /* Debugfs */
    struct dentry *debugfs_dir;
};

/* Global state declaration - defined in memprtc.c */
extern struct memprtc_state *g_state;

#endif /* _MEMPRTC_INTERNAL_H */