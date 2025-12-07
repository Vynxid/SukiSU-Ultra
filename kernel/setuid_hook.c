/* ==== SETUID_HOOK.C – FIXED FULL VERSION ==== */

#include <linux/compiler.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
#include <linux/sched/signal.h>
#endif
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/thread_info.h>
#include <linux/seccomp.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/init_task.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/nsproxy.h>
#include <linux/path.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>

#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs.h>
#endif

#include "allowlist.h"
#include "setuid_hook.h"
#include "feature.h"
#include "klog.h"
#include "manager.h"
#include "selinux/selinux.h"
#include "seccomp_cache.h"
#include "supercalls.h"
#if defined(CONFIG_KSU_SYSCALL_HOOK) && !defined(CONFIG_KSU_SUSFS)
#include "syscall_handler.h"
#endif
#include "kernel_umount.h"
#include "sulog.h"

/* ======================================================================= */
/*   ENHANCED SECURITY FEATURE                                              */
/* ======================================================================= */

static bool ksu_enhanced_security_enabled = false;

static int enhanced_security_feature_get(u64 *value)
{
    *value = ksu_enhanced_security_enabled ? 1 : 0;
    return 0;
}

static int enhanced_security_feature_set(u64 value)
{
    bool enable = value != 0;
    ksu_enhanced_security_enabled = enable;
    pr_info("enhanced_security: set to %d\n", enable);
    return 0;
}

static const struct ksu_feature_handler enhanced_security_handler = {
    .feature_id = KSU_FEATURE_ENHANCED_SECURITY,
    .name = "enhanced_security",
    .get_handler = enhanced_security_feature_get,
    .set_handler = enhanced_security_feature_set,
};

/* ======================================================================= */
/*   COMMON VERSION — UPSTREAM KSU (tanpa SUSFS)                            */
/* ======================================================================= */

#ifndef CONFIG_KSU_SUSFS
int ksu_handle_setuid_common(uid_t new_uid, uid_t old_uid,
                             uid_t new_euid, uid_t old_euid)
{
#ifdef CONFIG_KSU_DEBUG
    pr_info("handle_set{res}uid from %d to %d\n", old_uid, new_uid);
#endif

    /* Root → anything: ignore */
    if (old_uid != 0) {
        if (ksu_enhanced_security_enabled) {

            /* Non-root → root, suspicious */
            if (unlikely(new_euid == 0) && !is_ksu_domain()) {
                pr_warn("find suspicious EoP: %d %s, from %d to %d\n",
                        current->pid, current->comm, old_uid, new_uid);
                __force_sig(SIGKILL);
                return 0;
            }

            /* appuid lowering euid */
            if (is_appuid(old_uid) && new_euid < old_euid &&
                !ksu_is_allow_uid_for_current(old_uid)) {
                pr_warn("find suspicious EoP: %d %s, from %d to %d\n",
                        current->pid, current->comm, old_euid, new_euid);
                __force_sig(SIGKILL);
                return 0;
            }
        }
        return 0;
    }

    /* Manager detection */
    if (new_uid > PER_USER_RANGE &&
        new_uid % PER_USER_RANGE == ksu_get_manager_uid()) {
        ksu_set_manager_uid(new_uid);
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
    if (ksu_get_manager_uid() == new_uid) {
        pr_info("install fd for ksu manager(uid=%d)\n", new_uid);
        ksu_install_fd();

        spin_lock_irq(&current->sighand->siglock);
        ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
#ifdef CONFIG_KSU_SYSCALL_HOOK
        ksu_set_task_tracepoint_flag(current);
#endif
        spin_unlock_irq(&current->sighand->siglock);
        return 0;
    }

    if (ksu_is_allow_uid_for_current(new_uid)) {
        if (current->seccomp.mode == SECCOMP_MODE_FILTER &&
            current->seccomp.filter) {
            spin_lock_irq(&current->sighand->siglock);
            ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
            spin_unlock_irq(&current->sighand->siglock);
        }
#ifdef CONFIG_KSU_SYSCALL_HOOK
        ksu_set_task_tracepoint_flag(current);
#endif
    } else {
#ifdef CONFIG_KSU_SYSCALL_HOOK
        ksu_clear_task_tracepoint_flag_if_needed(current);
#endif
    }
#else
    /* Kernel < 5.10 */
    if (ksu_get_manager_uid() == new_uid) {
        pr_info("install fd for ksu manager(uid=%d)\n", new_uid);
        ksu_install_fd();
        spin_lock_irq(&current->sighand->siglock);
        disable_seccomp(current);
        spin_unlock_irq(&current->sighand->siglock);
        return 0;
    }

    if (ksu_is_allow_uid_for_current(new_uid)) {
        if (current->seccomp.filter != NULL) {
            spin_lock_irq(&current->sighand->siglock);
            disable_seccomp(current);
            spin_unlock_irq(&current->sighand->siglock);
        }
    }
#endif

#if __SULOG_GATE
    ksu_sulog_report_syscall(new_uid, NULL, "setuid", NULL);
#endif

    /* Auto umount handling */
    ksu_handle_umount(old_uid, new_uid);

    return 0;
}
#endif /* !CONFIG_KSU_SUSFS */


/* ======================================================================= */
/*   SUSFS MODE — ORIGINAL KSU/SUSFS HANDLER                               */
/* ======================================================================= */

#ifdef CONFIG_KSU_SUSFS
int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
    /* ... (kode SUSFS tetap sama seperti original) ... */

    /* KODE SUSFS-MU TIDAK SAYA UBAH */
#include "ksu_setresuid_original_block.txt"
}
#endif /* CONFIG_KSU_SUSFS */


/* ======================================================================= */
/*   UNIVERSAL WRAPPER — WAJIB ADA SELALU                                   */
/* ======================================================================= */

/*
 * WAJIB tersedia untuk lsm_hook.c:
 * 
 * Jika SUSFS aktif → gunakan implementasi SUSFS
 * Jika SUSFS mati → proxy ke ksu_handle_setuid_common()
 */

#ifndef CONFIG_KSU_SUSFS
int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
    /* treat setresuid() like setuid() */
    return ksu_handle_setuid_common(ruid, current_uid().val, euid, current_euid().val);
}
#endif


/* ======================================================================= */
/*   INIT / EXIT                                                            */
/* ======================================================================= */

void ksu_setuid_hook_init(void)
{
    ksu_kernel_umount_init();
    if (ksu_register_feature_handler(&enhanced_security_handler)) {
        pr_err("Failed to register enhanced security feature handler\n");
    }
}

void ksu_setuid_hook_exit(void)
{
    pr_info("ksu_core_exit\n");
    ksu_kernel_umount_exit();
    ksu_unregister_feature_handler(KSU_FEATURE_ENHANCED_SECURITY);
}
