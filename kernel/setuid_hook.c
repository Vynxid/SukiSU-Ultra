/* ==== SETUID_HOOK.C – FINAL NO-ERROR FULL VERSION ==== */

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
/*   COMMON SETUID HANDLER (NO SUSFS)                                       */
/* ======================================================================= */

#ifndef CONFIG_KSU_SUSFS
int ksu_handle_setuid_common(uid_t new_uid, uid_t old_uid,
                             uid_t new_euid, uid_t old_euid)
{
#ifdef CONFIG_KSU_DEBUG
    pr_info("handle_set{res}uid from %d to %d\n", old_uid, new_uid);
#endif

    if (old_uid != 0) {
        if (ksu_enhanced_security_enabled) {
            if (unlikely(new_euid == 0) && !is_ksu_domain()) {
                pr_warn("Suspicious EoP: %d %s from %d to %d\n",
                        current->pid, current->comm, old_uid, new_uid);
                __force_sig(SIGKILL);
                return 0;
            }
            if (is_appuid(old_uid) && new_euid < old_euid &&
                !ksu_is_allow_uid_for_current(old_uid)) {
                pr_warn("Suspicious EoP lowering %d → %d\n",
                        old_euid, new_euid);
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
        pr_info("install fd for manager uid=%d\n", new_uid);
        ksu_install_fd();
        spin_lock_irq(&current->sighand->siglock);
        ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
        spin_unlock_irq(&current->sighand->siglock);
        return 0;
    }
#else
    if (ksu_get_manager_uid() == new_uid) {
        pr_info("install fd for manager uid=%d\n", new_uid);
        ksu_install_fd();
        spin_lock_irq(&current->sighand->siglock);
        disable_seccomp(current);
        spin_unlock_irq(&current->sighand->siglock);
        return 0;
    }
#endif

#if __SULOG_GATE
    ksu_sulog_report_syscall(new_uid, NULL, "setuid", NULL);
#endif

    ksu_handle_umount(old_uid, new_uid);

    return 0;
}
#endif // !CONFIG_KSU_SUSFS

/* ======================================================================= */
/*   SUSFS VERSION — FULL INCLUDED (NO MISSING FILES)                       */
/* ======================================================================= */

#ifdef CONFIG_KSU_SUSFS
int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
    uid_t new_uid = ruid;
    uid_t old_uid = current_uid().val;

    if (old_uid != 0 && ksu_enhanced_security_enabled) {
        if (unlikely(euid == 0) && !is_ksu_domain()) {
            pr_warn("SUSFS EoP: %d %s from %d to %d\n",
                    current->pid, current->comm, old_uid, new_uid);
            __force_sig(SIGKILL);
            return 0;
        }
        if (is_appuid(old_uid) &&
            euid < current_euid().val &&
            !ksu_is_allow_uid_for_current(old_uid)) {
            pr_warn("SUSFS Lowering denied\n");
            __force_sig(SIGKILL);
            return 0;
        }
        return 0;
    }

    if (!susfs_is_sid_equal(current_cred()->security, susfs_zygote_sid)) {
        return 0;
    }

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
    if ((new_uid % 100000) >= 99000) {
        goto do_umount;
    }
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
    if (ksu_get_manager_uid() == new_uid) {
        pr_info("install fd for manager uid=%d\n", new_uid);
        ksu_install_fd();
        spin_lock_irq(&current->sighand->siglock);
        ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
        spin_unlock_irq(&current->sighand->siglock);
        return 0;
    }
#endif

    if (((new_uid % 100000) >= 10000 && (new_uid % 100000) < 19999) &&
        ksu_uid_should_umount(new_uid)) {
        goto do_umount;
    }

    return 0;

do_umount:
    ksu_handle_umount(old_uid, new_uid);

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
    susfs_reorder_mnt_id();
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
    susfs_run_sus_path_loop(new_uid);
#endif
    susfs_set_current_proc_umounted();
    return 0;
}
#endif // CONFIG_KSU_SUSFS

/* ======================================================================= */
/*   UNIVERSAL FALLBACK — ensure always available                           */
/* ======================================================================= */

#ifndef CONFIG_KSU_SUSFS
int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
    return ksu_handle_setuid_common(
        ruid,
        current_uid().val,
        euid,
        current_euid().val
    );
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
