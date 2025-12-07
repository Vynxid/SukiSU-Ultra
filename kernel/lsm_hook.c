// SPDX-License-Identifier: GPL-2.0
#include <linux/lsm_hooks.h>
#include <linux/uidgid.h>
#include <linux/version.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/string.h>

#include "klog.h"          // IWYU pragma: keep
#include "kernel_compat.h"
#include "ksud.h"
#include "setuid_hook.h"
#include "throne_tracker.h"

/*
 * Optional manual su escalation via task_alloc() hook.
 * LSM hook task_alloc hanya tersedia pada kernel yang lebih baru.
 * Untuk kernel 4.14, hook ini TIDAK dipakai.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0) && defined(CONFIG_KSU_MANUAL_SU)
#include "manual_su.h"

static int ksu_task_alloc(struct task_struct *task,
			  unsigned long clone_flags)
{
	ksu_try_escalate_for_uid(task_uid(task).val);
	return 0;
}
#endif /* >= 5.9 && CONFIG_KSU_MANUAL_SU */

/*
 * key_permission hook untuk mengambil init_session_keyring pada
 * beberapa vendor kernel (hisi / allowlist workaround).
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) || \
    defined(CONFIG_IS_HW_HISI) || defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
static int ksu_key_permission(key_ref_t key_ref, const struct cred *cred,
			      unsigned int perm)
{
	if (init_session_keyring != NULL)
		return 0;

	if (strcmp(current->comm, "init")) {
		/* only interested in init process */
		return 0;
	}

	init_session_keyring = cred->session_keyring;
	pr_info("kernel_compat: got init_session_keyring\n");

	return 0;
}
#endif

/*
 * Track /data/system/packages.list rename untuk throne tracker.
 */
static int ksu_inode_rename(struct inode *old_inode,
			    struct dentry *old_dentry,
			    struct inode *new_inode,
			    struct dentry *new_dentry)
{
	char path[128];
	char *buf;
	static bool do_once;

	/* skip kernel threads */
	if (!current->mm)
		return 0;

	/* hanya system uid */
	if (current_uid().val != 1000)
		return 0;

	if (!old_dentry || !new_dentry)
		return 0;

	/* /data/system/packages.list.tmp -> /data/system/packages.list */
	if (strcmp(new_dentry->d_iname, "packages.list"))
		return 0;

	buf = dentry_path_raw(new_dentry, path, sizeof(path));
	if (IS_ERR(buf)) {
		pr_err("dentry_path_raw failed.\n");
		return 0;
	}

	if (!strstr(buf, "/system/packages.list"))
		return 0;

	pr_info("renameat: %s -> %s, new path: %s\n",
		old_dentry->d_iname, new_dentry->d_iname, buf);

	/*
	 * RKSU: track_throne(true) only occurs when on_boot_completed.
	 * Make it once-lock.
	 */
	if (ksu_boot_completed && !do_once) {
		do_once = true;
		track_throne(true);
		return 0;
	}

	track_throne(false);

	return 0;
}

/*
 * Fix setuid/setresuid calls untuk menjaga state KernelSU.
 */
static int ksu_task_fix_setuid(struct cred *new, const struct cred *old,
			       int flags)
{
	kuid_t old_uid, old_euid, new_uid, new_euid;

	if (!new || !old)
		return 0;

	old_uid  = old->uid;
	old_euid = old->euid;
	new_uid  = new->uid;
	new_euid = new->euid;

	return ksu_handle_setuid_common(new_uid.val, old_uid.val,
					new_euid.val, old_euid.val);
}

/*
 * Daftar LSM hook KernelSU.
 * Untuk kernel 4.14, kita TIDAK memakai task_alloc hook.
 */
static struct security_hook_list ksu_hooks[] = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) || \
    defined(CONFIG_IS_HW_HISI) || defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
	LSM_HOOK_INIT(key_permission, ksu_key_permission),
#endif
	LSM_HOOK_INIT(inode_rename,   ksu_inode_rename),
	LSM_HOOK_INIT(task_fix_setuid, ksu_task_fix_setuid),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0) && defined(CONFIG_KSU_MANUAL_SU)
	/* Hanya untuk kernel baru yang punya task_alloc LSM hook */
	LSM_HOOK_INIT(task_alloc,     ksu_task_alloc),
#endif
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
static const struct lsm_id ksu_lsmid = {
	.name = "ksu",
	.id   = 912,
};
#endif

void __init ksu_lsm_hook_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), &ksu_lsmid);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), "ksu");
#else
	/*
	 * LSM API lama (<= 4.10), tidak punya argumen nama/lsm_id.
	 * Lihat: include/linux/lsm_hooks.h di 4.10.
	 */
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks));
#endif
	pr_info("KSU: LSM hooks initialized.\n");
}
