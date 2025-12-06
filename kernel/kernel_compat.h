#ifndef __KSU_H_KERNEL_COMPAT
#define __KSU_H_KERNEL_COMPAT

#include <linux/fs.h>
#include <linux/version.h>
#include <linux/task_work.h>
#include <linux/key.h>
#include "ss/policydb.h"

/*
 * Adapt to Huawei HISI kernel without affecting other kernels.
 * Huawei Hisi kernel EBITMAP enable or disable flag,
 * from ss/ebitmap.h.
 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0) && \
     LINUX_VERSION_CODE <  KERNEL_VERSION(4, 10, 0)) || \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0) && \
     LINUX_VERSION_CODE <  KERNEL_VERSION(4, 15, 0))
#ifdef HISI_SELINUX_EBITMAP_RO
#define CONFIG_IS_HW_HISI
#endif
#endif

/*
 * Sanity check for Samsung UH / KDP / RKP.
 * KernelSU tidak bisa jalan berdampingan dengan UH/KDP/RKP.
 */
#ifdef SAMSUNG_UH_DRIVER_EXIST
# if defined(CONFIG_UH) || defined(CONFIG_KDP) || defined(CONFIG_RKP)
#  error "CONFIG_UH, CONFIG_KDP or CONFIG_RKP is enabled! Disable/remove them before compiling a kernel with KernelSU."
# endif
#endif

/*
 * Compat helpers that are implemented in kernel_compat.c
 */

/* Safe strncpy_from_user_nofault wrapper used by SuSFS & KernelSU */
extern long ksu_strncpy_from_user_nofault(char *dst,
					  const void __user *unsafe_addr,
					  long count);

/* File I/O helpers that work across kernel versions */
extern struct file *ksu_filp_open_compat(const char *filename, int flags,
					 umode_t mode);
extern ssize_t ksu_kernel_read_compat(struct file *p, void *buf, size_t count,
				      loff_t *pos);
extern ssize_t ksu_kernel_write_compat(struct file *p, const void *buf,
				       size_t count, loff_t *pos);

/* Some older / vendor trees still expose init_session_keyring symbol */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) || \
    defined(CONFIG_IS_HW_HISI) || defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
extern struct key *init_session_keyring;
#endif

/* do_close_fd() is not exported uniformly on all versions */
extern int do_close_fd(unsigned int fd);

/*
 * access_ok() signature changed in upstream.
 *  - new: access_ok(addr, size)
 *  - old: access_ok(type, addr, size)
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
#define ksu_access_ok(addr, size) access_ok(addr, size)
#else
#define ksu_access_ok(addr, size) access_ok(VERIFY_READ, addr, size)
#endif

/*
 * Linux >= 5.7:
 *   task_work_add(struct task_struct *, struct callback_head *, enum task_work_notify_mode)
 * Linux < 5.7:
 *   task_work_add(struct task_struct *, struct callback_head *, bool)
 *
 * Define TWA_RESUME for old kernels so callers can use a single name.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
#ifndef TWA_RESUME
#define TWA_RESUME true
#endif
#endif

/*
 * SELinux compat:
 *
 * Beberapa tree 4.14 (termasuk vayu) tidak menyediakan selinux_inode()
 * dan/atau struct inode_security_struct yang cocok. Untuk mencegah error
 * compile di drivers/kernelsu/sucompat.c, kita buat flag ini:
 *
 *  - 0: kode yang memakai selinux_inode() akan di-ifdef-out
 *  - 1: aktifkan jika tree SELinux kamu punya API tersebut dan ingin
 *       memakai integrasi penuh (perlu penyesuaian manual).
 *
 * Di sucompat.c gunakan:
 *   #if KSU_SELINUX_INODE_COMPAT
 *      ... selinux_inode() ...
 *   #endif
 */
#define KSU_SELINUX_INODE_COMPAT 0

#endif /* __KSU_H_KERNEL_COMPAT */
