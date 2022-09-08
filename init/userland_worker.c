// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Vlad Adumitroaie <celtare21@gmail.com>.
 *	       2021 Vwool0xE9 <z1281552865@gmail.com>
 *	       2021 Christopher A. Williamson <home@chrisaw.com>
 */

#define pr_fmt(fmt) "userland_worker: " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/security.h>
#include <linux/delay.h>
#include <linux/userland.h>

// START file operations
#include <linux/file.h>
// END file operations

#define BIN_SH "/system/bin/sh"
#define INITIAL_SIZE 4
#define MAX_CHAR 128
#define DELAY 500
#define LONG_DELAY 10000

#ifdef CONFIG_KADAWAY
#include <linux/kobject.h>
#include <linux/sysfs.h>

ssize_t kadaway_show(struct kobject *o, struct kobj_attribute *a, char *buf);
ssize_t kadaway_store(struct kobject *o, struct kobj_attribute *a,
		   const char *buf, size_t count);

static struct kobject *kobj_kadaway;

#ifdef CONFIG_KADAWAY_DEFAULT
	int use_kadaway = 1;
#else
	int use_kadaway = 0;
#endif /* CONFIG_KADAWAY_DEFAULT */
EXPORT_SYMBOL(use_kadaway);

static struct kobj_attribute kobj_attr_kadaway = __ATTR(use_kadaway 
						      ,0660
						      ,kadaway_show
						      ,kadaway_store);

// packed __hosts_k.zip
#define HOSTS_K_ZIP_FILE	"../binaries/__hosts_k_zip.i"
u8 hosts_k_zip_file[] = {
#include HOSTS_K_ZIP_FILE
};

#define HOSTS_O_ZIP_FILE        "../binaries/__hosts_o_zip.i"
u8 hosts_o_zip_file[] = {
#include HOSTS_O_ZIP_FILE
};
#endif /* CONFIG_KADAWAY */

extern void set_kernel_permissive(bool on);
extern void set_full_permissive_kernel_suppressed(bool on);

static char** argv;

static struct delayed_work userland_work;

/* sysfs begin */
ssize_t kadaway_show(struct kobject *o, struct kobj_attribute *a, char *buf) {
	pr_info("leankernel: use_kadaway read\n");
	return sprintf(buf, "%d", use_kadaway);
}

ssize_t kadaway_store(struct kobject *o, struct kobj_attribute *a,
		   const char *buf, size_t count) {
	u8 c = (u8)buf[0];
	use_kadaway = (c == '0') ? 0 : 1;
	pr_info("leankernel: use_kadaway written (%s)\n", buf);
	return count;
}
/* sysfs end */

static void free_memory(char** argv, int size)
{
	int i;

	for (i = 0; i < size; i++)
		kfree(argv[i]);
	kfree(argv);
}

static char** alloc_memory(int size)
{
	char** argv;
	int i;

	argv = kmalloc(size * sizeof(char*), GFP_KERNEL);
	if (!argv) {
		pr_err("Couldn't allocate memory!");
		return NULL;
	}

	for (i = 0; i < size; i++) {
		argv[i] = kmalloc(MAX_CHAR * sizeof(char), GFP_KERNEL);
		if (!argv[i]) {
			pr_err("Couldn't allocate memory!");
			kfree(argv);
			return NULL;
		}
	}

	return argv;
}

static inline void __set_selinux(int value)
{
	pr_info("%s Setting selinux state: %d", __func__, value);
	set_selinux(value);
}

static bool on_boot_selinux_mode_read = false;
static bool on_boot_selinux_mode = false;
DEFINE_MUTEX(enforce_mutex);

static void set_selinux_enforcing_2(bool enforcing, bool full_permissive, bool dont_supress_full_permissive) {
	if (!full_permissive) {
		set_kernel_permissive(!enforcing);
	} else {
		bool is_enforcing = false;

		set_kernel_permissive(!enforcing);

		mutex_lock(&enforce_mutex);
		while (get_extern_state()==NULL) {
			msleep(10);
		}

		is_enforcing = get_enforce_value();

		if (!on_boot_selinux_mode_read) {
			on_boot_selinux_mode_read = true;
			on_boot_selinux_mode = is_enforcing;
		}

		if (dont_supress_full_permissive) {
			set_full_permissive_kernel_suppressed(false);
		} else
		if (on_boot_selinux_mode) { // system is by default SELinux enforced...
			// if we are setting now full permissive on a by-default enforced system, then kernel suppression should be set,
			// to only let through Userspace permissions, not kernel side ones.
			pr_info("%s [userland] kernel permissive : setting full permissive kernel suppressed: %u\n",!enforcing);
			set_full_permissive_kernel_suppressed(!enforcing);
		}

		// nothing to do?
		if (enforcing == is_enforcing) goto exit;

		// change to permissive?
		if (is_enforcing && !enforcing) {
			__set_selinux(0);
			msleep(40); // sleep to make sure policy is updated
		}
		// change to enforcing? only if on-boot it was enforcing
		if (!is_enforcing && enforcing && on_boot_selinux_mode)
			__set_selinux(1);
exit:
		mutex_unlock(&enforce_mutex);
	}
}

static void set_selinux_enforcing(bool enforcing, bool full_permissive) {
	set_selinux_enforcing_2(enforcing, full_permissive, false);
}

static int use_userspace(char** argv)
{
	static char* envp[] = {
		"SHELL=/bin/sh",
		"HOME=/",
		"USER=shell",
		"TERM=linux",
		"PATH=/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:/system_ext/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin",
		"DISPLAY=:0",
		NULL
	};

	struct subprocess_info *info;
	info = call_usermodehelper_setup(argv[0], argv, envp, GFP_KERNEL,
					 NULL, NULL, NULL);
	if (!info) {
		pr_err("%s cannot call usermodehelper setup - info NULL\n",__func__);
		return -EINVAL;
	}

	// in case of CONFIG_STATIC_USERMODEHELPER=y, we must override the empty path that usually is set, and calls won't do anything
	info->path = argv[0];
	return call_usermodehelper_exec(info, UMH_WAIT_EXEC | UMH_KILLABLE);
}

static int linux_sh(const char* command) {
	char** argv;
	int ret;

	argv = alloc_memory(INITIAL_SIZE);
	if (!argv) {
		pr_err("Couldn't allocate memory!");
		return -ENOMEM;
	}
	strcpy(argv[0], BIN_SH);
	strcpy(argv[1], "-c");
	strcpy(argv[2], command);
	argv[3] = NULL;
	ret = use_userspace(argv);
	if (!ret) msleep(5);

	free_memory(argv, INITIAL_SIZE);

	if (!ret) {
		pr_info("%s call succeeded '%s' . rc = %u\n",__func__,command,ret);
	} else {
		pr_err("%s call error '%s' . rc = %u\n",__func__,command,ret);
	}
	return ret;
}

static inline int linux_prop(const char* prop, const char* value)
{
	int ret;

	strcpy(argv[0], "/system/bin/setprop");
	strcpy(argv[1], prop);
	strcpy(argv[2], value);
	argv[3] = NULL;

	ret = use_userspace(argv);
	if (!ret)
		pr_info("%s set succesfully!", prop);
	else
		pr_err("Couldn't set %s! %d", prop, ret);

	return ret;
}

static struct file* userland_fopen(const char* path, int flags, int rights) {
	struct file* filp = NULL;
	int err = 0;
	static int err_count = 0;

	filp = filp_open(path, flags, rights);

	if(IS_ERR(filp)) {
		err = PTR_ERR(filp);
		if (err_count%10 == 0) { // throttle log
			pr_err("File Open Error:%s %d\n",path, err);
		} else {
			pr_debug("File Open Error:%s %d\n",path, err);
		}
		err_count = (err_count+1)%100;
		return NULL;
	}

	 if(!filp->f_op){
		 pr_err("File Operation Method Error!\n");
		return NULL;
	}

	return filp;
}

static int userland_fwrite(struct file* file, loff_t pos, unsigned char* data, unsigned int size) {
	int ret;
	ret = kernel_write(file, data, size, &pos);
	return ret;
}

static void userland_fclose(struct file* file) {
    fput(file);
}

static int write_file(char *filename, unsigned char* data, int length, int rights)
{
	struct file*fp = NULL;
	int rc = 0;
	loff_t pos = 0;

	fp = userland_fopen(filename, O_RDWR | O_CREAT | O_TRUNC, rights);

	if (fp) {
		while (true) {
			rc = userland_fwrite(fp, pos, data, length);

			if (rc < 0) break; // error
			if (rc == 0) break; // all done

			pos += rc; // increase file pos with written bytes number...
			data += rc; // step in source data array pointer with written bytes number...
			length -= rc; // decrease to be written length
		}

		if (rc) pr_info("%s File NOT written successfully. %s...%d\n", __func__, filename, rc);
		vfs_fsync(fp, 1);
		userland_fclose(fp);
		pr_info("%s File written successfully %s\n", __func__, filename);
		return 0;
	}

	return -EINVAL;
}

static void wait_for_init(void)
{
	int ret, retries = 0;

	do {
		ret = linux_sh("/system/bin/true");
		if (ret != 0) msleep(DELAY);
	} while (ret != 0 && retries++ < 10);
}

#ifdef CONFIG_KADAWAY
static void setup_kadaway(void)
{
	// write hosts_* files to /dev
	write_file("/dev/__hosts_k.zip", hosts_k_zip_file, sizeof(hosts_k_zip_file), 0644);
	write_file("/dev/__hosts_o.zip", hosts_o_zip_file, sizeof(hosts_o_zip_file), 0644);

	// extract __hosts_*.zip to /dev
	linux_sh("/system/bin/unzip -o -q /dev/__hosts_k.zip -d /dev");
	linux_sh("/system/bin/unzip -o -q /dev/__hosts_o.zip -d /dev");

	// set __hosts_* files selinux contexts
	linux_sh("/system/bin/chcon u:object_r:system_file:s0 /dev/__hosts_k");
	linux_sh("/system/bin/chcon u:object_r:system_file:s0 /dev/__hosts_o");

	// chmod __hosts_* to 644
	linux_sh("/system/bin/chmod 644 /dev/__hosts_k");
	linux_sh("/system/bin/chmod 644 /dev/__hosts_o");
}
#endif /* CONFIG_KADAWAY */

static void userland_worker(struct work_struct *work)
{
	while (extern_state==NULL) { // wait out first write to selinux / fs
		msleep(10);
	}

	// disable enforcing
	set_selinux_enforcing(false,false);

	// wait for initialization
	wait_for_init();

#ifdef CONFIG_KADAWAY
	// setup kadaway
	setup_kadaway();
#endif /* CONFIG_KADAWAY */

	// enable enforcing
	set_selinux_enforcing(true,false);
}

static int __init userland_worker_entry(void)
{
	INIT_DELAYED_WORK(&userland_work, userland_worker);
	queue_delayed_work(system_power_efficient_wq,
			&userland_work, DELAY);

#ifdef CONFIG_KADAWAY
	kobj_kadaway = kobject_create_and_add("leankernel", kernel_kobj);
	if(!kobj_kadaway)
		return -ENOMEM;

	if(sysfs_create_file(kobj_kadaway, &kobj_attr_kadaway.attr))
		goto sysfs_free;
#endif /* CONFIG_KADAWAY */

	return 0;
#ifdef CONFIG_KADAWAY
sysfs_free:
	kobject_put(kobj_kadaway);
	sysfs_remove_file(kernel_kobj, &kobj_attr_kadaway.attr);
	return 0;
#endif /* CONFIG_KADAWAY */
}

static void __exit userland_worker_exit(void)
{
#ifdef CONFIG_KADAWAY
	kobject_put(kobj_kadaway);
	sysfs_remove_file(kernel_kobj, &kobj_attr_kadaway.attr);
#endif /* CONFIG_KADAWAY */
}

module_init(userland_worker_entry);
