/*
 * fs/sdcardfs/packagelist.c
 *
 * Copyright (c) 2013 Samsung Electronics Co. Ltd
 *   Authors: Daeho Jeong, Woojoong Lee, Seunghwan Hyun,
 *               Sunghwan Yun, Sungjong Seo
 *
 * This program has been developed as a stackable file system based on
 * the WrapFS which written by
 *
 * Copyright (c) 1998-2011 Erez Zadok
 * Copyright (c) 2009     Shrikar Archak
 * Copyright (c) 2003-2011 Stony Brook University
 * Copyright (c) 2003-2011 The Research Foundation of SUNY
 *
 * This file is dual licensed.  It may be redistributed and/or modified
 * under the terms of the Apache 2.0 License OR version 2 of the GNU
 * General Public License.
 */

#include "sdcardfs.h"
#include <linux/hashtable.h>
#include <linux/ctype.h>
#include <linux/delay.h>


#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>

#include <linux/configfs.h>

#define STRING_BUF_SIZE		(512)

struct hashtable_entry {
	struct hlist_node hlist;
	void *key;
	unsigned int value;
};

struct sb_list {
	struct super_block *sb;
	struct list_head list;
};

struct packagelist_data {
	DECLARE_HASHTABLE(package_to_appid,8);
	spinlock_t hashtable_lock;

};

static struct packagelist_data *pkgl_data_all;
static unsigned int full_name_case_hash(const unsigned char *name, unsigned int len)
{
	unsigned long hash = init_name_hash();

	while (len--)
		hash = partial_name_hash(tolower(*name++), hash);
	return end_name_hash(hash);
}

static inline void qstr_init(struct qstr *q, const char *name)
{
	q->name = name;
	q->len = strlen(q->name);
	q->hash = full_name_case_hash(q->name, q->len);
}

static inline int qstr_copy(const struct qstr *src, struct qstr *dest)
{
	dest->name = kstrdup(src->name, GFP_KERNEL);
	dest->hash_len = src->hash_len;
	return !!dest->name;
}

static struct kmem_cache *hashtable_entry_cachep;

static unsigned int str_hash(const char *key) {
	int i;
	unsigned int h = strlen(key);
	char *data = (char *)key;

	for (i = 0; i < strlen(key); i++) {
		h = h * 31 + *data;
		data++;
	}
	return h;
}

appid_t get_appid(void *pkgl_id, const char *app_name)
{
	struct qstr q;

	qstr_init(&q, key);
	return __get_appid(&q);
}

static appid_t __get_ext_gid(const struct qstr *key)
{
	struct packagelist_data *pkgl_dat = pkgl_data_all;
	struct hashtable_entry *hash_cur;
	unsigned int hash = str_hash(app_name);
	appid_t ret_id;

	spin_lock(&pkgl_dat->hashtable_lock);
	hash_for_each_possible(pkgl_dat->package_to_appid, hash_cur, hlist, hash) {
		if (!strcasecmp(app_name, hash_cur->key)) {
			ret_id = (appid_t)hash_cur->value;
			spin_unlock(&pkgl_dat->hashtable_lock);
			return ret_id;
		}
	}
	spin_unlock(&pkgl_dat->hashtable_lock);
	return 0;
}

/* Kernel has already enforced everything we returned through
 * derive_permissions_locked(), so this is used to lock down access
 * even further, such as enforcing that apps hold sdcard_rw. */
int check_caller_access_to_name(struct inode *parent_node, const char* name) {

	/* Always block security-sensitive files at root */
	if (parent_node && SDCARDFS_I(parent_node)->perm == PERM_ROOT) {
		if (!strcasecmp(name, "autorun.inf")
			|| !strcasecmp(name, ".android_secure")
			|| !strcasecmp(name, "android_secure")) {
			return 0;
		}
	}

	/* Root always has access; access for any other UIDs should always
	 * be controlled through packages.list.
	 */
	if (current_fsuid() == 0)
		return 1;

	/* No extra permissions to enforce */
	return 1;
}

/* This function is used when file opening. The open flags must be
 * checked before calling check_caller_access_to_name()
 */
int open_flags_to_access_mode(int open_flags)
{
	if ((open_flags & O_ACCMODE) == O_RDONLY)
		return 0; /* R_OK */
	if ((open_flags & O_ACCMODE) == O_WRONLY)
		return 1; /* W_OK */
	/* Probably O_RDRW, but treat as default to be safe */
		return 1; /* R_OK | W_OK */
}

static int insert_str_to_int_lock(struct packagelist_data *pkgl_dat, char *key,
		unsigned int value)
{
	struct hashtable_entry *hash_cur;
	struct hashtable_entry *new_entry;
	unsigned int hash = str_hash(key);

	hash_for_each_possible(pkgl_dat->package_to_appid, hash_cur, hlist, hash) {
		if (!strcasecmp(key, hash_cur->key)) {
			hash_cur->value = value;
			return 0;
		}
	}
	new_entry = kmem_cache_alloc(hashtable_entry_cachep, GFP_ATOMIC);
	if (!new_entry)
		return -ENOMEM;
	new_entry->key = kstrdup(key, GFP_ATOMIC);
	new_entry->value = value;
	hash_add(pkgl_dat->package_to_appid, &new_entry->hlist, hash);
	return 0;
}

static void fixup_perms(struct super_block *sb, const char *key) {
	if (sb && sb->s_magic == SDCARDFS_SUPER_MAGIC) {
		fixup_perms_recursive(sb->s_root, key, strlen(key));
static int insert_userid_exclude_entry_locked(const struct qstr *key, userid_t value)
{
	struct hashtable_entry *hash_cur;
	struct hashtable_entry *new_entry;
	unsigned int hash = key->hash;

	/* Only insert if not already present */
	hash_for_each_possible_rcu(package_to_userid, hash_cur, hlist, hash) {
		if (atomic_read(&hash_cur->value) == value &&
				qstr_case_eq(key, &hash_cur->key))
			return 0;
	}
	new_entry = alloc_hashtable_entry(key, value);
	if (!new_entry)
		return -ENOMEM;
	hash_add_rcu(package_to_userid, &new_entry->hlist, hash);
	return 0;
}

static void fixup_all_perms_name(const struct qstr *key)
{
	struct sdcardfs_sb_info *sbinfo;
	struct limit_search limit = {
		.flags = BY_NAME,
		.name = QSTR_INIT(key->name, key->len),
	};
	list_for_each_entry(sbinfo, &sdcardfs_super_list, list) {
		if (sbinfo_has_sdcard_magic(sbinfo))
			fixup_perms_recursive(sbinfo->sb->s_root, &limit);
	}
}

static int insert_str_to_int(struct packagelist_data *pkgl_dat, char *key,
		unsigned int value) {
	int ret;
	struct sdcardfs_sb_info *sbinfo;
	mutex_lock(&sdcardfs_super_list_lock);
	spin_lock(&pkgl_dat->hashtable_lock);
	ret = insert_str_to_int_lock(pkgl_dat, key, value);
	spin_unlock(&pkgl_dat->hashtable_lock);
	struct limit_search limit = {
		.flags = BY_NAME | BY_USERID,
		.name = QSTR_INIT(key->name, key->len),
		.userid = userid,
	};
	list_for_each_entry(sbinfo, &sdcardfs_super_list, list) {
		if (sbinfo_has_sdcard_magic(sbinfo))
			fixup_perms_recursive(sbinfo->sb->s_root, &limit);
	}
}

	list_for_each_entry(sbinfo, &sdcardfs_super_list, list) {
		if (sbinfo) {
			fixup_perms(sbinfo->sb, key);
		}
	}
	mutex_unlock(&sdcardfs_super_list_lock);
	return ret;
}

static void remove_str_to_int_lock(struct hashtable_entry *h_entry) {
	kfree(h_entry->key);
	hash_del(&h_entry->hlist);
	kmem_cache_free(hashtable_entry_cachep, h_entry);
}

static void remove_str_to_int(struct packagelist_data *pkgl_dat, const char *key)
{
	struct sdcardfs_sb_info *sbinfo;
	struct hashtable_entry *hash_cur;
	unsigned int hash = str_hash(key);
	mutex_lock(&sdcardfs_super_list_lock);
	spin_lock(&pkgl_data_all->hashtable_lock);
	hash_for_each_possible(pkgl_dat->package_to_appid, hash_cur, hlist, hash) {
		if (!strcasecmp(key, hash_cur->key)) {
			remove_str_to_int_lock(hash_cur);
			break;
		}
	}
	spin_unlock(&pkgl_data_all->hashtable_lock);
	list_for_each_entry(sbinfo, &sdcardfs_super_list, list) {
		if (sbinfo) {
			fixup_perms(sbinfo->sb, key);
	synchronize_rcu();
	hlist_for_each_entry_safe(hash_cur, h_t, &free_list, dlist)
		free_hashtable_entry(hash_cur);
}

static void remove_packagelist_entry(const struct qstr *key)
{
	mutex_lock(&sdcardfs_super_list_lock);
	remove_packagelist_entry_locked(key);
	fixup_all_perms_name(key);
	mutex_unlock(&sdcardfs_super_list_lock);
}

static void remove_ext_gid_entry_locked(const struct qstr *key, gid_t group)
{
	struct hashtable_entry *hash_cur;
	unsigned int hash = key->hash;

	hash_for_each_possible_rcu(ext_to_groupid, hash_cur, hlist, hash) {
		if (qstr_case_eq(key, &hash_cur->key) && atomic_read(&hash_cur->value) == group) {
			hash_del_rcu(&hash_cur->hlist);
			synchronize_rcu();
			free_hashtable_entry(hash_cur);
			break;
>>>>>>> c99e957c8095a85a1ff20dcfd5919e1326122fd7
		}
	}
	mutex_unlock(&sdcardfs_super_list_lock);
}

static void remove_all_hashentrys(struct packagelist_data *pkgl_dat)
{
	struct hashtable_entry *hash_cur;
	struct hlist_node *h_t;
	int i;
	spin_lock(&pkgl_data_all->hashtable_lock);
	hash_for_each_safe(pkgl_dat->package_to_appid, i, h_t, hash_cur, hlist)
		remove_str_to_int_lock(hash_cur);
	spin_unlock(&pkgl_data_all->hashtable_lock);
	hash_init(pkgl_dat->package_to_appid);
}

static struct packagelist_data * packagelist_create(void)
{
	struct packagelist_data *pkgl_dat;
	mutex_lock(&sdcardfs_super_list_lock);
	remove_userid_all_entry_locked(userid);
	fixup_all_perms_userid(userid);
	mutex_unlock(&sdcardfs_super_list_lock);
}

	pkgl_dat = kmalloc(sizeof(*pkgl_dat), GFP_KERNEL | __GFP_ZERO);
	if (!pkgl_dat) {
                printk(KERN_ERR "sdcardfs: Failed to create hash\n");
		return ERR_PTR(-ENOMEM);
	}

	spin_lock_init(&pkgl_dat->hashtable_lock);
	hash_init(pkgl_dat->package_to_appid);

	return pkgl_dat;
static void remove_userid_exclude_entry(const struct qstr *key, userid_t userid)
{
	mutex_lock(&sdcardfs_super_list_lock);
	remove_userid_exclude_entry_locked(key, userid);
	fixup_all_perms_name_userid(key, userid);
	mutex_unlock(&sdcardfs_super_list_lock);
}

static void packagelist_destroy(struct packagelist_data *pkgl_dat)
{
	remove_all_hashentrys(pkgl_dat);
	printk(KERN_INFO "sdcardfs: destroyed packagelist pkgld\n");
	kfree(pkgl_dat);
	struct hashtable_entry *hash_cur;
	struct hlist_node *h_t;
	HLIST_HEAD(free_list);
	int i;

	mutex_lock(&sdcardfs_super_list_lock);
	hash_for_each_rcu(package_to_appid, i, hash_cur, hlist) {
		hash_del_rcu(&hash_cur->hlist);
		hlist_add_head(&hash_cur->dlist, &free_list);
	}
	hash_for_each_rcu(package_to_userid, i, hash_cur, hlist) {
		hash_del_rcu(&hash_cur->hlist);
		hlist_add_head(&hash_cur->dlist, &free_list);
	}
	synchronize_rcu();
	hlist_for_each_entry_safe(hash_cur, h_t, &free_list, dlist)
		free_hashtable_entry(hash_cur);
	mutex_unlock(&sdcardfs_super_list_lock);
	pr_info("sdcardfs: destroyed packagelist pkgld\n");
}

struct package_appid {
	struct config_item item;
	int add_pid;
};

static inline struct package_appid *to_package_appid(struct config_item *item)
{
	return item ? container_of(item, struct package_details, item) : NULL;
}

CONFIGFS_ATTR_STRUCT(package_details);
#define PACKAGE_DETAILS_ATTR(_name, _mode, _show, _store)	\
struct package_details_attribute package_details_attr_##_name = __CONFIGFS_ATTR(_name, _mode, _show, _store)
#define PACKAGE_DETAILS_ATTRIBUTE(name) (&package_details_attr_##name.attr)

static ssize_t package_details_appid_show(struct package_details *package_details,
				      char *page)
{
	return item ? container_of(item, struct package_appid, item) : NULL;
}

static struct configfs_attribute package_appid_attr_add_pid = {
	.ca_owner = THIS_MODULE,
	.ca_name = "appid",
	.ca_mode = S_IRUGO | S_IWUGO,
};

static struct configfs_attribute *package_appid_attrs[] = {
	&package_appid_attr_add_pid,
	NULL,
};

static ssize_t package_appid_attr_show(struct config_item *item,
				      struct configfs_attribute *attr,
				      char *page)
{
	ssize_t count;
	count = sprintf(page, "%d\n", get_appid(pkgl_data_all, item->ci_name));
	return count;
}

static ssize_t package_appid_attr_store(struct config_item *item,
				       struct configfs_attribute *attr,
				       const char *page, size_t count)
{
	struct package_appid *package_appid = to_package_appid(item);
	unsigned long tmp;
	char *p = (char *) page;
	int ret;

	tmp = simple_strtoul(p, &p, 10);
	if (!p || (*p && (*p != '\n')))
		return -EINVAL;

	if (tmp > INT_MAX)
		return -ERANGE;
	ret = insert_str_to_int(pkgl_data_all, item->ci_name, (unsigned int)tmp);
	package_appid->add_pid = tmp;
	if (ret)
		return ret;

	return count;
}

static void package_appid_release(struct config_item *item)
{
	printk(KERN_INFO "sdcardfs: removing %s\n", item->ci_dentry->d_name.name);
	/* item->ci_name is freed already, so we rely on the dentry */
	remove_str_to_int(pkgl_data_all, item->ci_dentry->d_name.name);
	kfree(to_package_appid(item));
	struct package_details *package_details = to_package_details(item);

	pr_info("sdcardfs: removing %s\n", package_details->name.name);
	remove_packagelist_entry(&package_details->name);
	kfree(package_details->name.name);
	kfree(package_details);
}

static struct configfs_item_operations package_appid_item_ops = {
	.release		= package_appid_release,
	.show_attribute		= package_appid_attr_show,
	.store_attribute	= package_appid_attr_store,
};

static struct config_item_type package_appid_type = {
	.ct_item_ops	= &package_appid_item_ops,
	.ct_attrs	= package_appid_attrs,
	.ct_owner	= THIS_MODULE,
};


struct sdcardfs_packages {
	struct config_group group;
};

static inline struct sdcardfs_packages *to_sdcardfs_packages(struct config_item *item)
{
	return item ? container_of(to_config_group(item), struct sdcardfs_packages, group) : NULL;
}

static struct config_item *sdcardfs_packages_make_item(struct config_group *group, const char *name)
{
	struct package_appid *package_appid;

	package_appid = kzalloc(sizeof(struct package_appid), GFP_KERNEL);
	if (!package_appid)
	struct extension_details *extension_details = to_extension_details(item);

	pr_info("sdcardfs: No longer mapping %s files to gid %d\n",
			extension_details->name.name, extension_details->num);
	remove_ext_gid_entry(&extension_details->name, extension_details->num);
	kfree(extension_details->name.name);
	kfree(extension_details);
}

static struct configfs_item_operations extension_details_item_ops = {
	.release = extension_details_release,
};

static struct config_item_type extension_details_type = {
	.ct_item_ops = &extension_details_item_ops,
	.ct_owner = THIS_MODULE,
};

static struct config_item *extension_details_make_item(struct config_group *group, const char *name)
{
	struct extensions_value *extensions_value = to_extensions_value(&group->cg_item);
	struct extension_details *extension_details = kzalloc(sizeof(struct extension_details), GFP_KERNEL);
	const char *tmp;
	int ret;

	if (!extension_details)
		return ERR_PTR(-ENOMEM);

	config_item_init_type_name(&package_appid->item, name,
				   &package_appid_type);

	package_appid->add_pid = 0;

	return &package_appid->item;
static void extensions_drop_group(struct config_group *group, struct config_item *item)
{
	struct extensions_value *value = to_extensions_value(item);

	pr_info("sdcardfs: No longer mapping any files to gid %d\n", value->num);
	kfree(value);
}

static struct configfs_attribute sdcardfs_packages_attr_description = {
	.ca_owner = THIS_MODULE,
	.ca_name = "packages_gid.list",
	.ca_mode = S_IRUGO,
};

static struct configfs_attribute *sdcardfs_packages_attrs[] = {
	&sdcardfs_packages_attr_description,
	NULL,
};

static ssize_t packages_attr_show(struct config_item *item,
					 struct configfs_attribute *attr,

static inline struct packages *to_packages(struct config_item *item)
{
	return item ? container_of(to_configfs_subsystem(to_config_group(item)), struct packages, subsystem) : NULL;
}

CONFIGFS_ATTR_STRUCT(packages);
#define PACKAGES_ATTR(_name, _mode, _show, _store)	\
struct packages_attribute packages_attr_##_name = __CONFIGFS_ATTR(_name, _mode, _show, _store)
#define PACKAGES_ATTR_RO(_name, _show)	\
struct packages_attribute packages_attr_##_name = __CONFIGFS_ATTR_RO(_name, _show)

static struct config_item *packages_make_item(struct config_group *group, const char *name)
{
	struct package_details *package_details;
	const char *tmp;

	package_details = kzalloc(sizeof(struct package_details), GFP_KERNEL);
	if (!package_details)
		return ERR_PTR(-ENOMEM);
	tmp = kstrdup(name, GFP_KERNEL);
	if (!tmp) {
		kfree(package_details);
		return ERR_PTR(-ENOMEM);
	}
	qstr_init(&package_details->name, tmp);
	config_item_init_type_name(&package_details->item, name,
						&package_appid_type);

	return &package_details->item;
}

static ssize_t packages_list_show(struct packages *packages,
>>>>>>> c99e957c8095a85a1ff20dcfd5919e1326122fd7
					 char *page)
{
	struct hashtable_entry *hash_cur;
	struct hlist_node *h_t;
	int i;
	int count = 0, written = 0;
	char errormsg[] = "<truncated>\n";

	spin_lock(&pkgl_data_all->hashtable_lock);
	hash_for_each_safe(pkgl_data_all->package_to_appid, i, h_t, hash_cur, hlist) {
		written = scnprintf(page + count, PAGE_SIZE - sizeof(errormsg) - count, "%s %d\n", (char *)hash_cur->key, hash_cur->value);
		if (count + written == PAGE_SIZE - sizeof(errormsg)) {
			count += scnprintf(page + count, PAGE_SIZE - count, errormsg);
			break;
		}
		count += written;
	}
	spin_unlock(&pkgl_data_all->hashtable_lock);

	return count;
}

static void sdcardfs_packages_release(struct config_item *item)
{

	printk(KERN_INFO "sdcardfs: destroyed something?\n");
	kfree(to_sdcardfs_packages(item));
}

static struct configfs_item_operations sdcardfs_packages_item_ops = {
	.release	= sdcardfs_packages_release,
	.show_attribute	= packages_attr_show,
};

/*
 * Note that, since no extra work is required on ->drop_item(),
 * no ->drop_item() is provided.
 */
static struct configfs_group_operations sdcardfs_packages_group_ops = {
	.make_item	= sdcardfs_packages_make_item,
};

static struct config_item_type sdcardfs_packages_type = {
	.ct_item_ops	= &sdcardfs_packages_item_ops,
	.ct_group_ops	= &sdcardfs_packages_group_ops,
	.ct_attrs	= sdcardfs_packages_attrs,
	.ct_owner	= THIS_MODULE,
};

static struct configfs_subsystem sdcardfs_packages_subsys = {
	.su_group = {
		.cg_item = {
			.ci_namebuf = "sdcardfs",
			.ci_type = &sdcardfs_packages_type,
		},
	},
};

static int configfs_sdcardfs_init(void)
{
	int ret;
	struct configfs_subsystem *subsys = &sdcardfs_packages_subsys;

	for (i = 0; sd_default_groups[i]; i++)
		config_group_init(sd_default_groups[i]);
	config_group_init(&subsys->su_group);
	mutex_init(&subsys->su_mutex);
	ret = configfs_register_subsystem(subsys);
	if (ret) {
		pr_err("Error %d while registering subsystem %s\n",
		       ret,
		       subsys->su_group.cg_item.ci_namebuf);
	}
	return ret;
}

static void configfs_sdcardfs_exit(void)
{
	configfs_unregister_subsystem(&sdcardfs_packages_subsys);
}

int packagelist_init(void)
{
	hashtable_entry_cachep =
		kmem_cache_create("packagelist_hashtable_entry",
					sizeof(struct hashtable_entry), 0, 0, NULL);
	if (!hashtable_entry_cachep) {
		pr_err("sdcardfs: failed creating pkgl_hashtable entry slab cache\n");
		return -ENOMEM;
	}

	pkgl_data_all = packagelist_create();
	configfs_sdcardfs_init();
	return 0;
}

void packagelist_exit(void)
{
	configfs_sdcardfs_exit();
	packagelist_destroy(pkgl_data_all);
	if (hashtable_entry_cachep)
		kmem_cache_destroy(hashtable_entry_cachep);
}
