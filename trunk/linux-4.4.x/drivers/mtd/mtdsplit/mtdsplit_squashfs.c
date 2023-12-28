/*
 *  Copyright (C) 2013 Felix Fietkau <nbd@nbd.name>
 *  Copyright (C) 2013 Gabor Juhos <juhosg@openwrt.org>
 *
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License version 2 as published
 *  by the Free Software Foundation.
 *
 */

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/magic.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/partitions.h>
#include <linux/byteorder/generic.h>

#include "mtdsplit.h"

static int
mtdsplit_parse_squashfs(struct mtd_info *master,
			struct mtd_partition **pparts,
			struct mtd_part_parser_data *data)
{
	struct mtd_partition *part;
	struct mtd_info *parent_mtd;
	size_t part_offset;
	size_t squashfs_len;
	size_t dm_off, dm_len;
	size_t retlen;
	char verity[7];
	int err;

	err = mtd_get_squashfs_len(master, 0, &squashfs_len);
	if (err)
		return err;

	parent_mtd = mtdpart_get_master(master);
	part_offset = mtdpart_get_offset(master);

#define DM_VERITY_STR		"verity"
#define DM_VERITY_BLK_SZ	4096
	/* Try to find DM-verity */
	dm_off = roundup(squashfs_len, DM_VERITY_BLK_SZ);
	dm_len = 7;
	err = mtd_read(master, dm_off, dm_len, &retlen, (void *)&verity);
	if (err || (retlen != dm_len)) {
		pr_alert("error occured while reading from \"%s\"\n",
			 master->name);
		return -EIO;
	}
	if (!strcmp(verity, DM_VERITY_STR)) {
		int dm_sz;

		dm_sz = roundup(squashfs_len / 128, DM_VERITY_BLK_SZ);
		dm_sz += DM_VERITY_BLK_SZ * 2;
		squashfs_len += dm_sz;
	}

	part = kzalloc(sizeof(*part), GFP_KERNEL);
	if (!part) {
		pr_alert("unable to allocate memory for \"%s\" partition\n",
			 ROOTFS_SPLIT_NAME);
		return -ENOMEM;
	}

	part->name = ROOTFS_SPLIT_NAME;
	part->offset = mtd_roundup_to_eb(part_offset + squashfs_len,
					 parent_mtd) - part_offset;
	if (master->type == MTD_NANDFLASH)
		part->offset += mtd_countbad(master, 0, part->offset) *
				master->erasesize;
	part->size = mtd_rounddown_to_eb(master->size - part->offset, master);

	*pparts = part;
	return 1;
}

static struct mtd_part_parser mtdsplit_squashfs_parser = {
	.owner = THIS_MODULE,
	.name = "squashfs-split",
	.parse_fn = mtdsplit_parse_squashfs,
	.type = MTD_PARSER_TYPE_ROOTFS,
};

static int __init mtdsplit_squashfs_init(void)
{
	register_mtd_parser(&mtdsplit_squashfs_parser);

	return 0;
}

subsys_initcall(mtdsplit_squashfs_init);
