/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2011-2014  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <alloca.h>
#include <fnmatch.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "util.h"
#include "hwdb.h"
#include "private.h"

static const char trie_sig[8] = { 'K', 'S', 'L', 'P', 'H', 'H', 'R', 'H' };

struct trie_header {
	uint8_t  signature[8];		/* Signature */
	uint64_t version;		/* Version of creator tool */
	uint64_t file_size;		/* Size of complete file */
	uint64_t header_size;		/* Size of header structure */
	uint64_t node_size;		/* Size of node structure */
	uint64_t child_size;		/* Size of child structure */
	uint64_t entry_size;		/* Size of entry structure */
	uint64_t root_offset;		/* Location of root node structure */
	uint64_t nodes_size;		/* Size of the nodes section */
	uint64_t strings_size;		/* Size of the strings section */

	/* followed by nodes_size nodes data */
	/* followed by strings_size strings data */
} __attribute__ ((packed));

struct trie_node {
	uint64_t prefix_offset;		/* Location of prefix string */
	uint8_t  child_count;		/* Number of child structures */
	uint8_t  padding[7];
	uint64_t entry_count;		/* Number of entry structures */

	/* followed by child_count child structures */
	/* followed by entry_count entry structures */
} __attribute__ ((packed));

struct trie_child {
	uint8_t  c;			/* Prefix character of child node */
	uint8_t  padding[7];
	uint64_t child_offset;		/* Location of child node structure */
} __attribute__ ((packed));

struct trie_entry {
	uint64_t key_offset;		/* Location of key string */
	uint64_t value_offset;		/* Location of value string */
} __attribute__ ((packed));

struct l_hwdb {
	int ref_count;
	int fd;
	time_t mtime;
	size_t size;
	void *addr;
	uint64_t root;
};

LIB_EXPORT struct l_hwdb *l_hwdb_new(const char *pathname)
{
	struct trie_header *hdr;
	struct l_hwdb *hwdb;
	struct stat st;
	void *addr;
	size_t size;
	int fd;

	if (!pathname)
		return NULL;

	fd = open(pathname, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return NULL;

	if (fstat(fd, &st) < 0) {
		close(fd);
		return NULL;
	}

	size = st.st_size;
	if (size < sizeof(struct trie_header)) {
		close(fd);
		return NULL;
	}

	addr = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		close(fd);
		return NULL;
	}

	hdr = addr;
	if (memcmp(hdr->signature, trie_sig, sizeof(trie_sig)))
		goto failed;

	if (le64_to_cpu(hdr->file_size) != size)
		goto failed;

	if (le64_to_cpu(hdr->header_size) != sizeof(struct trie_header))
		goto failed;

	if (le64_to_cpu(hdr->node_size) != sizeof(struct trie_node))
		goto failed;

	if (le64_to_cpu(hdr->child_size) != sizeof(struct trie_child))
		goto failed;

	if (le64_to_cpu(hdr->entry_size) != sizeof(struct trie_entry))
		goto failed;

	if (le64_to_cpu(hdr->header_size) + le64_to_cpu(hdr->nodes_size) +
					le64_to_cpu(hdr->strings_size) != size)
		goto failed;

	hwdb = l_new(struct l_hwdb, 1);

	hwdb->fd = fd;
	hwdb->mtime = st.st_mtime;
	hwdb->size = size;
	hwdb->addr = addr;
	hwdb->root = le64_to_cpu(hdr->root_offset);

	return l_hwdb_ref(hwdb);

failed:
	munmap(addr, st.st_size);
	close(fd);
	return NULL;
}

LIB_EXPORT struct l_hwdb *l_hwdb_new_default(void)
{
	return l_hwdb_new("/etc/udev/hwdb.bin");
}

LIB_EXPORT struct l_hwdb *l_hwdb_ref(struct l_hwdb *hwdb)
{
	if (!hwdb)
		return NULL;

	__sync_fetch_and_add(&hwdb->ref_count, 1);

	return hwdb;
}

LIB_EXPORT void l_hwdb_unref(struct l_hwdb *hwdb)
{
	if (!hwdb)
		return;

	if (__sync_sub_and_fetch(&hwdb->ref_count, 1))
		return;

	munmap(hwdb->addr, hwdb->size);

	close(hwdb->fd);

	l_free(hwdb);
}

static void print_node(const void *addr, uint64_t offset, const char *prefix,
				l_hwdb_print_func_t func, void *user_data)
{
	const struct trie_node *node = addr + offset;
	const void *addr_ptr = addr + offset + sizeof(*node);
	const char *prefix_str = addr + le64_to_cpu(node->prefix_offset);
	uint64_t child_count = le64_to_cpu(node->child_count);
	uint64_t entry_count = le64_to_cpu(node->entry_count);
	uint64_t i;
	char *str;

	for (i = 0; i < child_count; i++) {
		const struct trie_child *child = addr_ptr;

		str = l_strdup_printf("%s%s%c", prefix, prefix_str, child->c);
		print_node(addr, le64_to_cpu(child->child_offset), str,
							func, user_data);
		l_free(str);

		addr_ptr += sizeof(*child);
	}

	if (!entry_count)
		return;

	str = l_strdup_printf("%s%s", prefix, prefix_str);
	func(str, user_data);
	l_free(str);

	for (i = 0; i < entry_count; i++) {
		const struct trie_entry *entry = addr_ptr;
		const char *key_str = addr + le64_to_cpu(entry->key_offset);
		const char *val_str = addr + le64_to_cpu(entry->value_offset);

		str = l_strdup_printf("%s=%s", key_str, val_str);
		func(str, user_data);
		l_free(str);

		addr_ptr += sizeof(*entry);
	}

	func("", user_data);
}

LIB_EXPORT void l_hwdb_print_all(struct l_hwdb *hwdb, l_hwdb_print_func_t func,
							void *user_data)
{
	if (!hwdb || !func)
		return;

	print_node(hwdb->addr, hwdb->root, "", func, user_data);
}

static int trie_fnmatch(const void *addr, uint64_t offset, const char *prefix,
			const char *string, struct l_hwdb_entry **entries)
{
	const struct trie_node *node = addr + offset;
	const void *addr_ptr = addr + offset + sizeof(*node);
	const char *prefix_str = addr + le64_to_cpu(node->prefix_offset);
	uint64_t child_count = le64_to_cpu(node->child_count);
	uint64_t entry_count = le64_to_cpu(node->entry_count);
	uint64_t i;
	size_t scratch_len;
	char *scratch_buf;

	scratch_len = strlen(prefix) + strlen(prefix_str);
	scratch_buf = alloca(scratch_len + 2);
	sprintf(scratch_buf, "%s%s", prefix, prefix_str);
	scratch_buf[scratch_len + 1] = '\0';

	for (i = 0; i < child_count; i++) {
		const struct trie_child *child = addr_ptr;
		int err;

		scratch_buf[scratch_len] = child->c;

		err = trie_fnmatch(addr, le64_to_cpu(child->child_offset),
						scratch_buf, string, entries);
		if (err)
			return err;

		addr_ptr += sizeof(*child);
	}

	if (!entry_count)
		return 0;

	scratch_buf[scratch_len] = '\0';

	if (fnmatch(scratch_buf, string, 0))
		return 0;

	for (i = 0; i < entry_count; i++) {
		const struct trie_entry *entry = addr_ptr;
		const char *key_str = addr + le64_to_cpu(entry->key_offset);
		const char *val_str = addr + le64_to_cpu(entry->value_offset);
		struct l_hwdb_entry *result;

		if (key_str[0] == ' ') {
			result = l_new(struct l_hwdb_entry, 1);

			result->key = key_str + 1;
			result->value = val_str;
			result->next = (*entries);
			*entries = result;
		}

		addr_ptr += sizeof(*entry);
	}

	return 0;
}

LIB_EXPORT struct l_hwdb_entry *l_hwdb_lookup(struct l_hwdb *hwdb,
							const char *modalias)
{
	struct l_hwdb_entry *entries = NULL;

	if (!hwdb || !modalias)
		return NULL;

	trie_fnmatch(hwdb->addr, hwdb->root, "", modalias, &entries);

	return entries;
}

LIB_EXPORT void l_hwdb_lookup_free(struct l_hwdb_entry *entries)
{
	while (entries) {
		struct l_hwdb_entry *entry = entries;

		entries = entries->next;

		l_free(entry);
	}
}
