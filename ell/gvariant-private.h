/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2011-2014  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License version 2.1 as published by the Free Software Foundation.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

struct gvariant_type_info {
	uint8_t sig_start;
	uint8_t sig_end;
	bool fixed_size : 1;
	unsigned int alignment : 4;
	size_t end;		/* Index past the end of the type */
};

struct gvariant_iter {
	const char *sig_start;
	uint8_t sig_len;
	uint8_t sig_pos;
	const void *data;
	size_t len;
	size_t pos;
	char container_type;
	const void *offsets;
	struct gvariant_type_info *children;
	uint8_t n_children;
	size_t cur_child;
};

bool _gvariant_iter_init(struct gvariant_iter *iter, const char *sig_start,
				const char *sig_end,
				const void *data, size_t len);
void _gvariant_iter_free(struct gvariant_iter *iter);
bool _gvariant_iter_next_entry_basic(struct gvariant_iter *iter, char type,
					void *out_p);
bool _gvariant_iter_enter_struct(struct gvariant_iter *iter,
					struct gvariant_iter *structure);
bool _gvariant_iter_enter_variant(struct gvariant_iter *iter,
					struct gvariant_iter *variant);
bool _gvariant_iter_enter_array(struct gvariant_iter *iter,
					struct gvariant_iter *array);

bool _gvariant_valid_signature(const char *sig);
int _gvariant_get_alignment(const char *signature);
bool _gvariant_is_fixed_size(const char *signature);
int _gvariant_get_fixed_size(const char *signature);
int _gvariant_num_children(const char *sig);
