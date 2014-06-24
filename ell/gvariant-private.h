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

struct l_dbus_message_iter;
struct gvariant_builder;

bool _gvariant_iter_init(struct l_dbus_message_iter *iter,
				struct l_dbus_message *message,
				const char *sig_start, const char *sig_end,
				const void *data, size_t len);
bool _gvariant_iter_next_entry_basic(struct l_dbus_message_iter *iter,
					char type, void *out_p);
bool _gvariant_iter_enter_struct(struct l_dbus_message_iter *iter,
					struct l_dbus_message_iter *structure);
bool _gvariant_iter_enter_variant(struct l_dbus_message_iter *iter,
					struct l_dbus_message_iter *variant);
bool _gvariant_iter_enter_array(struct l_dbus_message_iter *iter,
					struct l_dbus_message_iter *array);

bool _gvariant_valid_signature(const char *sig);
int _gvariant_get_alignment(const char *signature);
bool _gvariant_is_fixed_size(const char *signature);
int _gvariant_get_fixed_size(const char *signature);
int _gvariant_num_children(const char *sig);

struct gvariant_builder *_gvariant_builder_new(void);
void _gvariant_builder_free(struct gvariant_builder *builder);
bool _gvariant_builder_append_basic(struct gvariant_builder *builder,
					char type, const void *value);
char *_gvariant_builder_finish(struct gvariant_builder *builder,
				void **body, size_t *body_size);
bool _gvariant_builder_enter_struct(struct gvariant_builder *builder,
					const char *signature);
bool _gvariant_builder_leave_struct(struct gvariant_builder *builder);
