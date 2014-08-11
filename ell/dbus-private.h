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

enum dbus_message_type {
	DBUS_MESSAGE_TYPE_METHOD_CALL	= 1,
	DBUS_MESSAGE_TYPE_METHOD_RETURN	= 2,
	DBUS_MESSAGE_TYPE_ERROR		= 3,
	DBUS_MESSAGE_TYPE_SIGNAL	= 4,
};

enum dbus_container_type {
	DBUS_CONTAINER_TYPE_ARRAY	= 'a',
	DBUS_CONTAINER_TYPE_STRUCT	= 'r',
	DBUS_CONTAINER_TYPE_VARIANT	= 'v',
	DBUS_CONTAINER_TYPE_DICT_ENTRY	= 'e',
};

#if __BYTE_ORDER == __BIG_ENDIAN
	#define DBUS_NATIVE_ENDIAN 'B'
#else
	#define DBUS_NATIVE_ENDIAN 'l'
#endif

struct dbus_header {
	uint8_t  endian;
	uint8_t  message_type;
	uint8_t  flags;
	uint8_t  version;
	uint32_t body_length;
	uint32_t serial;
	uint32_t field_length;
} __attribute__ ((packed));
#define DBUS_HEADER_SIZE 16

struct dbus_builder;
struct l_string;
struct l_dbus_interface;
struct _dbus_method;
struct _dbus_signal;
struct _dbus_property;
struct l_dbus_message_iter;
struct l_dbus_message;
struct l_dbus;

void _dbus1_iter_init(struct l_dbus_message_iter *iter,
			struct l_dbus_message *message,
			const char *sig_start, const char *sig_end,
			const void *data, size_t len);
bool _dbus1_iter_next_entry_basic(struct l_dbus_message_iter *iter, char type,
					void *out);
bool _dbus1_iter_enter_struct(struct l_dbus_message_iter *iter,
					struct l_dbus_message_iter *structure);
bool _dbus1_iter_enter_variant(struct l_dbus_message_iter *iter,
					struct l_dbus_message_iter *variant);
bool _dbus1_iter_enter_array(struct l_dbus_message_iter *iter,
					struct l_dbus_message_iter *array);

struct dbus_builder *_dbus1_builder_new(void *body, size_t body_size);
void _dbus1_builder_free(struct dbus_builder *builder);
bool _dbus1_builder_append_basic(struct dbus_builder *builder,
					char type, const void *value);
bool _dbus1_builder_enter_struct(struct dbus_builder *builder,
					const char *signature);
bool _dbus1_builder_leave_struct(struct dbus_builder *builder);
bool _dbus1_builder_enter_dict(struct dbus_builder *builder,
					const char *signature);
bool _dbus1_builder_leave_dict(struct dbus_builder *builder);
bool _dbus1_builder_enter_variant(struct dbus_builder *builder,
					const char *signature);
bool _dbus1_builder_leave_variant(struct dbus_builder *builder);
bool _dbus1_builder_enter_array(struct dbus_builder *builder,
					const char *signature);
bool _dbus1_builder_leave_array(struct dbus_builder *builder);
char *_dbus1_builder_finish(struct dbus_builder *builder,
				void **body, size_t *body_size);

void *_dbus_message_get_body(struct l_dbus_message *msg, size_t *out_size);
void *_dbus_message_get_header(struct l_dbus_message *msg, size_t *out_size);
void _dbus_message_set_serial(struct l_dbus_message *msg, uint32_t serial);
uint32_t _dbus_message_get_reply_serial(struct l_dbus_message *message);

enum dbus_message_type _dbus_message_get_type(struct l_dbus_message *message);
const char * _dbus_message_get_type_as_string(struct l_dbus_message *message);
uint8_t _dbus_message_get_version(struct l_dbus_message *message);
uint8_t _dbus_message_get_endian(struct l_dbus_message *message);

void _dbus_message_set_no_reply_expected(struct l_dbus_message *msg, bool on);
struct l_dbus_message *dbus_message_from_blob(const void *data, size_t size);
struct l_dbus_message *dbus_message_build(void *header, size_t header_size,
						void *body, size_t body_size,
						int fds[], uint32_t num_fds);
bool dbus_message_compare(struct l_dbus_message *message,
					const void *data, size_t size);

const char *_dbus_signature_end(const char *signature);

bool _dbus_valid_object_path(const char *path);
bool _dbus_valid_signature(const char *sig);
bool _dbus_valid_interface(const char *interface);
bool _dbus_valid_method(const char *method);

void _dbus_method_introspection(struct _dbus_method *info,
					struct l_string *buf);
void _dbus_signal_introspection(struct _dbus_signal *info,
					struct l_string *buf);
void _dbus_property_introspection(struct _dbus_property *info,
						struct l_string *buf);
void _dbus_interface_introspection(struct l_dbus_interface *interface,
						struct l_string *buf);

struct l_dbus_interface *_dbus_interface_new(const char *interface);
void _dbus_interface_free(struct l_dbus_interface *interface);

struct _dbus_method *_dbus_interface_find_method(struct l_dbus_interface *i,
							const char *method);
struct _dbus_signal *_dbus_interface_find_signal(struct l_dbus_interface *i,
							const char *signal);
struct _dbus_property *_dbus_interface_find_property(struct l_dbus_interface *i,
						const char *property);

struct _dbus_object_tree *_dbus_object_tree_new();
void _dbus_object_tree_free(struct _dbus_object_tree *tree);

struct object_node *_dbus_object_tree_makepath(struct _dbus_object_tree *tree,
						const char *path);
struct object_node *_dbus_object_tree_lookup(struct _dbus_object_tree *tree,
						const char *path);
void _dbus_object_tree_prune_node(struct object_node *node);

bool _dbus_object_tree_register(struct _dbus_object_tree *tree,
				const char *path, const char *interface,
				void (*setup_func)(struct l_dbus_interface *),
				void *user_data, void (*destroy) (void *));
bool _dbus_object_tree_unregister(struct _dbus_object_tree *tree,
					const char *path,
					const char *interface);

void _dbus_object_tree_introspect(struct _dbus_object_tree *tree,
					const char *path, struct l_string *buf);
bool _dbus_object_tree_dispatch(struct _dbus_object_tree *tree,
					struct l_dbus *dbus,
					struct l_dbus_message *message);

void _dbus_kernel_bloom_add(uint64_t filter[], size_t size, uint8_t num_hash,
				const char *prefix, const char *str);
void _dbus_kernel_bloom_add_parents(uint64_t filter[], size_t size,
					uint8_t num_hash, const char *prefix,
					const char *str, const char sep);

int _dbus_kernel_create_bus(const char *name);

struct l_dbus_message *_dbus_message_new_method_call(uint8_t version,
							const char *destination,
							const char *path,
							const char *interface,
							const char *method);
