/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2011-2015  Intel Corporation. All rights reserved.
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

#include <stdlib.h>
#include <assert.h>

#include <ell/ell.h>
#include "ell/dbus-private.h"
#include "ell/private.h"

#define DBUS_SERVICE_DBUS	"org.freedesktop.DBus"
#define DBUS_PATH_DBUS		"/org/freedesktop/DBus"
#define DBUS_INTERFACE_DBUS	"org.freedesktop.DBus"

static void test_rule_to_str(const void *test_data)
{
	static const struct _dbus_filter_condition rule1[] = {
		{ L_DBUS_MATCH_TYPE, "signal" },
		{ L_DBUS_MATCH_SENDER, DBUS_SERVICE_DBUS },
		{ L_DBUS_MATCH_PATH, DBUS_PATH_DBUS },
		{ L_DBUS_MATCH_INTERFACE, DBUS_INTERFACE_DBUS },
		{ L_DBUS_MATCH_MEMBER, "NameOwnerChanged" },
		{ L_DBUS_MATCH_ARGUMENT(0), ":1.101" }
	};
	static const char *expected1 = "type='signal',"
		"sender='org.freedesktop.DBus',"
		"path='/org/freedesktop/DBus',"
		"interface='org.freedesktop.DBus',"
		"member='NameOwnerChanged',"
		"arg0=':1.101'";
	static const struct _dbus_filter_condition rule2[] = {
		{ L_DBUS_MATCH_ARGUMENT(0), "'" },
		{ L_DBUS_MATCH_ARGUMENT(1), "\\" },
		{ L_DBUS_MATCH_ARGUMENT(2), "," },
		{ L_DBUS_MATCH_ARGUMENT(3), "\\\\" }
	};
	static const char *expected2 =
		"arg0=''\\''',arg1='\\',arg2=',',arg3='\\\\'";
	char *str;

	str = _dbus_filter_rule_to_str(rule1, L_ARRAY_SIZE(rule1));
	assert(str && !strcmp(str, expected1));
	l_free(str);

	str = _dbus_filter_rule_to_str(rule2, L_ARRAY_SIZE(rule2));
	assert(str && !strcmp(str, expected2));
	l_free(str);
}

struct l_dbus {
};

struct filter_test_state {
	struct l_dbus dbus;
	const struct _dbus_filter_condition *expected_rule;
	int expected_rule_len;
	unsigned int expected_id, new_id;
	int calls[5];
};

static void rule_compare(const struct _dbus_filter_condition *a, int len_a,
			const struct _dbus_filter_condition *b, int len_b)
{
	int i, j;
	bool matched[len_a];

	assert(len_a == len_b);

	for (i = 0; i < len_a; i++)
		matched[i] = false;

	for (i = 0; i < len_a; i++) {
		for (j = 0; j < len_a; j++)
			if (!matched[j] && a[i].type == b[j].type &&
					!strcmp(a[i].value, b[j].value))
				break;

		assert(j < len_a);
		matched[j] = true;
	}
}

static bool test_add_match(struct l_dbus *dbus, unsigned int id,
				const struct _dbus_filter_condition *rule,
				int rule_len)
{
	struct filter_test_state *test =
		l_container_of(dbus, struct filter_test_state, dbus);

	assert(test->expected_rule);

	rule_compare(test->expected_rule, test->expected_rule_len,
			rule, rule_len);

	test->new_id = id;
	test->expected_rule = NULL;

	return true;
}

static bool test_remove_match(struct l_dbus *dbus, unsigned int id)
{
	struct filter_test_state *test =
		l_container_of(dbus, struct filter_test_state, dbus);

	assert(test->expected_id == id && id);

	test->expected_id = 0;

	return true;
}

static void test_rule1_cb(struct l_dbus_message *message, void *user_data)
{
	struct filter_test_state *test = user_data;

	test->calls[0]++;
}

static void test_rule2_cb(struct l_dbus_message *message, void *user_data)
{
	struct filter_test_state *test = user_data;

	test->calls[1]++;
}

static void test_rule3_cb(struct l_dbus_message *message, void *user_data)
{
	struct filter_test_state *test = user_data;

	test->calls[2]++;
}

static void test_rule4_cb(struct l_dbus_message *message, void *user_data)
{
	struct filter_test_state *test = user_data;

	test->calls[3]++;
}

static void test_rule5_cb(struct l_dbus_message *message, void *user_data)
{
	struct filter_test_state *test = user_data;

	test->calls[4]++;
}

static void test_filter_tree(const void *test_data)
{
	struct _dbus_filter *filter;
	struct filter_test_state test = { .calls = { 0, 0, 0, 0 } };
	static const struct _dbus_filter_ops filter_ops = {
		.skip_register = true,
		.add_match = test_add_match,
		.remove_match = test_remove_match,
	};
	static const struct _dbus_filter_condition rule123[] = {
		{ L_DBUS_MATCH_TYPE, "signal" },
		{ L_DBUS_MATCH_SENDER, DBUS_SERVICE_DBUS },
		{ L_DBUS_MATCH_PATH, DBUS_PATH_DBUS },
		{ L_DBUS_MATCH_INTERFACE, DBUS_INTERFACE_DBUS },
		{ L_DBUS_MATCH_MEMBER, "NameOwnerChanged" },
		{ L_DBUS_MATCH_ARGUMENT(0), "org.test" }
	};
	static const struct _dbus_filter_condition rule45[] = {
		{ L_DBUS_MATCH_TYPE, "signal" },
		{ L_DBUS_MATCH_PATH, "/" },
		{ L_DBUS_MATCH_SENDER, "org.foo" },
	};
	unsigned int id1, id2, id3, id4, id5, internal_id1, internal_id4;
	struct l_dbus_message *message;

	filter = _dbus_filter_new(&test.dbus, &filter_ops, NULL);
	assert(filter);

	test.expected_rule = rule123;
	test.expected_rule_len = 2;
	id1 = _dbus_filter_add_rule(filter, rule123, 2, test_rule1_cb, &test);
	assert(id1);
	assert(!test.expected_rule);
	internal_id1 = test.new_id;

	id2 = _dbus_filter_add_rule(filter, rule123, 4, test_rule2_cb, &test);
	id3 = _dbus_filter_add_rule(filter, rule123, 6, test_rule3_cb, &test);
	assert(id2 && id3 && id2 != id1 && id3 != id1 && id3 != id2);

	test.expected_rule = rule45;
	test.expected_rule_len = 2;
	id4 = _dbus_filter_add_rule(filter, rule45, 2, test_rule4_cb, &test);
	assert(id4 && id4 != id1 && id4 != id2 && id4 != id3);
	assert(!test.expected_rule);
	internal_id4 = test.new_id;

	id5 = _dbus_filter_add_rule(filter, rule45, 3, test_rule5_cb, &test);
	assert(id5 && id5 != id1 && id5 != id2 && id5 != id3 && id5 != id4);

	assert(test.calls[0] == 0 && test.calls[1] == 0 &&
			test.calls[2] == 0 && test.calls[3] == 0 &&
			test.calls[4] == 0);

	message = _dbus_message_new_signal(2, DBUS_PATH_DBUS,
						DBUS_INTERFACE_DBUS,
						"NameOwnerChanged");
	l_dbus_message_set_arguments(message, "sss", "org.test",
					"", ":1.101");
	_dbus_message_set_sender(message, DBUS_SERVICE_DBUS);
	_dbus_filter_dispatch(message, filter);
	_dbus_message_set_sender(message, NULL);
	l_dbus_message_unref(message);

	message = _dbus_message_new_signal(2, DBUS_PATH_DBUS,
						DBUS_INTERFACE_DBUS,
						"NameOwnerChanged");
	l_dbus_message_set_arguments(message, "");
	_dbus_message_set_sender(message, DBUS_SERVICE_DBUS);
	_dbus_filter_dispatch(message, filter);
	_dbus_message_set_sender(message, NULL);
	l_dbus_message_unref(message);

	message = _dbus_message_new_signal(2, DBUS_PATH_DBUS, "foo", "Bar");
	l_dbus_message_set_arguments(message, "");
	_dbus_message_set_sender(message, DBUS_SERVICE_DBUS);
	_dbus_filter_dispatch(message, filter);
	_dbus_message_set_sender(message, NULL);
	l_dbus_message_unref(message);

	message = _dbus_message_new_signal(2, "/", "foo", "Bar");
	l_dbus_message_set_arguments(message, "");
	_dbus_message_set_sender(message, "org.foo");
	_dbus_filter_dispatch(message, filter);

	_dbus_message_set_sender(message, "org.bar");
	_dbus_filter_dispatch(message, filter);
	_dbus_message_set_sender(message, NULL);
	l_dbus_message_unref(message);

	assert(test.calls[0] == 3 && test.calls[1] == 2 &&
			test.calls[2] == 1 && test.calls[3] == 2 &&
			test.calls[4] == 1);

	test.expected_id = 0;
	assert(_dbus_filter_remove_rule(filter, id2));

	assert(_dbus_filter_remove_rule(filter, id1));

	assert(_dbus_filter_remove_rule(filter, id5));

	test.expected_id = internal_id4;
	assert(_dbus_filter_remove_rule(filter, id4));
	assert(!test.expected_id);

	test.expected_id = internal_id1;
	assert(_dbus_filter_remove_rule(filter, id3));
	assert(!test.expected_id);

	_dbus_filter_free(filter);

	assert(test.calls[0] == 3 && test.calls[1] == 2 &&
			test.calls[2] == 1 && test.calls[3] == 2 &&
			test.calls[4] == 1);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("_dbus_filter_rule_to_str", test_rule_to_str, NULL);

	l_test_add("DBus filter tree", test_filter_tree, NULL);

	return l_test_run();
}
