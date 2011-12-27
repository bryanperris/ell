/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2011  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <stdio.h>

#include <ell/ell.h>

struct settings_test {
	const char *input;
};

static struct settings_test settings_test1 = {
	.input = "[Foobar]\n#Comment\n#Comment2\nKey=Value\n",
};

static void settings_debug(const char *str, void *userdata)
{
	printf("%s\n", str);
}

static void test_settings(const void *test_data)
{
	const struct settings_test *test = test_data;
	struct l_settings *settings;

	settings = l_settings_new();

	l_settings_set_debug(settings, settings_debug, NULL, NULL);

	l_settings_load_from_data(settings, test->input, strlen(test->input));
	l_settings_free(settings);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("Settings Test 1", test_settings, &settings_test1);

	return l_test_run();
}
