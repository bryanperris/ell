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

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>

#include <ell/ell.h>

#define TEST_DIR "/tmp/ell-test-dir"
#define TEST_FILE1 "/tmp/ell-test-dir/file1"
#define TEST_FILE2 "/tmp/ell-test-dir/file2"

static struct l_fswatch *dir_watch;
static struct l_fswatch *file_watch;
static int data;

static enum {
	TEST_DIR_DESTROY_CB_1,
	TEST_FILE_CREATE,
	TEST_FILE_MOVE,
	TEST_FILE_MODIFY,
	TEST_FILE_REMOVE,
	TEST_DIR_REMOVE,
	TEST_DIR_DESTROY_CB_2,
} state;

static int substate;

enum {
	TEST_FILE_MOVE_DIR_FROM_EVENT = 1 << 0,
	TEST_FILE_MOVE_DIR_TO_EVENT = 1 << 1,
	TEST_FILE_MOVE_FILE_EVENT = 1 << 2,
	TEST_FILE_MOVE_ALL = 7,
};

enum {
	TEST_FILE_MODIFY_DIR_EVENT = 1 << 0,
	TEST_FILE_MODIFY_FILE_EVENT = 1 << 1,
	TEST_FILE_MODIFY_ALL = 3,
};

enum {
	TEST_FILE_REMOVE_DIR_EVENT = 1 << 0,
	TEST_FILE_REMOVE_FILE_EVENT = 1 << 1,
	TEST_FILE_REMOVE_DESTROY_CB = 1 << 2,
	TEST_FILE_REMOVE_ALL = 7,
};

static void test_file_move_check(void)
{
	if (substate == TEST_FILE_MOVE_ALL) {
		l_info("TEST_FILE_MODIFY");
		state = TEST_FILE_MODIFY;
		substate = 0;
		assert(close(creat(TEST_FILE2, 0600)) == 0);
	}
}

static void test_file_modify_check(void)
{
	if (substate == TEST_FILE_MODIFY_ALL) {
		l_info("TEST_FILE_REMOVE");
		state = TEST_FILE_REMOVE;
		substate = 0;
		assert(unlink(TEST_FILE2) == 0);
	}
}

static void test_file_remove_check(void)
{
	if (substate == TEST_FILE_REMOVE_ALL) {
		l_info("TEST_DIR_REMOVE");
		state = TEST_DIR_REMOVE;
		substate = 0;
		assert(rmdir(TEST_DIR) == 0);
	}
}

static void file_watch_destroy(void *user_data)
{
	assert(user_data == &data);
	assert(state == TEST_FILE_REMOVE);
	assert(!(substate & TEST_FILE_REMOVE_DESTROY_CB));
	assert(substate & TEST_FILE_REMOVE_FILE_EVENT);

	substate |= TEST_FILE_REMOVE_DESTROY_CB;

	test_file_remove_check();
}

static void file_watch_cb(struct l_fswatch *watch, const char *filename,
				enum l_fswatch_event event, void *user_data)
{
	assert(watch == file_watch);
	assert(user_data == &data);
	assert(filename == NULL);

	switch (state) {
	case TEST_FILE_MOVE:
		assert(event == L_FSWATCH_EVENT_MOVE);
		assert(!(substate & TEST_FILE_MOVE_FILE_EVENT));

		substate |= TEST_FILE_MOVE_FILE_EVENT;

		test_file_move_check();
		break;
	case TEST_FILE_MODIFY:
		assert(event == L_FSWATCH_EVENT_MODIFY);
		assert(!(substate & TEST_FILE_MODIFY_FILE_EVENT));

		substate |= TEST_FILE_MODIFY_FILE_EVENT;

		test_file_modify_check();
		break;
	case TEST_FILE_REMOVE:
		assert(event == L_FSWATCH_EVENT_DELETE);
		assert(!(substate & TEST_FILE_REMOVE_FILE_EVENT));

		substate |= TEST_FILE_REMOVE_FILE_EVENT;

		test_file_remove_check();
		break;
	default:
		assert(false);
	}
}

static void dir_watch_destroy_1(void *user_data)
{
	assert(user_data == &data);
	assert(state == TEST_DIR_DESTROY_CB_1);
	assert(dir_watch);

	dir_watch = NULL;
}

static void dir_watch_destroy_2(void *user_data)
{
	assert(user_data == &data);
	assert(state == TEST_DIR_DESTROY_CB_2);
	assert(dir_watch);

	l_main_quit();

	dir_watch = NULL;
}

static void dir_watch_cb(struct l_fswatch *watch, const char *filename,
				enum l_fswatch_event event, void *user_data)
{
	assert(watch == dir_watch);
	assert(user_data == &data);

	switch (state) {
	case TEST_FILE_CREATE:
		assert(event == L_FSWATCH_EVENT_CREATE);
		assert(filename);
		assert(strstr(TEST_FILE1, filename));

		file_watch = l_fswatch_new(TEST_FILE1, file_watch_cb, &data,
						file_watch_destroy);
		assert(file_watch);

		l_info("TEST_FILE_MOVE");
		state = TEST_FILE_MOVE;
		substate = 0;
		assert(rename(TEST_FILE1, TEST_FILE2) == 0);
		break;
	case TEST_FILE_MOVE:
		assert(event == L_FSWATCH_EVENT_MOVE);
		assert(filename);

		if (strstr(TEST_FILE1, filename)) {
			assert(!(substate & TEST_FILE_MOVE_DIR_FROM_EVENT));

			substate |= TEST_FILE_MOVE_DIR_FROM_EVENT;
		} else if (strstr(TEST_FILE2, filename)) {
			assert(!(substate & TEST_FILE_MOVE_DIR_TO_EVENT));

			substate |= TEST_FILE_MOVE_DIR_TO_EVENT;
		} else
			assert(false);

		test_file_move_check();
		break;
	case TEST_FILE_MODIFY:
		assert(event == L_FSWATCH_EVENT_MODIFY);
		assert(filename);
		assert(strstr(TEST_FILE2, filename));
		assert(!(substate & TEST_FILE_MODIFY_DIR_EVENT));

		substate |= TEST_FILE_MODIFY_DIR_EVENT;

		test_file_modify_check();
		break;
	case TEST_FILE_REMOVE:
		assert(event == L_FSWATCH_EVENT_DELETE);
		assert(filename);
		assert(strstr(TEST_FILE2, filename));
		assert(!(substate & TEST_FILE_REMOVE_DIR_EVENT));

		substate |= TEST_FILE_REMOVE_DIR_EVENT;

		test_file_remove_check();
		break;
	case TEST_DIR_REMOVE:
		assert(event == L_FSWATCH_EVENT_DELETE);
		assert(filename == NULL);

		l_info("TEST_DIR_DESTROY_CB_2");
		state = TEST_DIR_DESTROY_CB_2;
		break;
	default:
		assert(false);
	}
}

static void timeout_cb(struct l_timeout *timeout, void *user_data)
{
	assert(false);
}

int main(int argc, char *argv[])
{
	struct l_timeout *timeout;

	assert(l_main_init());

	l_log_set_stderr();

	unlink(TEST_FILE1);
	unlink(TEST_FILE2);
	rmdir(TEST_DIR);
	assert(mkdir(TEST_DIR, 0700) == 0);

	timeout = l_timeout_create(1, timeout_cb, NULL, NULL);

	l_info("TEST_DIR_DESTROY_CB_1");
	state = TEST_DIR_DESTROY_CB_1;

	dir_watch = l_fswatch_new(TEST_DIR, dir_watch_cb, &data,
					dir_watch_destroy_1);

	assert(dir_watch);
	l_fswatch_destroy(dir_watch);
	assert(!dir_watch);

	dir_watch = l_fswatch_new(TEST_DIR, dir_watch_cb, &data,
					dir_watch_destroy_2);

	assert(dir_watch);
	assert(!l_fswatch_new(TEST_FILE1, file_watch_cb, &data,
				file_watch_destroy));

	l_info("TEST_FILE_CREATE");
	state = TEST_FILE_CREATE;
	assert(close(creat(TEST_FILE1, 0600)) == 0);

	l_main_run();

	l_timeout_remove(timeout);

	l_main_exit();

	return 0;
}
