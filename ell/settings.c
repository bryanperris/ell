/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2011-2012  Intel Corporation. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "util.h"
#include "string.h"
#include "queue.h"
#include "settings.h"
#include "private.h"

struct setting_data {
	char *key;
	char *value;
};

struct group_data {
	char *name;
	struct l_queue *settings;
};

struct l_settings {
	l_settings_debug_cb_t debug_handler;
	l_settings_destroy_cb_t debug_destroy;
	void *debug_data;
	struct l_queue *groups;
};

static void setting_destroy(void *data)
{
	struct setting_data *pair = data;

	l_free(pair->key);
	l_free(pair->value);
	l_free(pair);
}

static void group_destroy(void *data)
{
	struct group_data *group = data;

	l_free(group->name);
	l_queue_destroy(group->settings, setting_destroy);

	l_free(group);
}

LIB_EXPORT struct l_settings *l_settings_new(void)
{
	struct l_settings *settings;

	settings = l_new(struct l_settings, 1);
	settings->groups = l_queue_new();

	return settings;
}

LIB_EXPORT void l_settings_free(struct l_settings *settings)
{
	if (unlikely(!settings))
		return;

	if (settings->debug_destroy)
		settings->debug_destroy(settings->debug_data);

	l_queue_destroy(settings->groups, group_destroy);

	l_free(settings);
}

static char *unescape_value(const char *value)
{
	char *ret;
	char *n;
	const char *o;

	ret = l_new(char, strlen(value) + 1);

	for (n = ret, o = value; *o; o++, n++) {
		if (*o != '\\') {
			*n = *o;
			continue;
		}

		o += 1;

		switch (*o) {
		case 's':
			*n = ' ';
			break;
		case 'n':
			*n = '\n';
			break;
		case 't':
			*n = '\t';
			break;
		case 'r':
			*n = '\r';
			break;
		case '\\':
			*n = '\\';
			break;
		default:
			l_free(ret);
			return NULL;
		}
	}

	return ret;
}

static bool parse_group(struct l_settings *settings, const char *data,
			size_t len, size_t line)
{
	size_t i = 1;
	size_t end;
	struct group_data *group;

	while (i < len && data[i] != ']') {
		if (l_ascii_isprint(data[i]) == false || data[i] == '[') {
			l_util_debug(settings->debug_handler,
					settings->debug_data,
					"Invalid group name at line %zd", line);
			return false;
		}

		i += 1;
	}

	if (i >= len) {
		l_util_debug(settings->debug_handler, settings->debug_data,
				"Unterminated group name at line %zd", line);
		return false;
	}

	end = i;
	i += 1;

	while (i < len && l_ascii_isblank(data[i]))
		i += 1;

	if (i != len) {
		l_util_debug(settings->debug_handler, settings->debug_data,
				"Junk characters at the end of line %zd", line);
		return false;
	}

	l_util_debug(settings->debug_handler, settings->debug_data,
			"Found group: [%.*s]", (int) (end - 1), data + 1);

	group = l_new(struct group_data, 1);
	group->name = l_strndup(data + 1, end - 1);
	group->settings = l_queue_new();

	l_queue_push_head(settings->groups, group);

	return true;
}

static unsigned int parse_key(struct l_settings *settings, const char *data,
				size_t len, size_t line)
{
	unsigned int i;
	unsigned int end;
	struct group_data *group;
	struct setting_data *pair;

	for (i = 0; i < len; i++) {
		if (l_ascii_isalnum(data[i]))
			continue;

		if (data[i] == '_' || data[i] == '-')
			continue;

		if (l_ascii_isblank(data[i]))
			break;

		l_util_debug(settings->debug_handler, settings->debug_data,
				"Invalid character in Key on line %zd", line);

		return 0;
	}

	end = i;

	/* Make sure the rest of the characters are blanks */
	while (i < len) {
		if (l_ascii_isblank(data[i++]))
			continue;

		l_util_debug(settings->debug_handler, settings->debug_data,
					"Garbage after Key on line %zd", line);

		return 0;
	}

	l_util_debug(settings->debug_handler, settings->debug_data,
					"Found Key: '%.*s'", end, data);

	group = l_queue_peek_head(settings->groups);
	pair = l_new(struct setting_data, 1);
	pair->key = l_strndup(data, end);
	l_queue_push_head(group->settings, pair);

	return end;
}

static bool parse_value(struct l_settings *settings, const char *data,
			size_t len, size_t line)
{
	unsigned int end = len;
	struct group_data *group;
	struct setting_data *pair;

	group = l_queue_peek_head(settings->groups);

	if (!l_utf8_validate(data, len, NULL)) {
		l_util_debug(settings->debug_handler, settings->debug_data,
				"Invalid UTF8 in value on line: %zd", line);

		pair = l_queue_pop_head(group->settings);
		l_free(pair->key);
		l_free(pair);

		return false;
	}

	l_util_debug(settings->debug_handler, settings->debug_data,
					"Found Value: '%.*s'", end, data);

	pair = l_queue_peek_head(group->settings);
	pair->value = l_strndup(data, end);

	return true;
}

static bool parse_keyvalue(struct l_settings *settings, const char *data,
				size_t len, size_t line)
{
	const char *equal = memchr(data, '=', len);

	if (!equal) {
		l_util_debug(settings->debug_handler, settings->debug_data,
				"Delimiter '=' not found on line: %zd", line);
		return false;
	}

	if (equal == data) {
		l_util_debug(settings->debug_handler, settings->debug_data,
					"Empty key on line: %zd", line);
		return false;
	}

	if (parse_key(settings, data, equal - data, line) == false)
		return false;

	equal += 1;
	while (equal < data + len && l_ascii_isblank(*equal))
		equal += 1;

	return parse_value(settings, equal, len - (equal - data), line);
}

LIB_EXPORT bool l_settings_load_from_data(struct l_settings *settings,
						const char *data, size_t len)
{
	size_t pos = 0;
	bool r = true;
	const char *eol;
	size_t line = 1;
	size_t line_len;

	if (unlikely(!settings || !data || !len))
		return false;

	while (pos < len && r) {
		if (l_ascii_isblank(data[pos])) {
			pos += 1;
			continue;
		}

		if (data[pos] == '\n') {
			line += 1;
			pos += 1;
			continue;
		}

		eol = memchr(data + pos, '\n', len - pos);
		if (!eol)
			eol = data + len;

		line_len = eol - data - pos;

		if (data[pos] == '[')
			r = parse_group(settings, data + pos, line_len, line);
		else if (data[pos] != '#')
			r = parse_keyvalue(settings, data + pos, line_len,
						line);

		pos += line_len;
	}

	return r;
}

LIB_EXPORT bool l_settings_load_from_file(struct l_settings *settings,
						const char *filename)
{
	int fd;
	struct stat st;
	char *data;
	bool r;

	if (unlikely(!settings || !filename))
		return false;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		l_util_debug(settings->debug_handler, settings->debug_data,
				"Could not open %s (%s)", filename,
				strerror(errno));
		return false;
	}

	if (fstat(fd, &st) < 0) {
		l_util_debug(settings->debug_handler, settings->debug_data,
				"Could not stat %s (%s)", filename,
				strerror(errno));
		close(fd);

		return false;
	}

	data = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (data == MAP_FAILED) {
		l_util_debug(settings->debug_handler, settings->debug_data,
				"Could not mmap %s (%s)", filename,
				strerror(errno));
		close(fd);

		return false;
	}

	r = l_settings_load_from_data(settings, data, st.st_size);

	munmap(data, st.st_size);
	close(fd);

	return r;
}

LIB_EXPORT bool l_settings_set_debug(struct l_settings *settings,
					l_settings_debug_cb_t callback,
					void *user_data,
					l_settings_destroy_cb_t destroy)
{
	if (unlikely(!settings))
		return false;

	if (settings->debug_destroy)
		settings->debug_destroy(settings->debug_data);

	settings->debug_handler = callback;
	settings->debug_destroy = destroy;
	settings->debug_data = user_data;

	return true;
}

static bool group_match(const void *a, const void *b)
{
	const struct group_data *group = a;
	const char *name = b;

	return !strcmp(group->name, name);
}

LIB_EXPORT bool l_settings_has_group(struct l_settings *settings,
					const char *group_name)
{
	struct group_data *group;

	if (unlikely(!settings))
		return false;

	group = l_queue_find(settings->groups, group_match, group_name);

	return group != NULL;
}

static bool key_match(const void *a, const void *b)
{
	const struct setting_data *setting = a;
	const char *key = b;

	return !strcmp(setting->key, key);
}

LIB_EXPORT bool l_settings_has_key(struct l_settings *settings,
					const char *group_name, const char *key)
{
	struct group_data *group;
	struct setting_data *setting;

	if (unlikely(!settings))
		return false;

	group = l_queue_find(settings->groups, group_match, group_name);

	if (!group)
		return false;

	setting = l_queue_find(group->settings, key_match, key);

	return setting != NULL;
}

LIB_EXPORT const char *l_settings_get_value(struct l_settings *settings,
						const char *group_name,
						const char *key)
{
	struct group_data *group;
	struct setting_data *setting;

	if (unlikely(!settings))
		return NULL;

	group = l_queue_find(settings->groups, group_match, group_name);

	if (!group)
		return NULL;

	setting = l_queue_find(group->settings, key_match, key);

	if (setting == NULL)
		return NULL;

	return setting->value;
}

LIB_EXPORT bool l_settings_set_value(struct l_settings *settings,
					const char *group_name, const char *key,
					const char *value)
{
	if (unlikely(!settings))
		return false;

	return true;
}

LIB_EXPORT bool l_settings_get_bool(struct l_settings *settings,
					const char *group_name, const char *key,
					bool *out)
{
	const char *value = l_settings_get_value(settings, group_name, key);

	if (!value)
		return false;

	if (!strcasecmp(value, "true") || !strcmp(value, "1")) {
		if (out)
			*out = true;

		return true;
	}

	if (!strcasecmp(value, "false") || !strcmp(value, "0")) {
		if (out)
			*out = false;

		return true;
	}

	l_util_debug(settings->debug_handler, settings->debug_data,
			"Could not interpret %s as a bool", value);

	return false;
}

LIB_EXPORT bool l_settings_set_bool(struct l_settings *settings,
					const char *group_name, const char *key,
					bool in)
{
	static const char *true_str = "true";
	static const char *false_str = "false";
	const char *v;

	if (in == false)
		v = false_str;
	else
		v = true_str;

	return l_settings_set_value(settings, group_name, key, v);
}

LIB_EXPORT bool l_settings_get_int(struct l_settings *settings,
					const char *group_name,
					const char *key, int *out)
{
	const char *value = l_settings_get_value(settings, group_name, key);
	long int r;
	int t;
	char *endp;

	if (!value)
		return false;

	if (*value == '\0')
		goto error;

	errno = 0;

	t = r = strtol(value, &endp, 10);
	if (*endp != '\0')
		goto error;

	if (unlikely(errno == ERANGE || r != t))
		goto error;

	if (out)
		*out = r;

	return true;

error:
	l_util_debug(settings->debug_handler, settings->debug_data,
			"Could not interpret %s as an int", value);

	return false;
}

LIB_EXPORT bool l_settings_set_int(struct l_settings *settings,
					const char *group_name, const char *key,
					int in)
{
	char buf[64];

	snprintf(buf, sizeof(buf), "%d", in);

	return l_settings_set_value(settings, group_name, key, buf);
}

LIB_EXPORT bool l_settings_get_uint(struct l_settings *settings,
					const char *group_name, const char *key,
					unsigned int *out)
{
	const char *value = l_settings_get_value(settings, group_name, key);
	unsigned long int r;
	unsigned int t;
	char *endp;

	if (!value)
		return false;

	if (*value == '\0')
		goto error;

	errno = 0;

	t = r = strtoul(value, &endp, 10);
	if (*endp != '\0')
		goto error;

	if (unlikely(errno == ERANGE || r != t))
		goto error;

	if (out)
		*out = r;

	return true;

error:
	l_util_debug(settings->debug_handler, settings->debug_data,
			"Could not interpret %s as a uint", value);

	return false;
}

LIB_EXPORT bool l_settings_set_uint(struct l_settings *settings,
					const char *group_name, const char *key,
					unsigned int in)
{
	char buf[64];

	snprintf(buf, sizeof(buf), "%u", in);

	return l_settings_set_value(settings, group_name, key, buf);
}

LIB_EXPORT bool l_settings_get_int64(struct l_settings *settings,
					const char *group_name, const char *key,
					int64_t *out)
{
	const char *value = l_settings_get_value(settings, group_name, key);
	int64_t r;
	char *endp;

	if (!value)
		return false;

	if (*value == '\0')
		goto error;

	errno = 0;

	r = strtoll(value, &endp, 10);
	if (*endp != '\0')
		goto error;

	if (unlikely(errno == ERANGE))
		goto error;

	if (out)
		*out = r;

	return true;

error:
	l_util_debug(settings->debug_handler, settings->debug_data,
			"Could not interpret %s as an int64", value);

	return false;
}

LIB_EXPORT bool l_settings_set_int64(struct l_settings *settings,
					const char *group_name, const char *key,
					int64_t in)
{
	char buf[64];

	snprintf(buf, sizeof(buf), "%" PRId64, in);

	return l_settings_set_value(settings, group_name, key, buf);
}

LIB_EXPORT bool l_settings_get_uint64(struct l_settings *settings,
					const char *group_name, const char *key,
					uint64_t *out)
{
	const char *value = l_settings_get_value(settings, group_name, key);
	uint64_t r;
	char *endp;

	if (!value)
		return false;

	if (*value == '\0')
		goto error;

	errno = 0;

	r = strtoull(value, &endp, 10);
	if (*endp != '\0')
		goto error;

	if (unlikely(errno == ERANGE))
		goto error;

	if (out)
		*out = r;

	return true;

error:
	l_util_debug(settings->debug_handler, settings->debug_data,
			"Could not interpret %s as a uint64", value);

	return false;
}

LIB_EXPORT bool l_settings_set_uint64(struct l_settings *settings,
					const char *group_name, const char *key,
					uint64_t in)
{
	char buf[64];

	snprintf(buf, sizeof(buf), "%" PRIu64, in);

	return l_settings_set_value(settings, group_name, key, buf);
}

LIB_EXPORT char *l_settings_get_string(struct l_settings *settings,
					const char *group_name, const char *key)
{
	const char *value = l_settings_get_value(settings, group_name, key);

	if (!value)
		return NULL;

	return unescape_value(value);
}

LIB_EXPORT char **l_settings_get_string_list(struct l_settings *settings,
						const char *group_name,
						const char *key,
						const char delimiter)
{
	const char *value = l_settings_get_value(settings, group_name, key);
	char *str;
	char **ret;

	if (!value)
		return NULL;

	str = unescape_value(value);
	if (str == NULL)
		return NULL;

	ret = l_strsplit(str, delimiter);
	l_free(str);

	return ret;
}

LIB_EXPORT bool l_settings_get_double(struct l_settings *settings,
					const char *group_name, const char *key,
					double *out)
{
	const char *value = l_settings_get_value(settings, group_name, key);
	char *endp;
	double r;

	if (!value)
		return NULL;

	if (*value == '\0')
		goto error;

	errno = 0;

	r = strtod(value, &endp);
	if (*endp != '\0')
		goto error;

	if (unlikely(errno == ERANGE))
		goto error;

	if (out)
		*out = r;

	return true;

error:
	l_util_debug(settings->debug_handler, settings->debug_data,
			"Could not interpret %s as a double", value);

	return false;
}

LIB_EXPORT bool l_settings_set_double(struct l_settings *settings,
					const char *group_name, const char *key,
					double in)
{
	L_AUTO_CLEANUP_VAR(char *, buf, l_free);

	buf = l_strdup_printf("%d", in);

	return l_settings_set_value(settings, group_name, key, buf);
}

LIB_EXPORT bool l_settings_get_float(struct l_settings *settings,
					const char *group_name, const char *key,
					float *out)
{
	const char *value = l_settings_get_value(settings, group_name, key);
	char *endp;
	float r;

	if (!value)
		return NULL;

	if (*value == '\0')
		goto error;

	errno = 0;

	r = strtof(value, &endp);
	if (*endp != '\0')
		goto error;

	if (unlikely(errno == ERANGE))
		goto error;

	if (out)
		*out = r;

	return true;

error:
	l_util_debug(settings->debug_handler, settings->debug_data,
			"Could not interpret %s as a float", value);

	return false;
}

LIB_EXPORT bool l_settings_set_float(struct l_settings *settings,
					const char *group_name, const char *key,
					float in)
{
	L_AUTO_CLEANUP_VAR(char *, buf, l_free);

	buf = l_strdup_printf("%f", in);

	return l_settings_set_value(settings, group_name, key, buf);
}
