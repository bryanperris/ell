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

#include <stdio.h>

#include "settings.h"
#include "util.h"
#include "string.h"
#include "private.h"

struct l_settings {
	l_settings_debug_cb_t debug_handler;
	l_settings_destroy_cb_t debug_destroy;
	void *debug_data;
};

static inline void __attribute__ ((always_inline))
			debug(struct l_settings *settings, const char *message)
{
	if (!settings->debug_handler)
		return;

	settings->debug_handler(message, settings->debug_data);
}

LIB_EXPORT struct l_settings *l_settings_new(void)
{
	struct l_settings *ret;

	ret = l_new(struct l_settings, 1);

	return ret;
}

LIB_EXPORT void l_settings_free(struct l_settings *settings)
{
	if (settings->debug_destroy)
		settings->debug_destroy(settings->debug_data);

	l_free(settings);
}

static bool parse_group(struct l_settings *settings, const char *data,
			size_t len, size_t line)
{
	size_t i = 1;
	size_t end;
	char buf[128];

	while (i < len && data[i] != ']') {
		if (l_ascii_isprint(data[i]) == false || data[i] == '[') {
			sprintf(buf, "Invalid group name at line %zd", line);
			debug(settings, buf);

			return false;
		}

		i += 1;
	}

	if (i >= len) {
		sprintf(buf, "Unterminated group name at line %zd", line);
		debug(settings, buf);

		return false;
	}

	end = i;
	i += 1;

	while (i < len && l_ascii_isblank(data[i]))
		i += 1;

	if (i != len) {
		sprintf(buf, "Junk characters at the end of line %zd", line);
		debug(settings, buf);

		return false;
	}

	sprintf(buf, "Found group: [%.*s]", (int) (end - 1), data + 1);
	debug(settings, buf);

	return true;
}

static bool parse_key(struct l_settings *settings, const char *data,
			size_t len, size_t line)
{
	unsigned int i;
	char buf[128];
	unsigned int end;

	for (i = 0; i < len; i++) {
		if (l_ascii_isalnum(data[i]))
			continue;

		if (data[i] == '_' || data[i] == '-')
			continue;

		if (l_ascii_isblank(data[i]))
			break;

		sprintf(buf, "Invalid character in Key on line %zd", line);
		debug(settings, buf);

		return false;
	}

	end = i;

	/* Make sure the rest of the characters are blanks */
	while (i < len) {
		if (l_ascii_isblank(data[i++]))
			continue;

		sprintf(buf, "Garbage after Key on line %zd", line);
		debug(settings, buf);

		return false;
	}

	sprintf(buf, "Found Key: '%.*s'", end, data);
	debug(settings, buf);

	return true;
}

static bool parse_value(struct l_settings *settings, const char *data,
			size_t len, size_t line)
{
	unsigned int end = len;
	char buf[128];

	sprintf(buf, "Found Value: '%.*s'", end, data);
	debug(settings, buf);

	return true;
}

static bool parse_keyvalue(struct l_settings *settings, const char *data,
				size_t len, size_t line)
{
	char buf[128];
	const char *equal = memchr(data, '=', len);
	int i;

	if (equal == NULL) {
		sprintf(buf, "Delimiter '=' not found on line: %zd", line);
		debug(settings, buf);

		return false;
	}

	if (equal == data) {
		sprintf(buf, "Empty key on line: %zd", line);
		debug(settings, buf);

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

		if (eol == NULL)
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
	return true;
}

LIB_EXPORT bool l_settings_set_debug(struct l_settings *settings,
					l_settings_debug_cb_t callback,
					void *user_data,
					l_settings_destroy_cb_t destroy)
{
	if (!settings)
		return false;

	if (settings->debug_destroy)
		settings->debug_destroy(settings->debug_data);

	settings->debug_handler = callback;
	settings->debug_destroy = destroy;
	settings->debug_data = user_data;

	return true;
}
