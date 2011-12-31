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

#include "util.h"
#include "string.h"
#include "settings.h"
#include "private.h"

struct l_settings {
	l_settings_debug_cb_t debug_handler;
	l_settings_destroy_cb_t debug_destroy;
	void *debug_data;
};

LIB_EXPORT struct l_settings *l_settings_new(void)
{
	struct l_settings *settings;

	settings = l_new(struct l_settings, 1);

	return settings;
}

LIB_EXPORT void l_settings_free(struct l_settings *settings)
{
	if (unlikely(!settings))
		return;

	if (settings->debug_destroy)
		settings->debug_destroy(settings->debug_data);

	l_free(settings);
}

static bool parse_group(struct l_settings *settings, const char *data,
			size_t len, size_t line)
{
	size_t i = 1;
	size_t end;

	while (i < len && data[i] != ']') {
		if (l_ascii_isprint(data[i]) == false || data[i] == '[') {
			l_util_debug(settings->debug_handler, settings->debug_data,
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

	return true;
}

static bool parse_key(struct l_settings *settings, const char *data,
			size_t len, size_t line)
{
	unsigned int i;
	unsigned int end;

	for (i = 0; i < len; i++) {
		if (l_ascii_isalnum(data[i]))
			continue;

		if (data[i] == '_' || data[i] == '-')
			continue;

		if (l_ascii_isblank(data[i]))
			break;

		l_util_debug(settings->debug_handler, settings->debug_data,
				"Invalid character in Key on line %zd", line);

		return false;
	}

	end = i;

	/* Make sure the rest of the characters are blanks */
	while (i < len) {
		if (l_ascii_isblank(data[i++]))
			continue;

		l_util_debug(settings->debug_handler, settings->debug_data,
					"Garbage after Key on line %zd", line);

		return false;
	}

	l_util_debug(settings->debug_handler, settings->debug_data,
					"Found Key: '%.*s'", end, data);

	return true;
}

static bool parse_value(struct l_settings *settings, const char *data,
			size_t len, size_t line)
{
	unsigned int end = len;

	l_util_debug(settings->debug_handler, settings->debug_data,
					"Found Value: '%.*s'", end, data);

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
	if (unlikely(!settings || !filename))
		return false;

	return true;
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
