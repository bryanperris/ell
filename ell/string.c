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
#include <wchar.h>

#include "util.h"
#include "string.h"
#include "private.h"

/**
 * SECTION:string
 * @short_description: Growable string buffer
 *
 * Growable string buffer support
 */

unsigned char l_ascii_table[256] = {
	[0x00 ... 0x08] = L_ASCII_CNTRL,
	[0x09 ... 0x0D] = L_ASCII_CNTRL | L_ASCII_SPACE,
	[0x0E ... 0x1F] = L_ASCII_CNTRL,
	[0x20]		= L_ASCII_PRINT | L_ASCII_SPACE,
	[0x21 ... 0x2F] = L_ASCII_PRINT | L_ASCII_PUNCT,
	[0x30 ... 0x39] = L_ASCII_DIGIT | L_ASCII_XDIGIT | L_ASCII_PRINT,
	[0x3A ... 0x40] = L_ASCII_PRINT | L_ASCII_PUNCT,
	[0x41 ... 0x46] = L_ASCII_PRINT | L_ASCII_XDIGIT | L_ASCII_UPPER,
	[0x47 ... 0x5A] = L_ASCII_PRINT | L_ASCII_UPPER,
	[0x5B ... 0x60] = L_ASCII_PRINT | L_ASCII_PUNCT,
	[0x61 ... 0x66] = L_ASCII_PRINT | L_ASCII_XDIGIT | L_ASCII_LOWER,
	[0x67 ... 0x7A] = L_ASCII_PRINT | L_ASCII_LOWER,
	[0x7B ... 0x7E] = L_ASCII_PRINT | L_ASCII_PUNCT,
	[0x7F]		= L_ASCII_CNTRL,
	[0x80 ... 0xFF] = 0,
};

/**
 * l_string:
 *
 * Opague object representing the string buffer.
 */
struct l_string {
	size_t max;
	size_t len;
	char *str;
};

static inline size_t next_power(size_t len)
{
	size_t n = 1;

	if (len > SIZE_MAX / 2)
		return SIZE_MAX;

	while (n < len)
		n = n << 1;

	return n;
}

static void grow_string(struct l_string *str, size_t extra)
{
	if (str->len + extra < str->max)
		return;

	str->max = next_power(str->len + extra + 1);
	str->str = l_realloc(str->str, str->max);
}

/**
 * l_string_new:
 * @initial_length: Initial length of the groable string
 *
 * Create new growable string.  If the @initial_length is 0, then a safe
 * default is chosen.
 *
 * Returns: a newly allocated #l_string object.
 **/
LIB_EXPORT struct l_string *l_string_new(size_t initial_length)
{
	static const size_t DEFAULT_INITIAL_LENGTH = 127;
	struct l_string *ret;

	ret = l_new(struct l_string, 1);

	if (initial_length == 0)
		initial_length = DEFAULT_INITIAL_LENGTH;

	grow_string(ret, initial_length);
	ret->str[0] = '\0';

	return ret;
}

/**
 * l_string_free:
 * @string: growable string object
 *
 * Free the growable string object and all associated data
 **/
LIB_EXPORT void l_string_free(struct l_string *string)
{
	if (unlikely(!string))
		return;

	l_free(string->str);
	l_free(string);
}

/**
 * l_string_unwrap:
 * @string: growable string object
 *
 * Free the growable string object and return the internal string data.
 * The caller is responsible for freeing the string data using l_free(),
 * and the string object is no longer usable.
 *
 * Returns: @string's internal buffer
 **/
LIB_EXPORT char *l_string_unwrap(struct l_string *string)
{
	char *result;

	if (unlikely(!string))
		return NULL;

	result = string->str;

	l_free(string);

	return result;
}

/**
 * l_string_append:
 * @dest: growable string object
 * @src: C-style string to copy
 *
 * Appends the contents of @src to @dest.  The internal buffer of @dest is
 * grown if necessary.
 *
 * Returns: @dest
 **/
LIB_EXPORT struct l_string *l_string_append(struct l_string *dest,
						const char *src)
{
	size_t size;

	if (unlikely(!dest || !src))
		return NULL;

	size = strlen(src);

	grow_string(dest, size);

	memcpy(dest->str + dest->len, src, size);
	dest->len += size;
	dest->str[dest->len] = '\0';

	return dest;
}

/**
 * l_string_append_c:
 * @dest: growable string object
 * @c: Character
 *
 * Appends character given by @c to @dest.  The internal buffer of @dest is
 * grown if necessary.
 *
 * Returns: @dest
 **/
LIB_EXPORT struct l_string *l_string_append_c(struct l_string *dest,
						const char c)
{
	if (unlikely(!dest))
		return NULL;

	grow_string(dest, 1);
	dest->str[dest->len++] = c;
	dest->str[dest->len] = '\0';

	return dest;
}

/**
 * l_string_append_fixed:
 * @dest: growable string object
 * @src: Character array to copy from
 * @max: Maximum number of characters to copy
 *
 * Appends the contents of a fixed size string array @src to @dest.
 * The internal buffer of @dest is grown if necessary.  Up to a maximum of
 * @max characters are copied.  If a null is encountered in the first @max
 * characters, the string is copied only up to the NULL character.
 *
 * Returns: @dest
 **/
LIB_EXPORT struct l_string *l_string_append_fixed(struct l_string *dest,
							const char *src,
							size_t max)
{
	const char *nul;

	if (unlikely(!dest || !src || !max))
		return NULL;

	nul = memchr(src, 0, max);
	if (nul)
		max = nul - src;

	grow_string(dest, max);

	memcpy(dest->str + dest->len, src, max);
	dest->len += max;
	dest->str[dest->len] = '\0';

	return dest;
}

/**
 * l_string_append_vprintf:
 * @dest: growable string object
 * @format: the string format.  See the sprintf() documentation
 * @args: the parameters to insert
 *
 * Appends a formatted string to the growable string buffer.  This function
 * is equivalent to l_string_append_printf except that the arguments are
 * passed as a va_list.
 **/
LIB_EXPORT void l_string_append_vprintf(struct l_string *dest,
					const char *format, va_list args)
{
	size_t len;
	size_t have_space;
	va_list args_copy;

	if (unlikely(!dest))
		return;

	va_copy(args_copy, args);

	have_space = dest->max - dest->len;
	len = vsnprintf(dest->str + dest->len, have_space, format, args);

	if (len >= have_space) {
		grow_string(dest, len);
		len = vsprintf(dest->str + dest->len, format, args_copy);
	}

	dest->len += len;

	va_end(args_copy);
}

/**
 * l_string_append_printf:
 * @dest: growable string object
 * @format: the string format.  See the sprintf() documentation
 * @...: the parameters to insert
 *
 * Appends a formatted string to the growable string buffer, growing it as
 * necessary.
 **/
LIB_EXPORT void l_string_append_printf(struct l_string *dest,
					const char *format, ...)
{
	va_list args;

	if (unlikely(!dest))
		return;

	va_start(args, format);
	l_string_append_vprintf(dest, format, args);
	va_end(args);
}

/**
 * l_string_length:
 * @string: growable string object
 *
 * Returns: bytes used in the string.
 **/
LIB_EXPORT unsigned int l_string_length(struct l_string *string)
{
	if (unlikely(!string))
		return 0;

	return string->len;
}

LIB_EXPORT struct l_string *l_string_truncate(struct l_string *string,
							size_t new_size)
{
	if (unlikely(!string))
		return NULL;

	if (new_size >= string->len)
		return string;

	string->len = new_size;
	string->str[new_size] = '\0';

	return string;
}

static inline bool __attribute__ ((always_inline))
			valid_unicode(wchar_t c)
{
	if (c <= 0xd7ff)
		return true;

	if (c < 0xe000 || c > 0x10ffff)
		return false;

	if (c >= 0xfdd0 && c <= 0xfdef)
		return false;

	if ((c & 0xfffe) == 0xfffe)
		return false;

	return true;
}

/**
 * l_utf8_get_codepoint
 * @str: a pointer to codepoint data
 * @len: maximum bytes to read
 * @cp: destination for codepoint
 *
 * Returns: number of bytes read, or -1 for invalid coddepoint
 **/
LIB_EXPORT int l_utf8_get_codepoint(const char *str, size_t len, wchar_t *cp)
{
	static const wchar_t mins[3] = { 1 << 7, 1 << 11, 1 << 16 };
	unsigned int expect_bytes;
	wchar_t val;
	size_t i;

	if (str[0] > 0) {
		*cp = str[0];
		return 1;
	}

	expect_bytes = __builtin_clz(~(str[0] << 24));

	if (expect_bytes < 2 || expect_bytes > 4)
		goto error;

	if (expect_bytes > len)
		goto error;

	val = str[0] & (0xff >> (expect_bytes + 1));

	for (i = 1; i < expect_bytes; i++) {
		if ((str[i] & 0xc0) == 0)
			goto error;

		val <<= 6;
		val |= str[i] & 0x3f;
	}

	if (val < mins[expect_bytes - 2])
		goto error;

	if (valid_unicode(val) == false)
		goto error;

	*cp = val;
	return expect_bytes;

error:
	return -1;
}

/**
 * l_utf8_validate:
 * @str: a pointer to character data
 * @len: max bytes to validate
 * @end: return location for end of valid data
 *
 * Validates UTF-8 encoded text. If @end is non-NULL, then the end of
 * the valid range will be stored there (i.e. the start of the first
 * invalid character if some bytes were invalid, or the end of the text
 * being validated otherwise).
 *
 * Returns: Whether the text was valid UTF-8
 **/
LIB_EXPORT bool l_utf8_validate(const char *str, size_t len, const char **end)
{
	size_t pos = 0;
	int ret;
	wchar_t val;

	while (pos < len && str[pos]) {
		ret = l_utf8_get_codepoint(str + pos, len - pos, &val);

		if (ret < 0)
			goto error;

		pos += ret;
	}

error:
	if (end)
		*end = str + pos;

	if (pos != len)
		return false;

	return true;
}

/**
 * l_utf8_strlen:
 * @str: a pointer to character data
 *
 * Computes the number of UTF-8 characters (not bytes) in the string given
 * by @str.
 *
 * Returns: The number of UTF-8 characters in the string
 **/
LIB_EXPORT size_t l_utf8_strlen(const char *str)
{
	size_t l = 0;
	size_t i;
	unsigned char b;

	for (i = 0; str[i]; i++) {
		b = str[i];

		if ((b >> 6) == 2)
			l += 1;
	}

	return i - l;
}

static inline int __attribute__ ((always_inline))
			utf8_length(wchar_t c)
{
	if (c <= 0x7f)
		return 1;

	if (c <= 0x7ff)
		return 2;

	if (c <= 0xffff)
		return 3;

	return 4;
}

static inline uint16_t __attribute__ ((always_inline))
			surrogate_value(uint16_t h, uint16_t l)
{
	return 0x10000 + (h - 0xd800) * 0x400 + l - 0xdc00;
}

/*
 * Assumes c is valid unicode and out_buf contains enough space
 * Returns: number of characters written
 */
static int wchar_to_utf8(wchar_t c, char *out_buf)
{
	int len = utf8_length(c);
	int i;

	if (len == 1) {
		out_buf[0] = c;
		return 1;
	}

	for (i = len - 1; i; i--) {
		out_buf[i] = (c & 0x3f) | 0x80;
		c >>= 6;
	}

	out_buf[0] = (0xff << (8 - len)) | c;
	return len;
}

/**
 * l_utf8_from_utf16:
 * @utf16: Array of UTF16 characters
 * @utf16_size: The size of the @utf16 array in bytes.  Must be a multiple of 2.
 *
 * Returns: A newly-allocated buffer containing UTF16 encoded string converted
 * to UTF8.  The UTF8 string will always be null terminated, even if the
 * original UTF16 string was not.
 **/
LIB_EXPORT char *l_utf8_from_utf16(const void *utf16, ssize_t utf16_size)
{
	char *utf8;
	size_t utf8_len = 0;
	wchar_t high_surrogate = 0;
	ssize_t i = 0;
	uint16_t in;
	wchar_t c;

	if (unlikely(utf16_size % 2))
		return NULL;

	while (utf16_size < 0 || i < utf16_size) {
		in = L_GET_UNALIGNED((const uint16_t *) (utf16 + i));

		if (!in)
			break;

		if (in >= 0xdc00 && in < 0xe000) {
			if (high_surrogate)
				c = surrogate_value(high_surrogate, in);
			else
				return NULL;

			high_surrogate = 0;
		} else {
			if (high_surrogate)
				return NULL;

			if (in >= 0xd800 && in < 0xdc00) {
				high_surrogate = in;
				goto next;
			}

			c = in;
		}

		if (!valid_unicode(c))
			return NULL;

		utf8_len += utf8_length(c);
next:
		i += 2;
	}

	if (high_surrogate)
		return NULL;

	utf8 = l_malloc(utf8_len + 1);
	utf8_len = 0;
	i = 0;

	while (utf16_size < 0 || i < utf16_size) {
		in = L_GET_UNALIGNED((const uint16_t *) (utf16 + i));

		if (!in)
			break;

		if (in >= 0xd800 && in < 0xdc00) {
			high_surrogate = in;
			i += 2;
			in = L_GET_UNALIGNED((const uint16_t *) (utf16 + i));
			c = surrogate_value(high_surrogate, in);
		} else
			c = in;

		utf8_len += wchar_to_utf8(c, utf8 + utf8_len);
		i += 2;
	}

	utf8[utf8_len] = '\0';

	return utf8;
}

/**
 * l_utf8_to_utf16:
 * @utf8: UTF8 formatted string
 * @out_size: The size in bytes of the converted utf16 string
 *
 * Converts a UTF8 formatted string to UTF16.  It is assumed that the string
 * is valid UTF8 and no sanity checking is performed.
 *
 * Returns: A newly-allocated buffer containing UTF8 encoded string converted
 * to UTF16.  The UTF16 string will always be null terminated.
 **/
LIB_EXPORT void *l_utf8_to_utf16(const char *utf8, size_t *out_size)
{
	const char *c;
	wchar_t wc;
	int len;
	uint16_t *utf16;
	size_t n_utf16;

	if (unlikely(!utf8))
		return NULL;

	c = utf8;
	n_utf16 = 0;

	while (*c) {
		len = l_utf8_get_codepoint(c, 4, &wc);
		if (len < 0)
			return NULL;

		if (wc < 0x10000)
			n_utf16 += 1;
		else
			n_utf16 += 2;

		c += len;
	}

	utf16 = l_malloc((n_utf16 + 1) * 2);
	c = utf8;
	n_utf16 = 0;

	while (*c) {
		len = l_utf8_get_codepoint(c, 4, &wc);

		if (wc >= 0x10000) {
			utf16[n_utf16++] = (wc - 0x1000) / 0x400 + 0xd800;
			utf16[n_utf16++] = (wc - 0x1000) % 0x400 + 0xdc00;
		} else
			utf16[n_utf16++] = wc;

		c += len;
	}

	utf16[n_utf16] = 0;

	if (out_size)
		*out_size = (n_utf16 + 1) * 2;

	return utf16;
}

struct arg {
	size_t max_len;
	size_t cur_len;
	char *chars;
};

static inline void arg_init(struct arg *arg)
{
	arg->max_len = 0;
	arg->cur_len = 0;
	arg->chars = NULL;
}

static void arg_putchar(struct arg *arg, char ch)
{
	if (arg->cur_len == arg->max_len) {
		arg->max_len += 32; /* Grow by at least 32 bytes */
		arg->chars = l_realloc(arg->chars, 1 + arg->max_len);
	}

	arg->chars[arg->cur_len++] = ch;
	arg->chars[arg->cur_len] = '\0';
}

static void arg_putmem(struct arg *arg, const void *mem, size_t len)
{
	if (len == 0)
		return;

	if (arg->cur_len + len > arg->max_len) {
		size_t growby = len * 2;

		if (growby < 32)
			growby = 32;

		arg->max_len += growby;
		arg->chars = l_realloc(arg->chars, 1 + arg->max_len);
	}

	memcpy(arg->chars + arg->cur_len, mem, len);
	arg->cur_len += len;
	arg->chars[arg->cur_len] = '\0';
}

static bool parse_backslash(struct arg *arg, const char *args, size_t *pos)
{
	/* We're at the backslash, not within double quotes */
	char c = args[*pos + 1];

	switch (c) {
	case 0:
		return false;
	case '\n':
		break;
	default:
		arg_putchar(arg, c);
		break;
	}

	*pos += 1;
	return true;
}

static bool parse_quoted_backslash(struct arg *arg,
						const char *args, size_t *pos)
{
	/* We're at the backslash, within double quotes */
	char c = args[*pos + 1];

	switch (c) {
	case 0:
		return false;
	case '\n':
		break;
	case '"':
	case '\\':
		arg_putchar(arg, c);
		break;
	default:
		arg_putchar(arg, '\\');
		arg_putchar(arg, c);
		break;
	}

	*pos += 1;
	return true;
}

static bool parse_single_quote(struct arg *arg, const char *args, size_t *pos)
{
	/* We're just past the single quote */
	size_t start = *pos;

	for (; args[*pos]; *pos += 1) {
		if (args[*pos] != '\'')
			continue;

		arg_putmem(arg, args + start, *pos - start);
		return true;
	}

	/* Unterminated ' */
	return false;
}

static bool parse_double_quote(struct arg *arg, const char *args, size_t *pos)
{
	/* We're just past the double quote */
	for (; args[*pos]; *pos += 1) {
		char c = args[*pos];

		switch (c) {
		case '"':
			return true;
		case '\\':
			if (!parse_quoted_backslash(arg, args, pos))
				return false;

			break;
		default:
			arg_putchar(arg, c);
			break;
		}
	}

	/* Unterminated */
	return false;
}

static void add_arg(char ***args, char *arg, int *n_args)
{
	*args = l_realloc(*args, sizeof(char *) * (2 + *n_args));
	(*args)[*n_args] = arg;
	(*args)[*n_args + 1] = NULL;

	*n_args += 1;
}

LIB_EXPORT char **l_parse_args(const char *args, int *out_n_args)
{
	size_t i;
	struct arg arg;
	char **ret = l_realloc(NULL, sizeof(char *));
	int n_args = 0;

	ret[0] = NULL;
	arg_init(&arg);

	for (i = 0; args[i]; i++) {
		switch (args[i]) {
		case '\\':
			if (!parse_backslash(&arg, args, &i))
				goto error;
			break;
		case '"':
			i += 1;
			if (!parse_double_quote(&arg, args, &i))
				goto error;

			/* Add an empty string */
			if (!arg.cur_len)
				add_arg(&ret, l_strdup(""), &n_args);

			break;
		case '\'':
			i += 1;
			if (!parse_single_quote(&arg, args, &i))
				goto error;

			/* Add an empty string */
			if (!arg.cur_len)
				add_arg(&ret, l_strdup(""), &n_args);

			break;
		default:
			if (!strchr(" \t", args[i])) {
				if (args[i] == '\n')
					goto error;

				arg_putchar(&arg, args[i]);
				continue;
			}

			if (arg.cur_len)
				add_arg(&ret, arg.chars, &n_args);

			arg_init(&arg);
			break;
		}
	}

	if (arg.cur_len)
		add_arg(&ret, arg.chars, &n_args);

	if (out_n_args)
		*out_n_args = n_args;

	return ret;

error:
	l_free(arg.chars);
	l_strfreev(ret);
	return NULL;
}
