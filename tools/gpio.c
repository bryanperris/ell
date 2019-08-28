/*
 *  Embedded Linux library
 *
 *  Copyright (C) 2019 Geanix. All rights reserved.
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <ell/ell.h>

static int print_usage(void)
{
	fprintf(stderr,
		"usage: %1$s find <name>\n"
		"       %1$s get (<chip> <line>|<label>)\n"
		"       %1$s set (<chip> <line>|<label>) <value>\n"
		"       %1$s chip <chip>\n"
		"       %1$s line (<chip> <line>|<label>)\n",
		program_invocation_short_name);

	return -1;
}

static bool find_line(const char *line_label, struct l_gpio_chip **chip,
			uint32_t *offset)
{
	struct l_gpio_chip *c;
	char **chip_names = NULL;
	uint32_t o;

	if (!unlikely(line_label))
		return false;

	chip_names = l_gpio_chips_with_line_label(line_label);
	if (l_strv_length(chip_names) != 1) {
		l_strfreev(chip_names);
		return false;
	}

	c = l_gpio_chip_new(chip_names[0]);
	l_strfreev(chip_names);

	if (!c)
		return false;

	if (!l_gpio_chip_find_line_offset(c, line_label, &o)) {
		l_gpio_chip_free(c);
		return false;
	}

	if (chip)
		*chip = c;

	if (offset)
		*offset = o;

	return true;
}

static int find(int argc, char **argv)
{
	struct l_gpio_chip *chip;
	uint32_t offset;

	if (argc != 2)
		return print_usage();

	if (!find_line(argv[1], &chip, &offset))
		return -1;

	printf("chip: %s\n", l_gpio_chip_get_name(chip));
	printf("line: %u\n", offset);

	l_gpio_chip_free(chip);

	return 0;
}

static int get(int argc, char **argv)
{
	struct l_gpio_chip *chip;
	struct l_gpio_reader *reader;
	uint32_t offset;
	uint32_t value;
	bool res;

	if (argc == 2) {
		if (!find_line(argv[1], &chip, &offset))
			return -1;
	} else if (argc == 3) {
		chip = l_gpio_chip_new(argv[1]);
		if (!chip)
			return -1;

		offset = strtoul(argv[2], NULL, 0);
	} else {
		return print_usage();
	}

	printf("chip: %s\n", l_gpio_chip_get_name(chip));
	printf("line: %u\n", offset);

	reader = l_gpio_reader_new(chip, "gpio-test", 1, &offset);
	if (!reader) {
		l_gpio_chip_free(chip);
		return -1;
	}

	res = l_gpio_reader_get(reader, 1, &value);
	l_gpio_reader_free(reader);
	l_gpio_chip_free(chip);

	if (!res)
		return -1;

	printf("val:  %u\n", value);

	return 0;
}

static int set(int argc, char **argv)
{
	struct l_gpio_chip *chip;
	struct l_gpio_writer *writer;
	uint32_t offset;
	uint32_t value;
	bool res;

	if (argc == 3) {
		if (!find_line(argv[1], &chip, &offset))
			return -1;

		value = strtol(argv[2], NULL, 0);
	} else if (argc == 4) {
		chip = l_gpio_chip_new(argv[1]);
		if (!chip)
			return -1;

		offset = strtoul(argv[2], NULL, 0);
		value = strtol(argv[3], NULL, 0);
	} else {
		return print_usage();
	}

	printf("chip: %s\n", l_gpio_chip_get_name(chip));
	printf("line: %u\n", offset);

	writer = l_gpio_writer_new(chip, "gpio-test", 1, &offset, &value);
	l_gpio_chip_free(chip);

	if (!writer)
		return -1;

	res = l_gpio_writer_set(writer, 1, &value);
	l_gpio_writer_free(writer);

	if (!res)
		return -1;

	printf("val:  %u\n", value);

	return 0;
}

static int chip(int argc, char **argv)
{
	struct l_gpio_chip *chip;

	if (argc != 2)
		return print_usage();

	chip = l_gpio_chip_new(argv[1]);
	if (!chip)
		return -1;

	printf("chip:  %s\n", l_gpio_chip_get_name(chip));
	printf("label: %s\n", l_gpio_chip_get_label(chip));
	printf("lines: %u\n", l_gpio_chip_get_num_lines(chip));

	l_gpio_chip_free(chip);

	return 0;
}

static int line(int argc, char **argv)
{
	struct l_gpio_chip *chip;
	uint32_t offset;
	char *consumer;
	char *label;

	if (argc == 2) {
		if (!find_line(argv[1], &chip, &offset))
			return -1;
	} else if (argc == 3) {
		chip = l_gpio_chip_new(argv[1]);
		if (!chip)
			return -1;

		offset = strtoul(argv[2], NULL, 0);
	} else {
		return print_usage();
	}

	label = l_gpio_chip_get_line_label(chip, offset);
	consumer = l_gpio_chip_get_line_consumer(chip, offset);

	printf("chip:     %s\n", l_gpio_chip_get_name(chip));
	printf("line:     %u\n", offset);
	printf("label:    %s\n", label);
	printf("consumer: %s\n", consumer);

	l_free(consumer);
	l_free(label);
	l_gpio_chip_free(chip);

	return 0;
}

int main(int argc, char **argv)
{
	const char *cmd;

	if (argc < 2)
		return print_usage();

	cmd = argv[1];
	argc--;
	argv++;

	if (strcmp(cmd, "get") == 0)
		return get(argc, argv);
	else if (strcmp(cmd, "set") == 0)
		return set(argc, argv);
	else if (strcmp(cmd, "find") == 0)
		return find(argc, argv);
	else if (strcmp(cmd, "chip") == 0)
		return chip(argc, argv);
	else if (strcmp(cmd, "line") == 0)
		return line(argc, argv);
	else
		return print_usage();
}
