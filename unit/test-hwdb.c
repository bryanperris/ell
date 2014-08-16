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

#include <ell/ell.h>

static void print_modalias(struct l_hwdb *hwdb, const char *modalias)
{
	struct l_hwdb_entry *entries, *entry;

	printf("%s\n", modalias);

	entries = l_hwdb_lookup(hwdb, modalias);

	for (entry = entries; entry; entry = entry->next)
		printf(" %s=%s\n", entry->key, entry->value);

	l_hwdb_lookup_free(entries);

	printf("\n");
}

int main(int argc, char *argv[])
{
	struct l_hwdb *hwdb;

	hwdb = l_hwdb_new_default();
	if (!hwdb)
		return 0;

	/* Bluetooth Interest Group Inc. */
	print_modalias(hwdb, "OUI:000F79");

	/* Bluetooth SIG, Inc. */
	print_modalias(hwdb, "bluetooth:v003F");

	/* Nike+ FuelBand */
	print_modalias(hwdb, "bluetooth:v0078p0001");

	/* Bluetooth Type-A standard interface */
	print_modalias(hwdb, "sdio:c02");

	l_hwdb_unref(hwdb);

	return 0;
}
