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

#ifndef __ELL_SETTINGS_H
#define __ELL_SETTINGS_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct l_settings;

typedef void (*l_settings_debug_cb_t) (const char *str, void *user_data);
typedef void (*l_settings_destroy_cb_t) (void *user_data);

struct l_settings *l_settings_new(void);
void l_settings_free(struct l_settings *settings);

bool l_settings_load_from_data(struct l_settings *settings,
						const char *data, size_t len);
bool l_settings_load_from_file(struct l_settings *settings, const char *filename);

bool l_settings_set_debug(struct l_settings *settings,
				l_settings_debug_cb_t callback,
				void *user_data,
				l_settings_destroy_cb_t destroy);
#ifdef __cplusplus
}
#endif

#endif /* __ELL_SETTINGS_H */
