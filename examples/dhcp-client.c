/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
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

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <sys/socket.h>
#include <linux/if_arp.h>

#include <ell/ell.h>

static void signal_handler(struct l_signal *signal, uint32_t signo,
							void *user_data)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		l_info("Terminate");
		l_main_quit();
		break;
	}
}

static void event_handler(struct l_dhcp_client *client,
					enum l_dhcp_client_event event,
					void *userdata)
{
	const struct l_dhcp_lease *lease = l_dhcp_client_get_lease(client);
	char *ip = l_dhcp_lease_get_address(lease);
	char *netmask = l_dhcp_lease_get_netmask(lease);
	char *gw = l_dhcp_lease_get_gateway(lease);
	uint32_t lifetime = l_dhcp_lease_get_lifetime(lease);

	l_info("Lease Obtained:");
	l_info("\tIP: %s, Netmask: %s, Gateway: %s", ip, netmask, gw);
	l_info("Lifetime: %u seconds", lifetime);

	l_free(ip);
	l_free(netmask);
	l_free(gw);
}

int main(int argc, char *argv[])
{
	struct l_dhcp_client *client;
	struct l_signal *signal;
	sigset_t mask;
	int ifindex;
	uint8_t mac[6];

	if (argc < 2) {
                printf("Usage: %s <interface index>\n", argv[0]);
                exit(0);
        }

	ifindex = atoi(argv[1]);

	if (!l_net_get_mac_address(ifindex, mac)) {
		printf("Unable to get address from interface %d\n", ifindex);
		exit(0);
	}

	if (!l_main_init())
		return -1;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	signal = l_signal_create(&mask, signal_handler, NULL, NULL);

	l_log_set_stderr();
	l_debug_enable("*");

	client = l_dhcp_client_new(ifindex);
	l_dhcp_client_set_address(client, ARPHRD_ETHER, mac, 6);
	l_dhcp_client_set_event_handler(client, event_handler, NULL, NULL);
	l_dhcp_client_start(client);

	l_main_run();

	l_dhcp_client_destroy(client);
	l_signal_remove(signal);
	l_main_exit();

	return 0;
}
