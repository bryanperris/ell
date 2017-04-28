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

#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <assert.h>

#include <ell/ell.h>

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static void getlink_callback(int error, uint16_t type, const void *data,
						uint32_t len, void *user_data)
{
	const struct ifinfomsg *ifi = data;
	struct rtattr *rta;
	int bytes;
	char ifname[IF_NAMESIZE];
	uint32_t index, flags;

	if (error)
		goto done;

	bytes = len - NLMSG_ALIGN(sizeof(struct ifinfomsg));

	memset(ifname, 0, sizeof(ifname));

	index = ifi->ifi_index;
	flags = ifi->ifi_flags;

	for (rta = IFLA_RTA(ifi); RTA_OK(rta, bytes);
					rta = RTA_NEXT(rta, bytes)) {
		switch (rta->rta_type) {
		case IFLA_IFNAME:
			if (RTA_PAYLOAD(rta) <= IF_NAMESIZE)
				strcpy(ifname, RTA_DATA(rta));
			break;
		}
	}

	l_info("index=%d flags=0x%08x name=%s", index, flags, ifname);

done:
	l_main_quit();
}

static void link_notification(uint16_t type, void const * data,
					uint32_t len, void * user_data)
{
}

int main(int argc, char *argv[])
{
	struct l_netlink *netlink;
	struct ifinfomsg msg;
	unsigned int link_id;

	if (!l_main_init())
		return -1;

	l_log_set_stderr();

	netlink = l_netlink_new(NETLINK_ROUTE);

	l_netlink_set_debug(netlink, do_debug, "[NETLINK] ", NULL);

	memset(&msg, 0, sizeof(msg));

	l_netlink_send(netlink, RTM_GETLINK, NLM_F_DUMP, &msg, sizeof(msg),
						getlink_callback, NULL, NULL);

	link_id = l_netlink_register(netlink, RTNLGRP_LINK,
					link_notification, NULL, NULL);

	l_main_run();

	assert(l_netlink_unregister(netlink, link_id));

	l_netlink_destroy(netlink);

	l_main_exit();

	return 0;
}
