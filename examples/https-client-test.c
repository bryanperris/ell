/*
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

#include <ell/ell.h>

static struct l_io *io;
static struct l_tls *tls;
static const char *hostname;

static void https_io_disconnect(struct l_io *io, void *user_data)
{
	l_main_quit();
}

static bool https_io_read(struct l_io *io, void *user_data)
{
	uint8_t buf[2048];
	int l;

	l = read(l_io_get_fd(io), buf, sizeof(buf));
	if (l == 0)
		l_main_quit();
	else if (l > 0)
		l_tls_handle_rx(tls, buf, l);

	return true;
}

static void https_tls_disconnected(enum l_tls_alert_desc reason, bool remote,
					void *user_data)
{
	if (reason)
		printf("TLS error: %s\n", l_tls_alert_to_str(reason));
	l_main_quit();
}

static void https_new_data(const uint8_t *data, size_t len, void *user_data)
{
	int r;

	while (len) {
		r = write(1, data, len);
		if (r < 0) {
			l_main_quit();
			break;
		}
		len -= r;
		data += r;
	}
}

static void https_tls_write(const uint8_t *data, size_t len, void *user_data)
{
	int r;

	while (len) {
		r = write(l_io_get_fd(io), data, len);
		if (r < 0) {
			l_main_quit();
			break;
		}
		len -= r;
		data += r;
	}
}

static void https_tls_ready(const char *peer_identity, void *user_data)
{
	uint8_t buf[2048];
	int l;

	if (peer_identity)
		printf("Server authenticated as %s\n", peer_identity);
	else
		printf("Server not authenticated\n");

	l = snprintf((char *) buf, sizeof(buf),
			"HEAD / HTTP/1.1\r\n"
			"Connection: close\r\n"
			"Host: %s\r\n\r\n", hostname);
	l_tls_write(tls, buf, l);
}

static void https_tls_debug_cb(const char *str, void *user_data)
{
	l_info("%s", str);
}

int main(int argc, char *argv[])
{
	struct hostent *he;
	struct in_addr **addr_list;
	struct sockaddr_in addr;
	int fd;
	bool auth_ok = true;

	if (argc != 2 && argc != 3 && argc != 6) {
		printf("Usage: %s <https-host-name> [<ca-cert-path> "
				"[<client-cert-path> <client-key-path> "
				"<client-key-passphrase>]]\n"
				"Note: The passphrase will be ignored if the "
				"key is not encrypted.\n",
				argv[0]);
		return -1;
	}

	l_log_set_stderr();

	hostname = argv[1];
	he = gethostbyname(hostname);
	if (!he) {
		printf("gethostbyname: %s\n", strerror(errno));
		return -1;
	}

	addr_list = (struct in_addr **) he->h_addr_list;
	if (!addr_list) {
		printf("No host addresses found\n");
		return -1;
	}

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		printf("socket: %s\n", strerror(errno));
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(443);
	memcpy(&addr.sin_addr, addr_list[0], sizeof(addr.sin_addr));
	if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		printf("connect: %s\n", strerror(errno));
		return -1;
	}

	if (!l_main_init())
		return -1;

	io = l_io_new(fd);
	l_io_set_close_on_destroy(io, true);
	l_io_set_read_handler(io, https_io_read, tls, NULL);
	l_io_set_disconnect_handler(io, https_io_disconnect, tls, NULL);

	tls = l_tls_new(false, https_new_data, https_tls_write,
			https_tls_ready, https_tls_disconnected, NULL);

	if (getenv("TLS_DEBUG"))
		l_tls_set_debug(tls, https_tls_debug_cb, NULL, NULL);

	if (argc > 2)
		l_tls_set_cacert(tls, argv[2]);
	if (argc > 5)
		auth_ok = l_tls_set_auth_data(tls, argv[3], argv[4], argv[5]);

	if (tls && auth_ok)
		l_main_run();

	l_io_destroy(io);
	l_tls_free(tls);

	l_main_exit();

	return 0;
}
