/*
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include <ell/ell.h>
#include "ell/tls-private.h"

static int load_cert_chain(const char *file, struct l_certchain **certchain)
{
	int fd;
	struct stat st;
	char *data;
	int err;

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Could not open %s: %s\n",
						file, strerror(errno));
		return -errno;
	}

	if (fstat(fd, &st) < 0) {
		err = -errno;
		fprintf(stderr, "Could not stat %s: %s\n",
						file, strerror(errno));
		goto close_file;
	}

	if (st.st_size == 0) {
		err = -EINVAL;
		fprintf(stderr, "Certificate file %s is empty!\n", file);
		goto close_file;
	}

	data = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (data == MAP_FAILED) {
		err = -errno;
		fprintf(stderr, "Could not mmap %s: %s\n",
						file, strerror(errno));
		goto close_file;
	}

	err = tls_parse_certificate_list(data, st.st_size, certchain);
	if (err < 0)
		fprintf(stderr, "Could not parse certificate list: %s\n",
						strerror(-err));

	munmap(data, st.st_size);

close_file:
	close(fd);
	return err;
}

static void usage(const char *bin)
{
	printf("%s - TLS certificate chain verification utility\n\n", bin);

	printf("Usage: %s [options] <ca_cert file> <raw certificates file>\n"
		"  <ca_cert file> - local CA Certificate to validate against\n"
		"  <raw certificates file> - Certificates obtained from PCAP\n"
		"  --help\n\n", bin);
}

int main(int argc, char *argv[])
{
	int status = EXIT_FAILURE;
	struct l_certchain *certchain;
	struct l_queue *ca_certs;
	int err;
	const char *error_str;

	if (argc != 3) {
		usage(argv[0]);
		return -1;
	}

	l_log_set_stderr();

	err = load_cert_chain(argv[2], &certchain);
	if (err < 0)
		goto done;

	if (!certchain) {
		status = EXIT_SUCCESS;
		fprintf(stdout, "Certchain is empty, nothing to do\n");
		goto done;
	}

	ca_certs = l_pem_load_certificate_list(argv[1]);
	if (!ca_certs) {
		fprintf(stderr, "Unable to load CA certifiates\n");
		goto free_certchain;
	}

	if (!l_certchain_verify(certchain, ca_certs, &error_str)) {
		fprintf(stderr, "Verification failed: %s\n", error_str);
		goto free_cacert;
	}

	fprintf(stdout, "Verification succeeded\n");
	status = EXIT_SUCCESS;

free_cacert:
	l_queue_destroy(ca_certs, (l_queue_destroy_func_t) l_cert_free);
free_certchain:
	l_certchain_free(certchain);
done:
	return status;
}
