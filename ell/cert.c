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

#include <string.h>
#include <stdio.h>

#include "private.h"
#include "key.h"
#include "queue.h"
#include "asn1-private.h"
#include "cert.h"
#include "cert-private.h"

#define X509_CERTIFICATE_POS			0
#define   X509_TBSCERTIFICATE_POS		  0
#define     X509_TBSCERT_VERSION_POS		    ASN1_CONTEXT_EXPLICIT(0)
#define     X509_TBSCERT_SERIAL_POS		    0
#define     X509_TBSCERT_SIGNATURE_POS		    1
#define       X509_ALGORITHM_ID_ALGORITHM_POS	      0
#define       X509_ALGORITHM_ID_PARAMS_POS	      1
#define     X509_TBSCERT_ISSUER_DN_POS		    2
#define     X509_TBSCERT_VALIDITY_POS		    3
#define     X509_TBSCERT_SUBJECT_DN_POS		    4
#define     X509_TBSCERT_SUBJECT_KEY_POS	    5
#define       X509_SUBJECT_KEY_ALGORITHM_POS	      0
#define       X509_SUBJECT_KEY_VALUE_POS	      1
#define     X509_TBSCERT_ISSUER_UID_POS		    ASN1_CONTEXT_IMPLICIT(1)
#define     X509_TBSCERT_SUBJECT_UID_POS	    ASN1_CONTEXT_IMPLICIT(2)
#define     X509_TBSCERT_EXTENSIONS_POS		    ASN1_CONTEXT_EXPLICIT(3)
#define   X509_SIGNATURE_ALGORITHM_POS		  1
#define   X509_SIGNATURE_VALUE_POS		  2

struct l_cert {
	enum l_cert_key_type pubkey_type;
	struct l_cert *issuer;
	struct l_cert *issued;
	size_t asn1_len;
	uint8_t asn1[0];
};

struct l_certchain {
	struct l_cert *leaf;	/* Bottom of the doubly-linked list */
	struct l_cert *ca;	/* Top of the doubly-linked list */
};

static const struct pkcs1_encryption_oid {
	enum l_cert_key_type key_type;
	struct asn1_oid oid;
} pkcs1_encryption_oids[] = {
	{ /* rsaEncryption */
		L_CERT_KEY_RSA,
		{ 9, { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 } },
	},
};

static bool cert_set_pubkey_type(struct l_cert *cert)
{
	const uint8_t *key_type;
	size_t key_type_len;
	int i;

	key_type = asn1_der_find_elem_by_path(cert->asn1, cert->asn1_len,
						ASN1_ID_OID, &key_type_len,
						X509_CERTIFICATE_POS,
						X509_TBSCERTIFICATE_POS,
						X509_TBSCERT_SUBJECT_KEY_POS,
						X509_SUBJECT_KEY_ALGORITHM_POS,
						X509_ALGORITHM_ID_ALGORITHM_POS,
						-1);
	if (!key_type)
		return false;

	for (i = 0; i < (int) L_ARRAY_SIZE(pkcs1_encryption_oids); i++)
		if (asn1_oid_eq(&pkcs1_encryption_oids[i].oid,
					key_type_len, key_type))
			break;

	if (i == L_ARRAY_SIZE(pkcs1_encryption_oids))
		cert->pubkey_type = L_CERT_KEY_UNKNOWN;
	else
		cert->pubkey_type = pkcs1_encryption_oids[i].key_type;

	return true;
}

LIB_EXPORT struct l_cert *l_cert_new_from_der(const uint8_t *buf,
						size_t buf_len)
{
	const uint8_t *seq = buf;
	size_t seq_len = buf_len;
	size_t content_len;
	struct l_cert *cert;

	/* Sanity check: outer element is a SEQUENCE */
	if (seq_len-- < 1 || *seq++ != ASN1_ID_SEQUENCE)
		return NULL;

	/* Sanity check: the SEQUENCE spans the whole buffer */
	content_len = asn1_parse_definite_length(&seq, &seq_len);
	if (content_len < 64 || content_len != seq_len)
		return NULL;

	/*
	 * We could require the signature algorithm and the key algorithm
	 * to be one of our supported types here but instead we only
	 * require that when the user wants to verify this certificate or
	 * get the public key respectively.
	 */

	cert = l_malloc(sizeof(struct l_cert) + buf_len);
	cert->issuer = NULL;
	cert->issued = NULL;
	cert->asn1_len = buf_len;
	memcpy(cert->asn1, buf, buf_len);

	/* Sanity check: structure is correct up to the Public Key Algorithm */
	if (!cert_set_pubkey_type(cert)) {
		l_free(cert);
		return NULL;
	}

	return cert;
}

LIB_EXPORT void l_cert_free(struct l_cert *cert)
{
	l_free(cert);
}

LIB_EXPORT const uint8_t *l_cert_get_der_data(struct l_cert *cert,
						size_t *out_len)
{
	if (unlikely(!cert))
		return NULL;

	*out_len = cert->asn1_len;
	return cert->asn1;
}

LIB_EXPORT const uint8_t *l_cert_get_dn(struct l_cert *cert, size_t *out_len)
{
	if (unlikely(!cert))
		return NULL;

	return asn1_der_find_elem_by_path(cert->asn1, cert->asn1_len,
						ASN1_ID_SEQUENCE, out_len,
						X509_CERTIFICATE_POS,
						X509_TBSCERTIFICATE_POS,
						X509_TBSCERT_SUBJECT_DN_POS,
						-1);
}

const uint8_t *cert_get_extension(struct l_cert *cert,
					const struct asn1_oid *ext_id,
					bool *out_critical, size_t *out_len)
{
	const uint8_t *ext, *end;
	size_t ext_len;

	if (unlikely(!cert))
		return NULL;

	ext = asn1_der_find_elem_by_path(cert->asn1, cert->asn1_len,
						ASN1_ID_SEQUENCE, &ext_len,
						X509_CERTIFICATE_POS,
						X509_TBSCERTIFICATE_POS,
						X509_TBSCERT_EXTENSIONS_POS,
						-1);
	if (unlikely(!ext))
		return NULL;

	end = ext + ext_len;
	while (ext < end) {
		const uint8_t *seq, *oid, *data;
		uint8_t tag;
		size_t len, oid_len, data_len;
		bool critical;

		seq = asn1_der_find_elem(ext, end - ext, 0, &tag, &len);
		if (unlikely(!seq || tag != ASN1_ID_SEQUENCE))
			return false;

		ext = seq + len;

		oid = asn1_der_find_elem(seq, len, 0, &tag, &oid_len);
		if (unlikely(!oid || tag != ASN1_ID_OID))
			return false;

		if (!asn1_oid_eq(ext_id, oid_len, oid))
			continue;

		data = asn1_der_find_elem(seq, len, 1, &tag, &data_len);
		critical = false;

		if (data && tag == ASN1_ID_BOOLEAN) {
			if (data_len != 1)
				return false;

			critical = *data != 0;	/* Tolerate BER booleans */

			data = asn1_der_find_elem(seq, len, 2, &tag, &data_len);
		}

		if (unlikely(!data || tag != ASN1_ID_OCTET_STRING))
			return false;

		if (out_critical)
			*out_critical = critical;

		if (out_len)
			*out_len = data_len;

		return data;
	}

	return NULL;
}

LIB_EXPORT enum l_cert_key_type l_cert_get_pubkey_type(struct l_cert *cert)
{
	if (unlikely(!cert))
		return L_CERT_KEY_UNKNOWN;

	return cert->pubkey_type;
}

/*
 * Note: Returns a new l_key object to be freed by the caller.
 */
LIB_EXPORT struct l_key *l_cert_get_pubkey(struct l_cert *cert)
{
	if (unlikely(!cert))
		return NULL;

	/* Use kernel's ASN.1 certificate parser to find the key data for us */
	if (cert->pubkey_type == L_CERT_KEY_RSA)
		return l_key_new(L_KEY_RSA, cert->asn1, cert->asn1_len);

	return NULL;
}

/*
 * Note: takes ownership of the certificate.  The certificate is
 * assumed to be new and not linked into any certchain object.
 */
struct l_certchain *certchain_new_from_leaf(struct l_cert *leaf)
{
	struct l_certchain *chain;

	chain = l_new(struct l_certchain, 1);
	chain->leaf = leaf;
	chain->ca = leaf;
	return chain;
}

/*
 * Note: takes ownership of the certificate.  The certificate is
 * assumed to be new and not linked into any certchain object.
 */
void certchain_link_issuer(struct l_certchain *chain, struct l_cert *ca)
{
	ca->issued = chain->ca;
	chain->ca->issuer = ca;
	chain->ca = ca;
}

static struct l_cert *certchain_pop_ca(struct l_certchain *chain)
{
	struct l_cert *ca = chain->ca;

	if (!ca)
		return NULL;

	if (ca->issued) {
		chain->ca = ca->issued;
		ca->issued->issuer = NULL;
		ca->issued = NULL;
	} else {
		chain->ca = NULL;
		chain->leaf = NULL;
	}

	return ca;
}

LIB_EXPORT void l_certchain_free(struct l_certchain *chain)
{
	while (chain && chain->ca)
		l_cert_free(certchain_pop_ca(chain));

	l_free(chain);
}

LIB_EXPORT struct l_cert *l_certchain_get_leaf(struct l_certchain *chain)
{
	if (unlikely(!chain))
		return NULL;

	return chain->leaf;
}

/*
 * Call @cb for each certificate in the chain starting from the leaf
 * certificate.  Stop if a call returns @true.
 */
LIB_EXPORT void l_certchain_walk_from_leaf(struct l_certchain *chain,
						l_cert_walk_cb_t cb,
						void *user_data)
{
	struct l_cert *cert;

	if (unlikely(!chain))
		return;

	for (cert = chain->leaf; cert; cert = cert->issuer)
		if (cb(cert, user_data))
			break;
}

/*
 * Call @cb for each certificate in the chain starting from the root
 * certificate.  Stop if a call returns @true.
 */
LIB_EXPORT void l_certchain_walk_from_ca(struct l_certchain *chain,
						l_cert_walk_cb_t cb,
						void *user_data)
{
	struct l_cert *cert;

	if (unlikely(!chain))
		return;

	for (cert = chain->ca; cert; cert = cert->issued)
		if (cb(cert, user_data))
			break;
}

static struct l_keyring *cert_set_to_keyring(struct l_queue *certs, char *error)
{
	struct l_keyring *ring;
	const struct l_queue_entry *entry;
	int i = 1;

	ring = l_keyring_new();
	if (!ring)
		return NULL;

	for (entry = l_queue_get_entries(certs); entry; entry = entry->next) {
		struct l_cert *cert = entry->data;
		struct l_key *key = l_cert_get_pubkey(cert);

		if (!key) {
			sprintf(error, "Can't get public key from certificate "
				"%i / %i in certificate set", i,
				l_queue_length(certs));
			goto cleanup;
		}

		if (!l_keyring_link(ring, key)) {
			l_key_free(key);
			sprintf(error, "Can't link the public key from "
				"certificate %i / %i to target keyring",
				i, l_queue_length(certs));
			goto cleanup;
		}

		l_key_free_norevoke(key);
		i++;
	}

	return ring;

cleanup:
	l_keyring_free(ring);
	return NULL;
}

static bool cert_is_in_set(struct l_cert *cert, struct l_queue *set)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(set); entry; entry = entry->next) {
		struct l_cert *cert2 = entry->data;

		if (cert == cert2)
			return true;

		if (cert->asn1_len == cert2->asn1_len &&
				!memcmp(cert->asn1, cert2->asn1,
					cert->asn1_len))
			return true;
	}

	return false;
}

static struct l_key *cert_try_link(struct l_cert *cert, struct l_keyring *ring)
{
	struct l_key *key;

	key = l_key_new(L_KEY_RSA, cert->asn1, cert->asn1_len);
	if (!key)
		return NULL;

	if (l_keyring_link(ring, key))
		return key;

	l_key_free(key);
	return NULL;
}

static void cert_keyring_cleanup(struct l_keyring **p)
{
	l_keyring_free(*p);
}

#define RETURN_ERROR(msg, args...)	\
	do {	\
		if (error) {	\
			*error = error_buf;	\
			snprintf(error_buf, sizeof(error_buf), msg, ## args); \
		}	\
		return false;	\
	} while (0)

LIB_EXPORT bool l_certchain_verify(struct l_certchain *chain,
					struct l_queue *ca_certs,
					const char **error)
{
	struct l_keyring *ca_ring = NULL;
	L_AUTO_CLEANUP_VAR(struct l_keyring *, verify_ring,
				cert_keyring_cleanup) = NULL;
	struct l_cert *cert;
	struct l_key *prev_key = NULL;
	int verified = 0;
	static char error_buf[200];

	if (unlikely(!chain || !chain->leaf))
		RETURN_ERROR("Chain empty");

	verify_ring = l_keyring_new();
	if (!verify_ring)
		RETURN_ERROR("Can't create verify keyring");

	cert = chain->ca;

	/*
	 * For TLS compatibility the trusted root CA certificate is
	 * optionally present in the chain.
	 *
	 * RFC5246 7.4.2:
	 * "Because certificate validation requires that root keys be
	 * distributed independently, the self-signed certificate that
	 * specifies the root certificate authority MAY be omitted from
	 * the chain, under the assumption that the remote end must
	 * already possess it in order to validate it in any case."
	 *
	 * The following is an optimization to skip verifying the root
	 * cert in the chain if it is identical to one of the trusted CA
	 * certificates.  It also happens to work around a kernel issue
	 * preventing self-signed certificates missing the AKID
	 * extension from being linked to a keyring.
	 */
	if (cert_is_in_set(cert, ca_certs)) {
		verified++;
		cert = cert->issued;
		if (!cert)
			return true;

		prev_key = cert_try_link(cert, verify_ring);
	} else if (ca_certs) {
		ca_ring = cert_set_to_keyring(ca_certs, error_buf);
		if (!ca_ring) {
			if (error)
				*error = error_buf;
			return false;
		}

		if (!l_keyring_link_nested(verify_ring, ca_ring)) {
			l_keyring_free(ca_ring);
			RETURN_ERROR("Can't link CA ring to verify ring");
		}
	} else
		prev_key = cert_try_link(cert, verify_ring);

	/*
	 * The top, unverified certificate(s) are linked to the keyring and
	 * we can now force verification of any new certificates linked.
	 */
	if (!l_keyring_restrict(verify_ring, L_KEYRING_RESTRICT_ASYM_CHAIN,
				NULL)) {
		l_key_free(prev_key);
		l_keyring_free(ca_ring);
		RETURN_ERROR("Can't restrict verify keyring");
	}

	if (ca_ring) {
		/*
		 * Verify the first certificate outside of the loop, then
		 * revoke the trusted CAs' keys so that only the newly
		 * verified cert's public key remains in the ring.
		 */
		prev_key = cert_try_link(cert, verify_ring);
		l_keyring_free(ca_ring);
	}

	cert = cert->issued;

	/* Verify the rest of the chain */
	while (prev_key && cert) {
		struct l_key *new_key = cert_try_link(cert, verify_ring);

		/*
		 * Free and revoke the issuer's public key again leaving only
		 * new_key in verify_ring to ensure the next certificate linked
		 * is signed by the owner of this key.
		 */
		l_key_free(prev_key);
		prev_key = new_key;
		cert = cert->issued;
		verified++;
	}

	if (!prev_key) {
		int total = 0;

		for (cert = chain->ca; cert; cert = cert->issued, total++);
		RETURN_ERROR("Linking certificate %i / %i failed, root %s"
				"verified against trusted CA(s) and the "
				"following %i top certificates verified ok",
				verified + 1, total,
				ca_certs && verified ? "" : "not ",
				verified ? verified - 1 : 0);
	}

	l_key_free(prev_key);
	return true;
}
