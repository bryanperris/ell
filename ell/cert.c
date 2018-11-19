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

#include "private.h"
#include "key.h"
#include "asn1-private.h"
#include "cert.h"
#include "cert-private.h"

#define X509_CERTIFICATE_POS			0
#define   X509_TBSCERTIFICATE_POS		  0
#define     X509_TBSCERT_VERSION_POS		    0
#define     X509_TBSCERT_SERIAL_POS		    1
#define     X509_TBSCERT_SIGNATURE_POS		    2
#define       X509_ALGORITHM_ID_ALGORITHM_POS	      0
#define       X509_ALGORITHM_ID_PARAMS_POS	      1
#define     X509_TBSCERT_ISSUER_DN_POS		    3
#define     X509_TBSCERT_VALIDITY_POS		    4
#define     X509_TBSCERT_SUBJECT_DN_POS		    5
#define     X509_TBSCERT_SUBJECT_KEY_POS	    6
#define       X509_SUBJECT_KEY_ALGORITHM_POS	      0
#define       X509_SUBJECT_KEY_VALUE_POS	      1
#define     X509_TBSCERT_ISSUER_UID_POS		    7
#define     X509_TBSCERT_SUBJECT_UID_POS	    8
#define     X509_TBSCERT_EXTENSIONS_POS		    9
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
						ASN1_ID_OID, out_len,
						X509_CERTIFICATE_POS,
						X509_TBSCERTIFICATE_POS,
						X509_TBSCERT_SUBJECT_DN_POS,
						-1);
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

LIB_EXPORT bool l_certchain_foreach_from_leaf(struct l_certchain *chain,
						l_cert_foreach_cb_t cb,
						void *user_data)
{
	struct l_cert *cert;

	if (unlikely(!chain))
		return false;

	for (cert = chain->leaf; cert; cert = cert->issuer)
		if (cb(cert, user_data))
			return true;

	return false;
}

LIB_EXPORT bool l_certchain_foreach_from_ca(struct l_certchain *chain,
						l_cert_foreach_cb_t cb,
						void *user_data)
{
	struct l_cert *cert;

	if (unlikely(!chain))
		return false;

	for (cert = chain->ca; cert; cert = cert->issued)
		if (cb(cert, user_data))
			return true;

	return false;
}

LIB_EXPORT bool l_certchain_find(struct l_certchain *chain,
					struct l_cert *ca_cert)
{
	if (unlikely(!chain || !chain->leaf))
		return false;

	/* Nothing to do if no CA certificates supplied */
	if (!ca_cert)
		return true;

	/*
	 * Also nothing to do if the user already supplied a working
	 * certificate chain.
	 */
	if (l_certchain_verify(chain, ca_cert))
		return true;

	/* Actual search for a chain to the CA cert is unimplemented, fail */
	return false;
}

static void cert_key_cleanup(struct l_key **p)
{
	l_key_free_norevoke(*p);
}

static bool certchain_verify_with_keyring(struct l_cert *cert,
						struct l_keyring *ring,
						struct l_cert *root,
						struct l_keyring *trusted)
{
	if (!cert)
		return true;

	if (cert->pubkey_type != L_CERT_KEY_RSA)
		return false;

	/*
	 * RFC5246 7.4.2:
	 * "Because certificate validation requires that root keys be
	 * distributed independently, the self-signed certificate that
	 * specifies the root certificate authority MAY be omitted from
	 * the chain, under the assumption that the remote end must
	 * already possess it in order to validate it in any case."
	 */
	if (!cert->issuer && root && cert->asn1_len == root->asn1_len &&
			!memcmp(cert->asn1, root->asn1, root->asn1_len))
		return true;

	if (certchain_verify_with_keyring(cert->issuer, ring, root, trusted)) {
		L_AUTO_CLEANUP_VAR(struct l_key *, key, cert_key_cleanup);

		key = l_key_new(L_KEY_RSA, cert->asn1, cert->asn1_len);
		if (!key)
			return false;

		if (!l_keyring_link(ring, key))
			return false;

		if (trusted || cert->issuer)
			return true;

		/*
		 * If execution reaches this point, it's known that:
		 *  * No trusted root key was supplied, so the chain is only
		 *    being checked against its own root
		 *  * The keyring 'ring' is not restricted yet
		 *  * The chain's root cert was just linked in to the
		 *    previously empty keyring 'ring'.
		 *
		 * By restricting 'ring' now, the rest of the certs in
		 * the chain will have their signature validated using 'key'
		 * as the root.
		 */
		return l_keyring_restrict(ring,	L_KEYRING_RESTRICT_ASYM_CHAIN,
						trusted);
	}

	return false;
}

static void cert_keyring_cleanup(struct l_keyring **p)
{
	l_keyring_free(*p);
}

LIB_EXPORT bool l_certchain_verify(struct l_certchain *chain,
					struct l_cert *ca_cert)
{
	L_AUTO_CLEANUP_VAR(struct l_keyring *, ca_ring,
				cert_keyring_cleanup) = NULL;
	L_AUTO_CLEANUP_VAR(struct l_keyring *, verify_ring,
				cert_keyring_cleanup) = NULL;

	if (unlikely(!chain || !chain->leaf))
		return false;

	if (ca_cert && ca_cert->pubkey_type != L_CERT_KEY_RSA)
		return false;

	if (ca_cert) {
		L_AUTO_CLEANUP_VAR(struct l_key *, ca_key, cert_key_cleanup);
		ca_key = NULL;

		ca_ring = l_keyring_new();
		if (!ca_ring)
			return false;

		ca_key = l_cert_get_pubkey(ca_cert);
		if (!ca_key || !l_keyring_link(ca_ring, ca_key))
			return false;
	}

	verify_ring = l_keyring_new();
	if (!verify_ring)
		return false;

	/*
	 * If a CA cert was supplied, restrict verify_ring now so
	 * everything else in certchain is validated against the CA.
	 * Otherwise, verify_ring will be restricted after the root of
	 * certchain is added to verify_ring by
	 * cert_verify_with_keyring().
	 */
	if (ca_ring && !l_keyring_restrict(verify_ring,
						L_KEYRING_RESTRICT_ASYM_CHAIN,
						ca_ring)) {
		return false;
	}

	return certchain_verify_with_keyring(chain->leaf, verify_ring, ca_cert,
						ca_ring);
}
