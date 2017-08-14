/*
 *  Embedded Linux library
 *
 *  Copyright (C) 2017  Intel Corporation. All rights reserved.
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

#define ASN1_ID(class, pc, tag)	(((class) << 6) | ((pc) << 5) | (tag))

#define ASN1_CLASS_UNIVERSAL	0

#define ASN1_ID_SEQUENCE	ASN1_ID(ASN1_CLASS_UNIVERSAL, 1, 0x10)
#define ASN1_ID_SET		ASN1_ID(ASN1_CLASS_UNIVERSAL, 1, 0x11)
#define ASN1_ID_INTEGER		ASN1_ID(ASN1_CLASS_UNIVERSAL, 0, 0x02)
#define ASN1_ID_BIT_STRING	ASN1_ID(ASN1_CLASS_UNIVERSAL, 0, 0x03)
#define ASN1_ID_OCTET_STRING	ASN1_ID(ASN1_CLASS_UNIVERSAL, 0, 0x04)
#define ASN1_ID_OID		ASN1_ID(ASN1_CLASS_UNIVERSAL, 0, 0x06)
#define ASN1_ID_UTF8STRING	ASN1_ID(ASN1_CLASS_UNIVERSAL, 0, 0x0c)
#define ASN1_ID_PRINTABLESTRING	ASN1_ID(ASN1_CLASS_UNIVERSAL, 0, 0x13)

struct asn1_oid {
	uint8_t asn1_len;
	uint8_t asn1[10];
};

#define asn1_oid_eq(oid1, oid2_len, oid2_string) \
	((oid1)->asn1_len == (oid2_len) && \
	 !memcmp((oid1)->asn1, (oid2_string), (oid2_len)))

static inline int asn1_parse_definite_length(const uint8_t **buf,
						size_t *len)
{
	int n;
	size_t result = 0;

	(*len)--;

	if (!(**buf & 0x80))
		return *(*buf)++;

	n = *(*buf)++ & 0x7f;
	if ((size_t) n > *len)
		return -1;

	*len -= n;
	while (n--)
		result = (result << 8) | *(*buf)++;

	return result;
}

/* Return index'th element in a DER SEQUENCE */
static inline const uint8_t *asn1_der_find_elem(const uint8_t *buf,
						size_t len_in, int index,
						uint8_t *tag, size_t *len_out)
{
	int tlv_len;

	while (1) {
		if (len_in < 2)
			return NULL;

		*tag = *buf++;
		len_in--;

		tlv_len = asn1_parse_definite_length((void *) &buf, &len_in);
		if (tlv_len < 0 || (size_t) tlv_len > len_in)
			return NULL;

		if (index-- == 0) {
			*len_out = tlv_len;
			return buf;
		}

		buf += tlv_len;
		len_in -= tlv_len;
	}
}

/* Return an element in a DER SEQUENCE structure by path */
static inline const uint8_t *asn1_der_find_elem_by_path(const uint8_t *buf,
						size_t len_in, uint8_t tag,
						size_t *len_out, ...)
{
	uint8_t elem_tag;
	int pos;
	va_list vl;

	va_start(vl, len_out);

	pos = va_arg(vl, int);

	while (pos != -1) {
		buf = asn1_der_find_elem(buf, len_in, pos, &elem_tag, &len_in);

		pos = va_arg(vl, int);

		if (!buf || elem_tag != (pos == -1 ? tag : ASN1_ID_SEQUENCE))
			return NULL;
	}

	va_end(vl);

	*len_out = len_in;
	return buf;
}
