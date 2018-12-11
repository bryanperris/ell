
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <linux/types.h>
#include <stdint.h>
#include <stdbool.h>

#include "private.h"
#include "ecc.h"
#include "ecc-private.h"
#include "random.h"

#define P256_CURVE_P { 0xFFFFFFFFFFFFFFFFull, 0x00000000FFFFFFFFull, \
			0x0000000000000000ull, 0xFFFFFFFF00000001ull }
#define P256_CURVE_GX { 0xF4A13945D898C296ull, 0x77037D812DEB33A0ull,   \
			0xF8BCE6E563A440F2ull, 0x6B17D1F2E12C4247ull }
#define P256_CURVE_GY { 0xCBB6406837BF51F5ull, 0x2BCE33576B315ECEull,   \
			0x8EE7EB4A7C0F9E16ull, 0x4FE342E2FE1A7F9Bull }
#define P256_CURVE_N { 0xF3B9CAC2FC632551ull, 0xBCE6FAADA7179E84ull,   \
			0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFF00000000ull }
#define P256_CURVE_B { 0x3BCE3C3E27D2604Bull, 0x651D06B0CC53B0F6ull,   \
			0xB3EBBD55769886BCull, 0x5AC635D8AA3A93E7ull }

static struct l_ecc_curve p256 = {
	.group = 19,
	.ndigits = 4,
	.g = {
		.x = P256_CURVE_GX,
		.y = P256_CURVE_GY,
		.curve = &p256
	},
	.p = P256_CURVE_P,
	.n = P256_CURVE_N,
	.b = P256_CURVE_B,
};

static struct l_ecc_curve *curves[] = {
	&p256,
};

LIB_EXPORT const struct l_ecc_curve *l_ecc_curve_get(unsigned int group)
{
	int i;

	for (i = 0; curves[i]; i++) {
		if (curves[i]->group == group)
			return curves[i];
	}

	return NULL;
}

static bool ecc_valid_point(struct l_ecc_point *point)
{
	const struct l_ecc_curve *curve = point->curve;
	uint64_t tmp1[L_ECC_MAX_DIGITS];
	uint64_t tmp2[L_ECC_MAX_DIGITS];
	uint64_t _3[L_ECC_MAX_DIGITS] = { 3 };	/* -a = 3 */
	unsigned int ndigits = curve->ndigits;

	/* The point at infinity is invalid. */
	if (_ecc_point_is_zero(point))
		return false;

	/* x and y must be smaller than p. */
	if (_vli_cmp(curve->p, point->x, ndigits) != 1 ||
			_vli_cmp(curve->p, point->y, ndigits) != 1)
		return false;

	/* Computes result = y^2. */
	_vli_mod_square_fast(tmp1, point->y, curve->p, ndigits);

	/* Computes result = x^3 + ax + b. result must not overlap x. */
	/* r = x^2 */
	_vli_mod_square_fast(tmp2, point->x, curve->p, ndigits);
	/* r = x^2 - 3 */
	_vli_mod_sub(tmp2, tmp2, _3, curve->p, ndigits);
	/* r = x^3 - 3x */
	_vli_mod_mult_fast(tmp2, tmp2, point->x, curve->p, ndigits);
	/* r = x^3 - 3x + b */
	_vli_mod_add(tmp2, tmp2, curve->b, curve->p, ndigits);
	/* Make sure that y^2 == x^3 + ax + b */
	return (_vli_cmp(tmp1, tmp2, ndigits) == 0);
}

void _ecc_be2native(uint64_t *dest, uint64_t *bytes, unsigned int ndigits)
{
	unsigned int i;
	uint64_t tmp[L_ECC_MAX_DIGITS];

	for (i = 0; i < ndigits; i++)
		tmp[ndigits - 1 - i] = l_get_be64(&bytes[i]);

	memcpy(dest, tmp, ndigits * 8);
}

void _ecc_native2be(uint64_t *dest, uint64_t *native, unsigned int ndigits)
{
	unsigned int i;
	uint64_t tmp[L_ECC_MAX_DIGITS];

	for (i = 0; i < ndigits; i++)
		l_put_be64(native[ndigits - 1 - i], &tmp[i]);

	memcpy(dest, tmp, ndigits * 8);
}

static void ecc_compute_y_sqr(const struct l_ecc_curve *curve,
					uint64_t *y_sqr, uint64_t *x)
{
	uint64_t sum[L_ECC_MAX_DIGITS] = { 0 };
	uint64_t tmp[L_ECC_MAX_DIGITS] = { 0 };
	uint64_t _3[L_ECC_MAX_DIGITS] = { 3ull }; /* -a = 3 */

	/* x^3 */
	_vli_mod_square_fast(sum, x, curve->p, curve->ndigits);
	_vli_mod_mult_fast(sum, sum, x, curve->p, curve->ndigits);
	/* x^3 - ax */
	_vli_mod_mult_fast(tmp, _3, x, curve->p, curve->ndigits);
	_vli_mod_sub(sum, sum, tmp, curve->p, curve->ndigits);
	/* x^3 - ax + b */
	_vli_mod_add(sum, sum, curve->b, curve->p, curve->ndigits);

	memcpy(y_sqr, sum, curve->ndigits * 8);
}

bool _ecc_compute_y(const struct l_ecc_curve *curve, uint64_t *y, uint64_t *x)
{
	/*
	 * y = sqrt(x^3 + ax + b) (mod p)
	 *
	 * Since our prime p satisfies p = 3 (mod 4), we can say:
	 *
	 * y = (x^3 - 3x + b)^((p + 1) / 4)
	 *
	 * This avoids the need for a square root function.
	 */

	uint64_t sum[L_ECC_MAX_DIGITS] = { 0 };
	uint64_t expo[L_ECC_MAX_DIGITS] = { 0 };
	uint64_t one[L_ECC_MAX_DIGITS] = { 1ull };
	uint64_t check[L_ECC_MAX_DIGITS] = { 0 };

	memcpy(expo, curve->p, curve->ndigits * 8);

	/* x^3 - 3x + b */
	ecc_compute_y_sqr(curve, sum, x);

	/* (p + 1) / 4  == (p >> 2) + 1 */
	_vli_rshift1(expo, curve->ndigits);
	_vli_rshift1(expo, curve->ndigits);
	_vli_mod_add(expo, expo, one, curve->p, curve->ndigits);
	/* sum ^ ((p + 1) / 4) */
	_vli_mod_exp(y, sum, expo, curve->p, curve->ndigits);

	/* square y to ensure we have a correct value */
	_vli_mod_mult_fast(check, y, y, curve->p, curve->ndigits);

	if (_vli_cmp(check, sum, curve->ndigits) != 0)
		return false;

	return true;
}

/*
 * IETF - Compact representation of an elliptic curve point:
 * https://tools.ietf.org/id/draft-jivsov-ecc-compact-00.xml
 *
 * "min(y,p-y) can be calculated with the help of the pre-calculated value
 *  p2=(p-1)/2. min(y,p-y) is y if y<p2 and p-y otherwise."
 */
void _ecc_calculate_p2(const struct l_ecc_curve *curve, uint64_t *p2)
{
	uint64_t one[L_ECC_MAX_DIGITS] = { 1 };

	_vli_mod_sub(p2, curve->p, one, curve->p, curve->ndigits);
	_vli_rshift1(p2, curve->ndigits);
}

/*
 * IETF draft-jivsov-ecc-compact-00 Section 4.1
 * Encoding and decoding of an elliptic curve point
 * ...
 * Decoding:
 * Given the compact representation of Q, return canonical representation
 * of Q=(x,y) as follows:
 *     1. y' = sqrt( x^3 + a*x + b ), where y'>0
 *     2. y = min(y',p-y')
 *     3. Q=(x,y) is the canonical representation of the point
 */
static bool decode_point(const struct l_ecc_curve *curve, uint64_t *x,
				struct l_ecc_point *point)
{
	uint64_t y_min[L_ECC_MAX_DIGITS];
	uint64_t p2[L_ECC_MAX_DIGITS];

	if (!_ecc_compute_y(curve, y_min, (uint64_t *)x))
		return false;

	_ecc_calculate_p2(curve, p2);

	if (_vli_cmp(y_min, p2, curve->ndigits) >= 0)
		_vli_mod_sub(point->y, curve->p, y_min,
					curve->p, curve->ndigits);
	else
		memcpy(point->y, y_min, curve->ndigits * 8);

	memcpy(point->x, x, curve->ndigits * 8);

	return true;
}

LIB_EXPORT struct l_ecc_point *l_ecc_point_new(const struct l_ecc_curve *curve)
{
	struct l_ecc_point *p = l_new(struct l_ecc_point, 1);

	p->curve = curve;

	return p;
}

LIB_EXPORT struct l_ecc_point *l_ecc_point_from_data(
					const struct l_ecc_curve *curve,
					enum l_ecc_point_type type,
					const void *data, size_t len)
{
	struct l_ecc_point *p;
	size_t bytes = curve->ndigits * 8;

	if (!data)
		return NULL;

	/* In all cases there should be an X coordinate in data */
	if (len < bytes)
		return NULL;

	p = l_ecc_point_new(curve);

	_ecc_be2native(p->x, (void *) data, curve->ndigits);

	switch (type) {
	case L_ECC_POINT_TYPE_COMPLIANT:
		if (!decode_point(curve, p->x, p))
			goto failed;

		break;
	case L_ECC_POINT_TYPE_COMPRESSED_BIT0:
		if (!_ecc_compute_y(curve, p->y, p->x))
			goto failed;

		if (!(p->y[0] & 1))
			_vli_mod_sub(p->y, curve->p, p->y, curve->p,
						curve->ndigits);
		break;
	case L_ECC_POINT_TYPE_COMPRESSED_BIT1:
		if (!_ecc_compute_y(curve, p->y, p->x))
			goto failed;

		if (p->y[0] & 1)
			_vli_mod_sub(p->y, curve->p, p->y, curve->p,
						curve->ndigits);

		break;
	case L_ECC_POINT_TYPE_FULL:
		if (len != bytes * 2)
			goto failed;

		_ecc_be2native(p->y, (void *) data + bytes, curve->ndigits);

		if (!ecc_valid_point(p))
			goto failed;

		break;
	}

	return p;

failed:
	l_free(p);
	return NULL;
}

LIB_EXPORT ssize_t l_ecc_point_get_x(const struct l_ecc_point *p, void *x,
					size_t xlen)
{
	if (xlen < p->curve->ndigits * 8)
		return -EMSGSIZE;

	_ecc_native2be(x, (uint64_t *) p->x, p->curve->ndigits);

	return p->curve->ndigits * 8;
}

LIB_EXPORT ssize_t l_ecc_point_get_data(const struct l_ecc_point *p, void *buf,
					size_t len)
{
	if (len < (p->curve->ndigits * 8) * 2)
		return -EMSGSIZE;

	_ecc_native2be(buf, (uint64_t *) p->x, p->curve->ndigits);
	_ecc_native2be(buf + (p->curve->ndigits * 8), (uint64_t *) p->y,
				p->curve->ndigits);

	return (p->curve->ndigits * 8) * 2;
}

LIB_EXPORT void l_ecc_point_free(struct l_ecc_point *p)
{
	l_free(p);
}

struct l_ecc_scalar *_ecc_constant_new(const struct l_ecc_curve *curve,
						void *buf, size_t len)
{
	struct l_ecc_scalar *c;

	if (unlikely(!curve))
		return NULL;

	if (buf && len != curve->ndigits * 8)
		return NULL;

	c = l_new(struct l_ecc_scalar, 1);

	c->curve = curve;

	if (buf)
		memcpy(c->c, buf, len);

	return c;
}

LIB_EXPORT struct l_ecc_scalar *l_ecc_scalar_new(
					const struct l_ecc_curve *curve,
					void *buf, size_t len)
{
	struct l_ecc_scalar *c;

	c = _ecc_constant_new(curve, NULL, 0);
	if (!c)
		return NULL;

	if (buf)
		_ecc_be2native(c->c, buf, curve->ndigits);

	return c;
}

LIB_EXPORT struct l_ecc_scalar *l_ecc_scalar_new_random(
					const struct l_ecc_curve *curve)
{
	uint64_t r[L_ECC_MAX_DIGITS];
	uint64_t zero[L_ECC_MAX_DIGITS] = { 0 };

	l_getrandom(r, curve->ndigits * 8);

	while (_vli_cmp(r, curve->p, curve->ndigits) > 0 ||
			_vli_cmp(r, zero, curve->ndigits) == 0)
		l_getrandom(r, curve->ndigits * 8);

	return _ecc_constant_new(curve, r, curve->ndigits * 8);
}

LIB_EXPORT ssize_t l_ecc_scalar_get_data(const struct l_ecc_scalar *c,

						void *buf, size_t len)
{
	if (len < c->curve->ndigits * 8)
		return -EMSGSIZE;

	_ecc_native2be(buf, (uint64_t *) c->c, c->curve->ndigits);

	return c->curve->ndigits * 8;
}

LIB_EXPORT void l_ecc_scalar_free(struct l_ecc_scalar *c)
{
	l_free(c);
}
