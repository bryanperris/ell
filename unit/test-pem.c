/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2015  Intel Corporation. All rights reserved.
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

#include <assert.h>

#include <ell/ell.h>

struct pem_test {
	const char *input;
	bool valid;
	const char *label;
	size_t decoded_size;
};

static const struct pem_test invalid_header1 = {
	.input = "-----BEGIN FOOBAR -----\r\n"
			"----END FOOBAR -----\r\n",
	.valid = false,
};

static const struct pem_test invalid_header2 = {
	.input = "-----BEGIN CERT  IFICATE-----\r\n"
			"-----END CERT  IFICATE----\r\n",
	.valid = false,
};

static const struct pem_test empty = {
	.input = "-----BEGIN CERTIFICATE-----\r\n"
			"-----END CERTIFICATE-----\r\n",
	.valid = false,
};

static const struct pem_test empty_label = {
	.input = "-----BEGIN -----\r\n"
			"U28/PHA+\r\n"
			"-----END -----\r\n",
	.valid = true,
	.label = "",
	.decoded_size = 6,
};

struct pem_from_data_test {
	const char *list;
	const char *ca;
};

static const struct pem_from_data_test single_line_cert_chain = {
	/* Copied from cert-chain.pem */
	.list =
		"-----BEGIN CERTIFICATE-----\n"
		"MIIEXDCCA0SgAwIBAgIJALjNE85c9plgMA0GCSqGSIb3DQEBCwUAMHgxNTAzBgNV\n"
		"BAoMLEludGVybmF0aW9uYWwgVW5pb24gb2YgRXhhbXBsZSBPcmdhbml6YXRpb25z\n"
		"MR8wHQYDVQQDDBZDZXJ0aWZpY2F0ZSBpc3N1ZXIgZ3V5MR4wHAYJKoZIhvcNAQkB\n"
		"Fg9jYUBtYWlsLmV4YW1wbGUwHhcNMTkwOTE2MTcxMzAzWhcNNDcwMjAxMTcxMzAz\n"
		"WjB4MTUwMwYDVQQKDCxJbnRlcm5hdGlvbmFsIFVuaW9uIG9mIEV4YW1wbGUgT3Jn\n"
		"YW5pemF0aW9uczEfMB0GA1UEAwwWQ2VydGlmaWNhdGUgaXNzdWVyIGd1eTEeMBwG\n"
		"CSqGSIb3DQEJARYPY2FAbWFpbC5leGFtcGxlMIIBIjANBgkqhkiG9w0BAQEFAAOC\n"
		"AQ8AMIIBCgKCAQEA7Lft5O6BtUUokuueQ7mBQVzRzPeH0Nl3NjgGnfBYcz7O2Jca\n"
		"rFSBPsV76reUG4QFQudsdwyaLOpniFFSFaI3GRXMxjwZJJjLqvT0aebTiLUSKseA\n"
		"QkP/NSITmIljs2yclnPJGIApLuFvykPagx+yc9ckbziEz1PvKB/ukbiU/zt6QCru\n"
		"BbyCQ1kWBuyrS3RC0/UgmrSbL7YkkmuD2B1vyZLIoPsJijXs2GJQY3a+zpLemTth\n"
		"i/Vw4AURJS1gfEUDNzf9Y9+o7vWJfzk+g7xm1XpMTsNTd7q6UwHOi1xdiKCEPT+q\n"
		"c3LXi7qgWqSXeD+F513PM3JMJ3Wk1H8K4VwJwQIDAQABo4HoMIHlMAwGA1UdEwQF\n"
		"MAMBAf8wHQYDVR0OBBYEFMuhnjqw8YGMg0cyYlQppMncWis/MIG1BgNVHSMEga0w\n"
		"gaqAFJ75Zb78cte1aqkdBX4EuDcM140noXykejB4MTUwMwYDVQQKDCxJbnRlcm5h\n"
		"dGlvbmFsIFVuaW9uIG9mIEV4YW1wbGUgT3JnYW5pemF0aW9uczEfMB0GA1UEAwwW\n"
		"Q2VydGlmaWNhdGUgaXNzdWVyIGd1eTEeMBwGCSqGSIb3DQEJARYPY2FAbWFpbC5l\n"
		"eGFtcGxlghQog5dBcTIdmw4XD/6KEME0ZNCdZTANBgkqhkiG9w0BAQsFAAOCAQEA\n"
		"PjX5n/fgkskZmh9aRhX8r9985JtxMdgogJP4uwRbfuQPzAqYyu9QlAOcRl6tNGN7\n"
		"mztB5RfJ9HDyjS9iGXsvKXS8wT5ELbuATev+C1Ppxakd3gvJMN4ZqYn32JqRYigN\n"
		"L2V2jo9RzVUuFa3YP6sw0KfZAfHsfUmQCxAm8HAfQg98aYyIXu/OzeVUsAuhfqWN\n"
		"qvWcOLjTQTn6t10OHHdIYw59EpIEOPD3Opq7pLgIm+EV3eVMWthSLYbEhIavh8Pc\n"
		"xN9lqCg887kTawbXbXd49Z8jYZxjxQl7IoonvIyrPhhabKjKCpE2bRFzzpia0PkC\n"
		"fRgh+KB2tqIeAoekDllmbA==\n"
		"-----END CERTIFICATE-----\n"
		"-----BEGIN CERTIFICATE-----\n"
		"MIIEajCCA1KgAwIBAgIUKIOXQXEyHZsOFw/+ihDBNGTQnWUwDQYJKoZIhvcNAQEL\n"
		"BQAweDE1MDMGA1UECgwsSW50ZXJuYXRpb25hbCBVbmlvbiBvZiBFeGFtcGxlIE9y\n"
		"Z2FuaXphdGlvbnMxHzAdBgNVBAMMFkNlcnRpZmljYXRlIGlzc3VlciBndXkxHjAc\n"
		"BgkqhkiG9w0BCQEWD2NhQG1haWwuZXhhbXBsZTAeFw0xOTA5MTYxNzEyNThaFw00\n"
		"NzAyMDExNzEyNThaMHgxNTAzBgNVBAoMLEludGVybmF0aW9uYWwgVW5pb24gb2Yg\n"
		"RXhhbXBsZSBPcmdhbml6YXRpb25zMR8wHQYDVQQDDBZDZXJ0aWZpY2F0ZSBpc3N1\n"
		"ZXIgZ3V5MR4wHAYJKoZIhvcNAQkBFg9jYUBtYWlsLmV4YW1wbGUwggEiMA0GCSqG\n"
		"SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCjovj3aq26sAQ0k5vD/BVp40p0lhz1+Wet\n"
		"1EcdQa1arVIca9nhfvoHfJAmK+zzqQLbvI0/e2if4X6OKf41g7w7VaYS9qv5jZZ0\n"
		"v/7aL6PUa2F7C9HG/vuIII/dRvP2uQ43PLxeTeZyj7bBUB9xCFCpzB+7AZuUuH0H\n"
		"ABaC9CAGZWImBY5NUXST7E/BsvqU80KJglDovcabthvwoekji9DC/wwISLE1e9cO\n"
		"A9IB0Co0mA1ME6wzrawmuTzxUw9BsmEhbKhFGBRwIrrq0r4GvDmeMFiZjXv+I0vq\n"
		"wSCyRtgoeBmyemqIEgiN4Z23V7ps3dbYF/tw96Zj7rd5gtjY9VSdAgMBAAGjgesw\n"
		"gegwDwYDVR0TBAgwBgEB/wIBADAdBgNVHQ4EFgQUnvllvvxy17VqqR0FfgS4NwzX\n"
		"jScwgbUGA1UdIwSBrTCBqoAUnvllvvxy17VqqR0FfgS4NwzXjSehfKR6MHgxNTAz\n"
		"BgNVBAoMLEludGVybmF0aW9uYWwgVW5pb24gb2YgRXhhbXBsZSBPcmdhbml6YXRp\n"
		"b25zMR8wHQYDVQQDDBZDZXJ0aWZpY2F0ZSBpc3N1ZXIgZ3V5MR4wHAYJKoZIhvcN\n"
		"AQkBFg9jYUBtYWlsLmV4YW1wbGWCFCiDl0FxMh2bDhcP/ooQwTRk0J1lMA0GCSqG\n"
		"SIb3DQEBCwUAA4IBAQBROAyWfQyKXQ007U6ctgihHbg/lsfEEfeNPG+QRVt8/e53\n"
		"4fH6scuY9bW7CZQSdiBo178ITHrIOo2CuFMa0ysnW3V1M9/s0dUYjBHYdpTEEQ+d\n"
		"tgm1uRLiTsYeBtueRItEmZU6JjgmvAH8i1UqI0e5iYlfnovPmftpqIwRH7k7A9kS\n"
		"SehC9QkkrnIttDEoeYTGhLOJu1Fx2cwAodce6VNgz/k1zIXY5Tprg440zrCwc+th\n"
		"MpX48F31ggg8Wd5N6Xg1nricGwL8K90ts6xvwF1WwKsg6BeYdyC0eYBqQ41MA/7P\n"
		"DK3OGM6cC5tbQGWaIT0Q407GJBGpaijDicA2YqlK\n"
		"-----END CERTIFICATE-----\n",
	/* copied from cert-ca.pem */
	.ca =	"-----BEGIN CERTIFICATE-----\n"
		"MIIEajCCA1KgAwIBAgIUKIOXQXEyHZsOFw/+ihDBNGTQnWUwDQYJKoZIhvcNAQEL\n"
		"BQAweDE1MDMGA1UECgwsSW50ZXJuYXRpb25hbCBVbmlvbiBvZiBFeGFtcGxlIE9y\n"
		"Z2FuaXphdGlvbnMxHzAdBgNVBAMMFkNlcnRpZmljYXRlIGlzc3VlciBndXkxHjAc\n"
		"BgkqhkiG9w0BCQEWD2NhQG1haWwuZXhhbXBsZTAeFw0xOTA5MTYxNzEyNThaFw00\n"
		"NzAyMDExNzEyNThaMHgxNTAzBgNVBAoMLEludGVybmF0aW9uYWwgVW5pb24gb2Yg\n"
		"RXhhbXBsZSBPcmdhbml6YXRpb25zMR8wHQYDVQQDDBZDZXJ0aWZpY2F0ZSBpc3N1\n"
		"ZXIgZ3V5MR4wHAYJKoZIhvcNAQkBFg9jYUBtYWlsLmV4YW1wbGUwggEiMA0GCSqG\n"
		"SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCjovj3aq26sAQ0k5vD/BVp40p0lhz1+Wet\n"
		"1EcdQa1arVIca9nhfvoHfJAmK+zzqQLbvI0/e2if4X6OKf41g7w7VaYS9qv5jZZ0\n"
		"v/7aL6PUa2F7C9HG/vuIII/dRvP2uQ43PLxeTeZyj7bBUB9xCFCpzB+7AZuUuH0H\n"
		"ABaC9CAGZWImBY5NUXST7E/BsvqU80KJglDovcabthvwoekji9DC/wwISLE1e9cO\n"
		"A9IB0Co0mA1ME6wzrawmuTzxUw9BsmEhbKhFGBRwIrrq0r4GvDmeMFiZjXv+I0vq\n"
		"wSCyRtgoeBmyemqIEgiN4Z23V7ps3dbYF/tw96Zj7rd5gtjY9VSdAgMBAAGjgesw\n"
		"gegwDwYDVR0TBAgwBgEB/wIBADAdBgNVHQ4EFgQUnvllvvxy17VqqR0FfgS4NwzX\n"
		"jScwgbUGA1UdIwSBrTCBqoAUnvllvvxy17VqqR0FfgS4NwzXjSehfKR6MHgxNTAz\n"
		"BgNVBAoMLEludGVybmF0aW9uYWwgVW5pb24gb2YgRXhhbXBsZSBPcmdhbml6YXRp\n"
		"b25zMR8wHQYDVQQDDBZDZXJ0aWZpY2F0ZSBpc3N1ZXIgZ3V5MR4wHAYJKoZIhvcN\n"
		"AQkBFg9jYUBtYWlsLmV4YW1wbGWCFCiDl0FxMh2bDhcP/ooQwTRk0J1lMA0GCSqG\n"
		"SIb3DQEBCwUAA4IBAQBROAyWfQyKXQ007U6ctgihHbg/lsfEEfeNPG+QRVt8/e53\n"
		"4fH6scuY9bW7CZQSdiBo178ITHrIOo2CuFMa0ysnW3V1M9/s0dUYjBHYdpTEEQ+d\n"
		"tgm1uRLiTsYeBtueRItEmZU6JjgmvAH8i1UqI0e5iYlfnovPmftpqIwRH7k7A9kS\n"
		"SehC9QkkrnIttDEoeYTGhLOJu1Fx2cwAodce6VNgz/k1zIXY5Tprg440zrCwc+th\n"
		"MpX48F31ggg8Wd5N6Xg1nricGwL8K90ts6xvwF1WwKsg6BeYdyC0eYBqQ41MA/7P\n"
		"DK3OGM6cC5tbQGWaIT0Q407GJBGpaijDicA2YqlK\n"
		"-----END CERTIFICATE-----\n",
};

static void destroy_cert(void *cert)
{
	l_cert_free(cert);
}

static void test_chain_from_data(const void *data)
{
	const struct pem_from_data_test *test = data;
	struct l_queue *twocas;
	struct l_certchain *chain;

	twocas = l_pem_load_certificate_list_from_data(test->list,
							strlen(test->list));
	assert(twocas);

	chain = l_pem_load_certificate_chain_from_data(test->ca,
							strlen(test->ca));
	assert(chain);

	assert(l_certchain_verify(chain, twocas, NULL));

	l_certchain_free(chain);
	l_queue_destroy(twocas, destroy_cert);
}

static void test_priv_key_from_data(const void *data)
{
	bool is_encrypted = false;
	struct l_key *key;

	const char *raw_private_key =
		"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
		"MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIvjkVXsNnUUgCAggA\n"
		"MAwGCCqGSIb3DQILBQAwHQYJYIZIAWUDBAEqBBAQfXcH4tJZzrKM0bmpXyQWBIIE\n"
		"0FwZdv9kfXAZVbPIC2UZLpAqrFqxaaxPMA7FxZrS2sI7QmkXEIfO5TkR8IupYigh\n"
		"s/41jv7V5Mij1syrSodfiYDq3Y0gb9tF9Cb0FNoJwJ9f29X/h1GgnG5NPQBQEH4d\n"
		"zkqCA8Q8tzh8UTGXLcPwKYSmsAK9Rq739qre5qwHY0+hcoCtUfrev4twFUSC/PUj\n"
		"oJDFUxQyVt+WCjcuOG+ugWZSENJJe2O8pAqmt7ChuNKGZTe0UEFn/pxgAAgQYfaz\n"
		"lH/Nx7OQBSVqxdVkFr03/j8eeBy/SzZubirThd0aehwsQTw5/M9rSX8p2ldyjUWF\n"
		"Fb+UjXFFWdOs21rZtO0LcbdZlIVK94mswI4zo+Vv3f7DsAZPgW+Y36UJbzZNtxRl\n"
		"C8t97KH3NozGZIq0znC3CmdYk3EsIlMasp1vgyIpjnsyZcCVtCqbl2+PORv4gZyA\n"
		"9/PMNDNGambIERa4WCLc+Sx5lTryK6wNzQXCMigrpB7yaD+s2CA4OxvdU99iMQzD\n"
		"9/7cRvEQn/qFhcdTpz3wt97Gs51A+IleJbj9l/50sEsfQmcLVlUM3VbKtozUkaV1\n"
		"+5/O15HtMQp0jsjwTlz1AzW5eanPIGoFzLiHKfauzrO5L3i5I2G9GGeCtbUV0+Ts\n"
		"CTwT2kCUnypaNl4D5qdtxe3h+78uW3Yz0f5t4Yw/RlYVSJQZ7irdi3QTgDEEBrpL\n"
		"pOXTd8nRNxZ+zJZ5ifnBB0Ed+cMxmyKcliVnVLSV0KseNn3tKZwmRUtMBiPqKUD1\n"
		"qh8KskfJ0ye8jdcWIubP/gvDh5OgkSz1OdDZKH/RmkktUWCJoyXOMxIz+7GH9u3n\n"
		"n9Z6uAteNTefTJyawA3dwlGvRhySAI2nMl2Aj0g+6/ztpUUjXVx09oxZqh9Bn9k4\n"
		"t+gKaf4osH51QcKFs8J2YcYCwEYilzRAUwyw65Bo/k4myNXA5t2xSWfQIYRY+Yob\n"
		"pmbhOfDMLY1spEVHQ49hXvKE99eP5dyA0CmwZw2gkbXCYBEE1IPthJGYxO4zZdrq\n"
		"AYZq22L+09o0899pnD+p/eDTwKaFenjHVqO71khXurF6q7EPz9m4SkphDSNe/9Tc\n"
		"O11yMrQE9OUBTTd3zYuN8KuZpj2aW2p5/Z7pqCYJTDwlV/+HRmS/8aJ/sgHfYXpS\n"
		"Wpl/SHav6qI7fE5BlKwOwWE6O+vf0Nm9AMsbMErXTFdXe5dAin/uNuFyJM3bTHVO\n"
		"SR/R7/zsNoMJwsgogGMSiFbG1ebcSTgMNHKMFS8RvCBNX44fErW2r0bfNjHU4GgO\n"
		"KJFukksz/6tNfpIi9lU0Xojc7W8CJVdA9RTx8+LClM5nwFQlqyfIrtEXUK5BM+Vz\n"
		"2OI8DlMTpp0+JbSAdE3z1i8cEDFmbfaJ2pNX/1M0JPfcZmZsJiMtNC5Fn6MFBQME\n"
		"Fu1MyJuUr+maOqPLb6c4aYa7gVWpiRwwK8nTe1FofKeEY7mi7PyNJI7pARIDmoD4\n"
		"d5yFZ9Itg/5/XK7GfuRdve1m5/YGpV+u3HWqDnk/xBJ5FhyF9aIPzROYhXkRkVZz\n"
		"rn7DSN3XL2XXtUMle9++kRNmjB8h9GGn4ljunjs9YJBVTb1Y9C9vH1xLh2hknL4M\n"
		"h+XY4w5Os5FZNEkIQd/0gLUwgQRK5+j3aetp085GutPR\n"
		"-----END ENCRYPTED PRIVATE KEY-----\n";

	key = l_pem_load_private_key_from_data(raw_private_key,
						strlen(raw_private_key),
						"abc", &is_encrypted);
	assert(key);
	assert(is_encrypted);

	l_key_free(key);
}

static void test_pem(const void *data)
{
	const struct pem_test *test = data;
	uint8_t *decoded;
	char *label;
	size_t decoded_size;

	decoded = l_pem_load_buffer((const uint8_t *) test->input,
					strlen(test->input), 0,
					&label, &decoded_size);

	if (!test->valid) {
		assert(!decoded);
		return;
	}

	assert(decoded);

	assert(!strcmp(test->label, label));
	assert(decoded_size == test->decoded_size);

	l_free(label);
	l_free(decoded);
}

static void test_encrypted_pkey(const void *data)
{
	const char *encrypted_pem = data;
	const char *plaintext_pem = CERTDIR "cert-client-key-pkcs8.pem";
	bool is_encrypted;
	size_t size;
	uint8_t encrypted1[256], encrypted2[256], plaintext[256];
	struct l_key *pkey1, *pkey2;
	bool is_public;

	is_encrypted = false;
	assert(!l_pem_load_private_key(encrypted_pem, NULL, &is_encrypted));
	assert(is_encrypted);

	is_encrypted = false;
	assert(!l_pem_load_private_key(encrypted_pem, "wrong-passwd",
					&is_encrypted));
	assert(is_encrypted);

	is_encrypted = false;
	pkey1 = l_pem_load_private_key(encrypted_pem, "abc", &is_encrypted);
	assert(pkey1);
	assert(is_encrypted);

	pkey2 = l_pem_load_private_key(plaintext_pem, NULL, &is_encrypted);
	assert(pkey2);
	assert(!is_encrypted);

	/*
	 * l_key_extract doesn't work for private keys so compare encrypt
	 * results instead of key exponent.
	 */
	memset(plaintext, 42, 256);
	assert(l_key_get_info(pkey1, L_KEY_RSA_RAW, L_CHECKSUM_NONE,
				&size, &is_public));
	assert(size == 2048);
	assert(!is_public);
	assert(l_key_encrypt(pkey1, L_KEY_RSA_RAW, L_CHECKSUM_NONE,
				plaintext, encrypted1, 256, 256) == 256);
	assert(l_key_encrypt(pkey2, L_KEY_RSA_RAW, L_CHECKSUM_NONE,
				plaintext, encrypted2, 256, 256) == 256);
	assert(!memcmp(encrypted1, encrypted2, 256));

	l_key_free(pkey1);
	l_key_free(pkey2);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("pem/invalid header/test 1", test_pem, &invalid_header1);
	l_test_add("pem/invalid header/test 2", test_pem, &invalid_header2);

	l_test_add("pem/empty", test_pem, &empty);

	l_test_add("pem/empty label", test_pem, &empty_label);
	l_test_add("pem/cert chain from data", test_chain_from_data,
			&single_line_cert_chain);
	l_test_add("pem/private key from data", test_priv_key_from_data, NULL);

	if (!l_checksum_is_supported(L_CHECKSUM_MD5, false) ||
			!l_checksum_is_supported(L_CHECKSUM_SHA1, false) ||
			!l_cipher_is_supported(L_CIPHER_DES_CBC) ||
			!l_key_is_supported(L_KEY_FEATURE_CRYPTO))
		goto done;

	l_test_add("pem/v1 MD5AndDES encrypted Private Key",
			test_encrypted_pkey,
			CERTDIR "cert-client-key-md5-des.pem");
	l_test_add("pem/v1 SHA1AndDES encrypted Private Key",
			test_encrypted_pkey,
			CERTDIR "cert-client-key-sha1-des.pem");
	l_test_add("pem/v2 DES encrypted Private Key", test_encrypted_pkey,
			CERTDIR "cert-client-key-v2-des.pem");

	if (l_cipher_is_supported(L_CIPHER_DES3_EDE_CBC) &&
			l_checksum_is_supported(L_CHECKSUM_SHA224, false))
		l_test_add("pem/v2 DES EDE3 encrypted Private Key",
				test_encrypted_pkey,
				CERTDIR "cert-client-key-v2-des-ede3.pem");

	if (!l_cipher_is_supported(L_CIPHER_AES))
		goto done;

	if (l_checksum_is_supported(L_CHECKSUM_SHA256, false))
		l_test_add("pem/v2 AES128 encrypted Private Key",
				test_encrypted_pkey,
				CERTDIR "cert-client-key-v2-aes128.pem");

	if (l_checksum_is_supported(L_CHECKSUM_SHA512, false))
		l_test_add("pem/v2 AES256 encrypted Private Key",
				test_encrypted_pkey,
				CERTDIR "cert-client-key-v2-aes256.pem");

done:
	return l_test_run();
}
