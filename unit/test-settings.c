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

#include <assert.h>
#include <stdio.h>
#include <limits.h>

#include <ell/ell.h>

#define TEST_CERTIFICATE \
	"-----BEGIN CERTIFICATE-----\n" \
	"MIIEajCCA1KgAwIBAgIUKIOXQXEyHZsOFw/+ihDBNGTQnWUwDQYJKoZIhvcNAQEL\n" \
	"BQAweDE1MDMGA1UECgwsSW50ZXJuYXRpb25hbCBVbmlvbiBvZiBFeGFtcGxlIE9y\n" \
	"Z2FuaXphdGlvbnMxHzAdBgNVBAMMFkNlcnRpZmljYXRlIGlzc3VlciBndXkxHjAc\n" \
	"BgkqhkiG9w0BCQEWD2NhQG1haWwuZXhhbXBsZTAeFw0xOTA5MTYxNzEyNThaFw00\n" \
	"NzAyMDExNzEyNThaMHgxNTAzBgNVBAoMLEludGVybmF0aW9uYWwgVW5pb24gb2Yg\n" \
	"RXhhbXBsZSBPcmdhbml6YXRpb25zMR8wHQYDVQQDDBZDZXJ0aWZpY2F0ZSBpc3N1\n" \
	"ZXIgZ3V5MR4wHAYJKoZIhvcNAQkBFg9jYUBtYWlsLmV4YW1wbGUwggEiMA0GCSqG\n" \
	"SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCjovj3aq26sAQ0k5vD/BVp40p0lhz1+Wet\n" \
	"1EcdQa1arVIca9nhfvoHfJAmK+zzqQLbvI0/e2if4X6OKf41g7w7VaYS9qv5jZZ0\n" \
	"v/7aL6PUa2F7C9HG/vuIII/dRvP2uQ43PLxeTeZyj7bBUB9xCFCpzB+7AZuUuH0H\n" \
	"ABaC9CAGZWImBY5NUXST7E/BsvqU80KJglDovcabthvwoekji9DC/wwISLE1e9cO\n" \
	"A9IB0Co0mA1ME6wzrawmuTzxUw9BsmEhbKhFGBRwIrrq0r4GvDmeMFiZjXv+I0vq\n" \
	"wSCyRtgoeBmyemqIEgiN4Z23V7ps3dbYF/tw96Zj7rd5gtjY9VSdAgMBAAGjgesw\n" \
	"gegwDwYDVR0TBAgwBgEB/wIBADAdBgNVHQ4EFgQUnvllvvxy17VqqR0FfgS4NwzX\n" \
	"jScwgbUGA1UdIwSBrTCBqoAUnvllvvxy17VqqR0FfgS4NwzXjSehfKR6MHgxNTAz\n" \
	"BgNVBAoMLEludGVybmF0aW9uYWwgVW5pb24gb2YgRXhhbXBsZSBPcmdhbml6YXRp\n" \
	"b25zMR8wHQYDVQQDDBZDZXJ0aWZpY2F0ZSBpc3N1ZXIgZ3V5MR4wHAYJKoZIhvcN\n" \
	"AQkBFg9jYUBtYWlsLmV4YW1wbGWCFCiDl0FxMh2bDhcP/ooQwTRk0J1lMA0GCSqG\n" \
	"SIb3DQEBCwUAA4IBAQBROAyWfQyKXQ007U6ctgihHbg/lsfEEfeNPG+QRVt8/e53\n" \
	"4fH6scuY9bW7CZQSdiBo178ITHrIOo2CuFMa0ysnW3V1M9/s0dUYjBHYdpTEEQ+d\n" \
	"tgm1uRLiTsYeBtueRItEmZU6JjgmvAH8i1UqI0e5iYlfnovPmftpqIwRH7k7A9kS\n" \
	"SehC9QkkrnIttDEoeYTGhLOJu1Fx2cwAodce6VNgz/k1zIXY5Tprg440zrCwc+th\n" \
	"MpX48F31ggg8Wd5N6Xg1nricGwL8K90ts6xvwF1WwKsg6BeYdyC0eYBqQ41MA/7P\n" \
	"DK3OGM6cC5tbQGWaIT0Q407GJBGpaijDicA2YqlK\n" \
	"-----END CERTIFICATE-----\n"

#define TEST_CERT_LIST \
	"-----BEGIN CERTIFICATE-----\n" \
	"MIIEXDCCA0SgAwIBAgIJALjNE85c9plgMA0GCSqGSIb3DQEBCwUAMHgxNTAzBgNV\n" \
	"BAoMLEludGVybmF0aW9uYWwgVW5pb24gb2YgRXhhbXBsZSBPcmdhbml6YXRpb25z\n" \
	"MR8wHQYDVQQDDBZDZXJ0aWZpY2F0ZSBpc3N1ZXIgZ3V5MR4wHAYJKoZIhvcNAQkB\n" \
	"Fg9jYUBtYWlsLmV4YW1wbGUwHhcNMTkwOTE2MTcxMzAzWhcNNDcwMjAxMTcxMzAz\n" \
	"WjB4MTUwMwYDVQQKDCxJbnRlcm5hdGlvbmFsIFVuaW9uIG9mIEV4YW1wbGUgT3Jn\n" \
	"YW5pemF0aW9uczEfMB0GA1UEAwwWQ2VydGlmaWNhdGUgaXNzdWVyIGd1eTEeMBwG\n" \
	"CSqGSIb3DQEJARYPY2FAbWFpbC5leGFtcGxlMIIBIjANBgkqhkiG9w0BAQEFAAOC\n" \
	"AQ8AMIIBCgKCAQEA7Lft5O6BtUUokuueQ7mBQVzRzPeH0Nl3NjgGnfBYcz7O2Jca\n" \
	"rFSBPsV76reUG4QFQudsdwyaLOpniFFSFaI3GRXMxjwZJJjLqvT0aebTiLUSKseA\n" \
	"QkP/NSITmIljs2yclnPJGIApLuFvykPagx+yc9ckbziEz1PvKB/ukbiU/zt6QCru\n" \
	"BbyCQ1kWBuyrS3RC0/UgmrSbL7YkkmuD2B1vyZLIoPsJijXs2GJQY3a+zpLemTth\n" \
	"i/Vw4AURJS1gfEUDNzf9Y9+o7vWJfzk+g7xm1XpMTsNTd7q6UwHOi1xdiKCEPT+q\n" \
	"c3LXi7qgWqSXeD+F513PM3JMJ3Wk1H8K4VwJwQIDAQABo4HoMIHlMAwGA1UdEwQF\n" \
	"MAMBAf8wHQYDVR0OBBYEFMuhnjqw8YGMg0cyYlQppMncWis/MIG1BgNVHSMEga0w\n" \
	"gaqAFJ75Zb78cte1aqkdBX4EuDcM140noXykejB4MTUwMwYDVQQKDCxJbnRlcm5h\n" \
	"dGlvbmFsIFVuaW9uIG9mIEV4YW1wbGUgT3JnYW5pemF0aW9uczEfMB0GA1UEAwwW\n" \
	"Q2VydGlmaWNhdGUgaXNzdWVyIGd1eTEeMBwGCSqGSIb3DQEJARYPY2FAbWFpbC5l\n" \
	"eGFtcGxlghQog5dBcTIdmw4XD/6KEME0ZNCdZTANBgkqhkiG9w0BAQsFAAOCAQEA\n" \
	"PjX5n/fgkskZmh9aRhX8r9985JtxMdgogJP4uwRbfuQPzAqYyu9QlAOcRl6tNGN7\n" \
	"mztB5RfJ9HDyjS9iGXsvKXS8wT5ELbuATev+C1Ppxakd3gvJMN4ZqYn32JqRYigN\n" \
	"L2V2jo9RzVUuFa3YP6sw0KfZAfHsfUmQCxAm8HAfQg98aYyIXu/OzeVUsAuhfqWN\n" \
	"qvWcOLjTQTn6t10OHHdIYw59EpIEOPD3Opq7pLgIm+EV3eVMWthSLYbEhIavh8Pc\n" \
	"xN9lqCg887kTawbXbXd49Z8jYZxjxQl7IoonvIyrPhhabKjKCpE2bRFzzpia0PkC\n" \
	"fRgh+KB2tqIeAoekDllmbA==\n" \
	"-----END CERTIFICATE-----\n" \
	"-----BEGIN CERTIFICATE-----\n" \
	"MIIEajCCA1KgAwIBAgIUKIOXQXEyHZsOFw/+ihDBNGTQnWUwDQYJKoZIhvcNAQEL\n" \
	"BQAweDE1MDMGA1UECgwsSW50ZXJuYXRpb25hbCBVbmlvbiBvZiBFeGFtcGxlIE9y\n" \
	"Z2FuaXphdGlvbnMxHzAdBgNVBAMMFkNlcnRpZmljYXRlIGlzc3VlciBndXkxHjAc\n" \
	"BgkqhkiG9w0BCQEWD2NhQG1haWwuZXhhbXBsZTAeFw0xOTA5MTYxNzEyNThaFw00\n" \
	"NzAyMDExNzEyNThaMHgxNTAzBgNVBAoMLEludGVybmF0aW9uYWwgVW5pb24gb2Yg\n" \
	"RXhhbXBsZSBPcmdhbml6YXRpb25zMR8wHQYDVQQDDBZDZXJ0aWZpY2F0ZSBpc3N1\n" \
	"ZXIgZ3V5MR4wHAYJKoZIhvcNAQkBFg9jYUBtYWlsLmV4YW1wbGUwggEiMA0GCSqG\n" \
	"SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCjovj3aq26sAQ0k5vD/BVp40p0lhz1+Wet\n" \
	"1EcdQa1arVIca9nhfvoHfJAmK+zzqQLbvI0/e2if4X6OKf41g7w7VaYS9qv5jZZ0\n" \
	"v/7aL6PUa2F7C9HG/vuIII/dRvP2uQ43PLxeTeZyj7bBUB9xCFCpzB+7AZuUuH0H\n" \
	"ABaC9CAGZWImBY5NUXST7E/BsvqU80KJglDovcabthvwoekji9DC/wwISLE1e9cO\n" \
	"A9IB0Co0mA1ME6wzrawmuTzxUw9BsmEhbKhFGBRwIrrq0r4GvDmeMFiZjXv+I0vq\n" \
	"wSCyRtgoeBmyemqIEgiN4Z23V7ps3dbYF/tw96Zj7rd5gtjY9VSdAgMBAAGjgesw\n" \
	"gegwDwYDVR0TBAgwBgEB/wIBADAdBgNVHQ4EFgQUnvllvvxy17VqqR0FfgS4NwzX\n" \
	"jScwgbUGA1UdIwSBrTCBqoAUnvllvvxy17VqqR0FfgS4NwzXjSehfKR6MHgxNTAz\n" \
	"BgNVBAoMLEludGVybmF0aW9uYWwgVW5pb24gb2YgRXhhbXBsZSBPcmdhbml6YXRp\n" \
	"b25zMR8wHQYDVQQDDBZDZXJ0aWZpY2F0ZSBpc3N1ZXIgZ3V5MR4wHAYJKoZIhvcN\n" \
	"AQkBFg9jYUBtYWlsLmV4YW1wbGWCFCiDl0FxMh2bDhcP/ooQwTRk0J1lMA0GCSqG\n" \
	"SIb3DQEBCwUAA4IBAQBROAyWfQyKXQ007U6ctgihHbg/lsfEEfeNPG+QRVt8/e53\n" \
	"4fH6scuY9bW7CZQSdiBo178ITHrIOo2CuFMa0ysnW3V1M9/s0dUYjBHYdpTEEQ+d\n" \
	"tgm1uRLiTsYeBtueRItEmZU6JjgmvAH8i1UqI0e5iYlfnovPmftpqIwRH7k7A9kS\n" \
	"SehC9QkkrnIttDEoeYTGhLOJu1Fx2cwAodce6VNgz/k1zIXY5Tprg440zrCwc+th\n" \
	"MpX48F31ggg8Wd5N6Xg1nricGwL8K90ts6xvwF1WwKsg6BeYdyC0eYBqQ41MA/7P\n" \
	"DK3OGM6cC5tbQGWaIT0Q407GJBGpaijDicA2YqlK\n" \
	"-----END CERTIFICATE-----\n"

#define TEST_PRIV_KEY \
	"-----BEGIN ENCRYPTED PRIVATE KEY-----\n" \
	"MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIvjkVXsNnUUgCAggA\n" \
	"MAwGCCqGSIb3DQILBQAwHQYJYIZIAWUDBAEqBBAQfXcH4tJZzrKM0bmpXyQWBIIE\n" \
	"0FwZdv9kfXAZVbPIC2UZLpAqrFqxaaxPMA7FxZrS2sI7QmkXEIfO5TkR8IupYigh\n" \
	"s/41jv7V5Mij1syrSodfiYDq3Y0gb9tF9Cb0FNoJwJ9f29X/h1GgnG5NPQBQEH4d\n" \
	"zkqCA8Q8tzh8UTGXLcPwKYSmsAK9Rq739qre5qwHY0+hcoCtUfrev4twFUSC/PUj\n" \
	"oJDFUxQyVt+WCjcuOG+ugWZSENJJe2O8pAqmt7ChuNKGZTe0UEFn/pxgAAgQYfaz\n" \
	"lH/Nx7OQBSVqxdVkFr03/j8eeBy/SzZubirThd0aehwsQTw5/M9rSX8p2ldyjUWF\n" \
	"Fb+UjXFFWdOs21rZtO0LcbdZlIVK94mswI4zo+Vv3f7DsAZPgW+Y36UJbzZNtxRl\n" \
	"C8t97KH3NozGZIq0znC3CmdYk3EsIlMasp1vgyIpjnsyZcCVtCqbl2+PORv4gZyA\n" \
	"9/PMNDNGambIERa4WCLc+Sx5lTryK6wNzQXCMigrpB7yaD+s2CA4OxvdU99iMQzD\n" \
	"9/7cRvEQn/qFhcdTpz3wt97Gs51A+IleJbj9l/50sEsfQmcLVlUM3VbKtozUkaV1\n" \
	"+5/O15HtMQp0jsjwTlz1AzW5eanPIGoFzLiHKfauzrO5L3i5I2G9GGeCtbUV0+Ts\n" \
	"CTwT2kCUnypaNl4D5qdtxe3h+78uW3Yz0f5t4Yw/RlYVSJQZ7irdi3QTgDEEBrpL\n" \
	"pOXTd8nRNxZ+zJZ5ifnBB0Ed+cMxmyKcliVnVLSV0KseNn3tKZwmRUtMBiPqKUD1\n" \
	"qh8KskfJ0ye8jdcWIubP/gvDh5OgkSz1OdDZKH/RmkktUWCJoyXOMxIz+7GH9u3n\n" \
	"n9Z6uAteNTefTJyawA3dwlGvRhySAI2nMl2Aj0g+6/ztpUUjXVx09oxZqh9Bn9k4\n" \
	"t+gKaf4osH51QcKFs8J2YcYCwEYilzRAUwyw65Bo/k4myNXA5t2xSWfQIYRY+Yob\n" \
	"pmbhOfDMLY1spEVHQ49hXvKE99eP5dyA0CmwZw2gkbXCYBEE1IPthJGYxO4zZdrq\n" \
	"AYZq22L+09o0899pnD+p/eDTwKaFenjHVqO71khXurF6q7EPz9m4SkphDSNe/9Tc\n" \
	"O11yMrQE9OUBTTd3zYuN8KuZpj2aW2p5/Z7pqCYJTDwlV/+HRmS/8aJ/sgHfYXpS\n" \
	"Wpl/SHav6qI7fE5BlKwOwWE6O+vf0Nm9AMsbMErXTFdXe5dAin/uNuFyJM3bTHVO\n" \
	"SR/R7/zsNoMJwsgogGMSiFbG1ebcSTgMNHKMFS8RvCBNX44fErW2r0bfNjHU4GgO\n" \
	"KJFukksz/6tNfpIi9lU0Xojc7W8CJVdA9RTx8+LClM5nwFQlqyfIrtEXUK5BM+Vz\n" \
	"2OI8DlMTpp0+JbSAdE3z1i8cEDFmbfaJ2pNX/1M0JPfcZmZsJiMtNC5Fn6MFBQME\n" \
	"Fu1MyJuUr+maOqPLb6c4aYa7gVWpiRwwK8nTe1FofKeEY7mi7PyNJI7pARIDmoD4\n" \
	"d5yFZ9Itg/5/XK7GfuRdve1m5/YGpV+u3HWqDnk/xBJ5FhyF9aIPzROYhXkRkVZz\n" \
	"rn7DSN3XL2XXtUMle9++kRNmjB8h9GGn4ljunjs9YJBVTb1Y9C9vH1xLh2hknL4M\n" \
	"h+XY4w5Os5FZNEkIQd/0gLUwgQRK5+j3aetp085GutPR\n" \
	"-----END ENCRYPTED PRIVATE KEY-----\n"

static const char *data1 = "[Foobar]\n#Comment\n#Comment2\nKey=Value\n"
		"IntegerA=2147483647\nIntegerB=-2147483648\n"
		"IntegerC=4294967295\nIntegerD=9223372036854775807\n"
		"IntegerE=-9223372036854775808\n"
		"IntegerF=18446744073709551615\n"
		"IntegerG=2247483647\nIntegerH=4294967296\n"
		"IntegerI=9223372036854775808\n"
		"IntegerJ=18446744073709551616\n"
		"String=\\tFoobar\\s\n"
		"StringEmpty=\n"
		"StringBad1=Foobar\\\n"
		"StringBad2=Foobar\\b123\n"
		"StringList=Foo,Bar,Baz\n"
		"StringListEmpty=\n"
		"StringListOne=FooBarBaz\n"
		"StringWithSpaces=Bar B Q\n\n"
		"[@pem@certificate]\n"
		TEST_CERTIFICATE;

static const char *data2 = "[Group1]\nKey=Value\n"
			"IntegerA=2147483647\nIntegerB=-2147483648\n"
			"IntegerC=4294967295\nIntegerD=9223372036854775807\n"
			"IntegerE=-9223372036854775808\n"
			"IntegerF=18446744073709551615\n"
			"IntegerG=2247483647\nIntegerH=4294967296\n"
			"String=\\tFoobar\\s\n"
			"StringEmpty=\n"
			"StringBad1=Foobar\\\n"
			"StringBad2=Foobar\\b123\n"
			"StringList=Foo,Bar,Baz\n"
			"StringListEmpty=\n"
			"StringListOne=FooBarBaz\n\n"
			"[Group2]\nKey=Value\n\n"
			"[@pem@example]\n"
			"-----BEGIN CERTIFICATE-----\n"
			"MIIEajCCA1KgAwIBAgoZIhvcNAQEL\n"
			"-----END CERTIFICATE-----\n";

static void settings_debug(const char *str, void *userdata)
{
	printf("%s\n", str);
}

static void test_settings(struct l_settings *settings)
{
	int int32;
	unsigned int uint32;
	int64_t int64;
	uint64_t uint64;
	char *str;
	char **strv;

	assert(l_settings_has_group(settings, "Foobar"));
	assert(!l_settings_has_group(settings, "Foobar2"));

	assert(l_settings_has_key(settings, "Foobar", "Key"));
	assert(!l_settings_has_key(settings, "Foobar", "Key2"));

	assert(!l_settings_get_bool(settings, "Foobar", "Key", NULL));

	assert(l_settings_get_int(settings, "Foobar", "IntegerA", &int32));
	assert(l_settings_get_int(settings, "Foobar", "IntegerB", &int32));
	assert(l_settings_get_uint(settings, "Foobar", "IntegerC", &uint32));
	assert(l_settings_get_int64(settings, "Foobar", "IntegerD", &int64));
	assert(l_settings_get_int64(settings, "Foobar", "IntegerE", &int64));
	assert(l_settings_get_uint64(settings, "Foobar", "IntegerF", &uint64));
	assert(!l_settings_get_int(settings, "Foobar", "IntegerG", &int32));
	assert(!l_settings_get_uint(settings, "Foobar", "FoobarH", &uint32));
	assert(!l_settings_get_int64(settings, "Foobar", "IntegerI", &int64));
	assert(!l_settings_get_uint64(settings, "Foobar", "IntegerJ", &uint64));

	str = l_settings_get_string(settings, "Foobar", "String");
	assert(str);
	assert(!strcmp(str, "\tFoobar "));
	l_free(str);

	str = l_settings_get_string(settings, "Foobar", "StringEmpty");
	assert(str);
	assert(!strcmp(str, ""));
	l_free(str);

	str = l_settings_get_string(settings, "Foobar", "StringBad1");
	assert(!str);

	str = l_settings_get_string(settings, "Foobar", "StringBad2");
	assert(!str);

	strv = l_settings_get_string_list(settings, "Foobar",
						"StringList", ',');
	assert(strv);
	assert(!strcmp(strv[0], "Foo"));
	assert(!strcmp(strv[1], "Bar"));
	assert(!strcmp(strv[2], "Baz"));
	assert(strv[3] == NULL);
	l_strfreev(strv);

	strv = l_settings_get_string_list(settings, "Foobar", "StringListEmpty",						',');
	assert(strv);
	assert(strv[0] == NULL);
	l_strfreev(strv);

	strv = l_settings_get_string_list(settings, "Foobar", "StringListOne",
						',');
	assert(strv);
	assert(strv[0]);
	assert(!strcmp(strv[0], "FooBarBaz"));
	assert(strv[1] == NULL);
	l_strfreev(strv);

	str = l_settings_get_string(settings, "Foobar", "StringWithSpaces");
	assert(str);
	assert(!strcmp(str, "Bar B Q"));
	l_free(str);

	strv = l_settings_get_groups(settings);
	assert(strv);
	assert(!strcmp(strv[0], "Foobar"));
	assert(!l_settings_has_embedded_group(settings, strv[0]));
	assert(!strv[1]);
	l_strfreev(strv);

	strv = l_settings_get_embedded_groups(settings);
	assert(strv);
	assert(!strcmp(strv[0], "certificate"));
	assert(l_settings_has_embedded_group(settings, "certificate"));
	assert(!strv[1]);
	l_strfreev(strv);

	assert(!l_settings_get_keys(settings, "Nonexistent"));

	strv = l_settings_get_keys(settings, "Foobar");
	assert(strv);
	l_strfreev(strv);

	assert(!l_settings_remove_key(settings, "Bar", "Foo"));
	assert(!l_settings_remove_key(settings, "Foobar", "Nonexistent"));
	assert(l_settings_remove_key(settings, "Foobar", "Key"));
	assert(!l_settings_has_key(settings, "Foobar", "Key"));

	assert(!l_settings_remove_group(settings, "Bar"));
	assert(l_settings_remove_group(settings, "Foobar"));
	assert(!l_settings_has_group(settings, "Foobar"));
}

static void test_valid_extended_group(const void *test_data)
{
	const char *raw_data =
			"[normal]\n"
			"key=value\n"
			"[@pem@single_cert]\n"
			TEST_CERTIFICATE
			"[next_group]\n"
			"another_key=another_value\n"
			"[@pem@two_certs]\n"
			TEST_CERT_LIST
			"\n"
			"[group_after_list]\n"
			"key=value\n\n\n\n"
			"[@pem@priv_key]\n"
			TEST_PRIV_KEY
			"\n\n\n\n";
	struct l_settings *settings = l_settings_new();
	const char *certificate = TEST_CERTIFICATE;
	const char *two_certs = TEST_CERT_LIST;
	const char *priv_key = TEST_PRIV_KEY;
	const char *test_cert;
	const char *out_type;

	assert(l_settings_load_from_data(settings, raw_data, strlen(raw_data)));

	assert(l_settings_has_group(settings, "normal"));
	assert(l_settings_has_group(settings, "next_group"));
	assert(!l_settings_get_value(settings, "single_cert", "value"));

	assert(l_settings_has_embedded_group(settings, "single_cert"));
	test_cert = l_settings_get_embedded_value(settings, "single_cert", &out_type);
	assert(test_cert);
	assert(!strcmp(test_cert, certificate));

	assert(l_settings_has_embedded_group(settings, "two_certs"));
	test_cert = l_settings_get_embedded_value(settings, "two_certs", &out_type);
	assert(!strcmp(test_cert, two_certs));

	assert(l_settings_has_embedded_group(settings, "priv_key"));
	test_cert = l_settings_get_embedded_value(settings, "priv_key", &out_type);
	assert(!strcmp(test_cert, priv_key));

	l_settings_free(settings);
}

static void test_invalid_extended_group(const void *test_data)
{
	int i = 0;
	const char *invalid_data[] = {
			/* Unterminated PEM */
			"[normal]\n"
			"key=value\n"
			"[@pem@unterminated_pem]\n"
			"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
			"MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhki",
			/* Invalid ext type */
			"[normal]\n"
			"key=value\n"
			"[@invalid@name]\n"
			"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
			"-----END ENCRYPTED PRIVATE KEY-----\n",
			/* Valid ext type, invalid name */
			"[normal]\n"
			"key=value\n"
			"[@pem@]\n"
			"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
			"-----END ENCRYPTED PRIVATE KEY-----\n",
			/* Invalid ext type */
			"[normal]\n"
			"key=value\n"
			"[@@some_name]\n"
			"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
			"-----END ENCRYPTED PRIVATE KEY-----\n",
			/* second PEM invalid */
			"[normal]\n"
			"key=value\n"
			"[@pem@two_pems]\n"
			"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
			"MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhki\n"
			"-----END ENCRYPTED PRIVATE KEY-----\n"
			"-----BEGIN \n",
			/* end boundary only */
			"[normal]\n"
			"key=value\n"
			"[@pem@two_pems]\n"
			"-----END ENCRYPTED PRIVATE KEY-----\n",
			/* No terminating newline */
			"[normal]\n"
			"key=value\n"
			"[@pem@certs]\n"
			"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
			"MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhki\n"
			"-----END ENCRYPTED PRIVATE KEY-----",
			NULL
	};

	struct l_settings *settings = l_settings_new();

	while (invalid_data[i]) {
		assert(!l_settings_load_from_data(settings, invalid_data[i],
						strlen(invalid_data[i])));
		i++;
	}

	l_settings_free(settings);
}

static void test_load_from_data(const void *test_data)
{
	struct l_settings *settings;

	settings = l_settings_new();

	l_settings_set_debug(settings, settings_debug, NULL, NULL);
	l_settings_load_from_data(settings, data1, strlen(data1));

	test_settings(settings);

	l_settings_free(settings);
}

static void test_load_from_file(const void *test_data)
{
	struct l_settings *settings;

	settings = l_settings_new();

	l_settings_set_debug(settings, settings_debug, NULL, NULL);
	assert(l_settings_load_from_file(settings, UNITDIR "settings.test"));

	test_settings(settings);

	l_settings_free(settings);
}

static void test_set_methods(const void *test_data)
{
	struct l_settings *settings;
	int int32;
	unsigned int uint32;
	int64_t int64;
	uint64_t uint64;
	bool b;
	const char *v;
	char *s;

	settings = l_settings_new();

	l_settings_set_debug(settings, settings_debug, NULL, NULL);

	/* Integer tests */
	assert(l_settings_set_int(settings, "Main", "Integers", -15));
	assert(l_settings_get_int(settings, "Main", "Integers", &int32));
	assert(int32 == -15);
	v = l_settings_get_value(settings, "Main", "Integers");
	assert(v);
	assert(!strcmp(v, "-15"));

	assert(l_settings_set_uint(settings, "Main", "Integers", 15));
	assert(l_settings_get_uint(settings, "Main", "Integers", &uint32));
	assert(uint32 == 15);
	v = l_settings_get_value(settings, "Main", "Integers");
	assert(v);
	assert(!strcmp(v, "15"));

	assert(l_settings_set_int64(settings, "Main", "Integers", -2423492340ll));
	assert(l_settings_get_int64(settings, "Main", "Integers", &int64));
	assert(int64 == -2423492340ll);
	v = l_settings_get_value(settings, "Main", "Integers");
	assert(v);
	assert(!strcmp(v, "-2423492340"));

	assert(l_settings_set_uint64(settings, "Main", "Integers", 2423492340ul));
	assert(l_settings_get_uint64(settings, "Main", "Integers", &uint64));
	assert(uint64 == 2423492340ul);
	v = l_settings_get_value(settings, "Main", "Integers");
	assert(v);
	assert(!strcmp(v, "2423492340"));

	/* Boolean tests */
	assert(l_settings_set_bool(settings, "Main", "Boolean", true));
	assert(l_settings_get_bool(settings, "Main", "Boolean", &b));
	assert(b == true);
	v = l_settings_get_value(settings, "Main", "Boolean");
	assert(v);
	assert(!strcmp(v, "true"));

	assert(l_settings_set_bool(settings, "Main", "Boolean", false));
	assert(l_settings_get_bool(settings, "Main", "Boolean", &b));
	assert(b == false);
	v = l_settings_get_value(settings, "Main", "Boolean");
	assert(v);
	assert(!strcmp(v, "false"));

	/* String tests */
	assert(l_settings_set_string(settings, "Main", "String", "  \tFoobar"));
	s = l_settings_get_string(settings, "Main", "String");
	assert(s);
	assert(!strcmp(s, "  \tFoobar"));
	l_free(s);
	v = l_settings_get_value(settings, "Main", "String");
	assert(v);
	assert(!strcmp(v, "\\s\\s\\tFoobar"));

	assert(l_settings_set_string(settings, "Main", "Escapes",
					" \\Text\t\n\r\\"));
	s = l_settings_get_string(settings, "Main", "Escapes");
	assert(s);
	assert(!strcmp(s, " \\Text\t\n\r\\"));
	l_free(s);
	v = l_settings_get_value(settings, "Main", "Escapes");
	assert(v);
	assert(!strcmp(v, "\\s\\\\Text\t\\n\\r\\\\"));

	l_settings_free(settings);
}

static void test_to_data(const void *test_data)
{
	const char *data = test_data;
	struct l_settings *settings;
	char *res;
	size_t res_len;

	settings = l_settings_new();

	l_settings_set_debug(settings, settings_debug, NULL, NULL);
	l_settings_load_from_data(settings, data2, strlen(data2));

	res = l_settings_to_data(settings, &res_len);

	assert(!strcmp(res, data));
	l_free(res);

	l_settings_free(settings);
}

static const char *no_group_data = "key_without_group=value\n";
static const char *key_before_group_data = "key_without_group=value\n"
						"[GROUP]\n"
						"valid_key=value\n";

static void test_invalid_data(const void *test_data)
{
	const char *data = test_data;
	struct l_settings *settings;
	bool r;

	settings = l_settings_new();

	r = l_settings_load_from_data(settings, data, strlen(data));
	assert(r == false);

	l_settings_free(settings);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("Load from Data", test_load_from_data, NULL);
	l_test_add("Load from File", test_load_from_file, NULL);
	l_test_add("Set Methods", test_set_methods, NULL);
	l_test_add("Export to Data 1", test_to_data, data2);
	l_test_add("Invalid Data 1", test_invalid_data, no_group_data);
	l_test_add("Invalid Data 2", test_invalid_data, key_before_group_data);
	l_test_add("Test valid ext group", test_valid_extended_group, NULL);
	l_test_add("Test invalid ext group", test_invalid_extended_group, NULL);


	return l_test_run();
}
