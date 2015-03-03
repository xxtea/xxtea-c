/**********************************************************\
|                                                          |
| xxtea.c                                                  |
|                                                          |
| XXTEA encryption algorithm library for Golang.           |
|                                                          |
| Encryption Algorithm Authors:                            |
|      David J. Wheeler                                    |
|      Roger M. Needham                                    |
|                                                          |
| Code Author: Ma Bingyao <mabingyao@gmail.com>            |
| LastModified: Mar 3, 2015                                |
|                                                          |
\**********************************************************/


#include "xxtea.h"

#include <stddef.h>
#if defined(_MSC_VER) && _MSC_VER < 1600
typedef unsigned __int8 uint8_t;
typedef unsigned __int32 uint32_t;
#else
#include <stdint.h>
#endif

#define MX (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z))
#define DELTA 0x9e3779b9

/**
 * Method:   xxtea_to_uint_array
 * @data:    Data to be converted
 * @len:     Length of the data to be converted
 * @inc_len: Including the length of the information?
 * @out_len: Pointer to output length variable
 * Returns:  UInt array or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer.
 */
uint32_t * xxtea_to_uint_array(const uint8_t * data, size_t len, int inc_len, size_t * out_len)
{
    uint32_t *out;
    size_t i, n;

    n = (((len & 3) == 0) ? (len >> 2) : ((len >> 2) + 1));

    if (inc_len)
    {
        out = (uint32_t *)calloc(n + 1, sizeof(uint32_t));
        if (!out) return NULL;
        out[n] = (uint32_t)len;
        *out_len = n + 1;
    }
    else
    {
        out = (uint32_t *)calloc(n, sizeof(uint32_t));
        if (!out) return NULL;
        *out_len = n;
    }

    for (i = 0; i < len; i++)
    {
        out[i >> 2] |= (uint32_t)data[i] << ((i & 3) << 3);
    }

    return out;
}

/**
 * Method:   xxtea_to_ubyte_array
 * @data:    Data to be converted
 * @len:     Length of the data to be converted
 * @inc_len: Included the length of the information?
 * @out_len: Pointer to output length variable
 * Returns:  UByte array or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer.
 */
uint8_t * xxtea_to_ubyte_array(const uint32_t * data, size_t len, int inc_len, size_t * out_len)
{
    uint8_t *out;
    size_t i, m, n;

    n = len << 2;

    if (inc_len)
    {
        m = data[len - 1];
        if (m > n) return NULL;
        n = m;
    }

    out = (uint8_t *)malloc(n + 1);

    for (i = 0; i < n; i++)
    {
        out[i] = (uint8_t)(data[i >> 2] >> ((i & 3) << 3));
    }

    out[n] = '\0';
    *out_len = n;

    return out;
}

/**
 * Method:  xxtea_uint_encrypt
 * @data:   Data to be encrypted
 * @len:    Length of the data to be encrypted
 * @key:    Symmetric key
 * Returns: Encrypted data
 */
uint32_t * xxtea_uint_encrypt(uint32_t * data, size_t len, uint32_t * key)
{
    uint32_t n = (uint32_t)len - 1;
    uint32_t z = data[n], y = data[0], p, q = 6 + 52 / (n + 1), sum = 0, e;

    if (n < 1) return data;

    while (0 < q--)
    {
        sum += DELTA;
        e = sum >> 2 & 3;

        for (p = 0; p < n; p++)
        {
            y = data[p + 1];
            z = data[p] += MX;
        }

        y = data[0];
        z = data[n] += MX;
    }

    return data;
}

/**
 * Method:  xxtea_uint_decrypt
 * @data:   Data to be decrypted
 * @len:    Length of the data to be decrypted
 * @key:    Symmetric key
 * Returns: Decrypted data
 */
uint32_t * xxtea_uint_decrypt(uint32_t * data, size_t len, uint32_t * key)
{
    uint32_t n = (uint32_t)len - 1;
    uint32_t z = data[n], y = data[0], p, q = 6 + 52 / (n + 1), sum = q * DELTA, e;

    if (n < 1) return data;

    while (sum != 0)
    {
        e = sum >> 2 & 3;

        for (p = n; p > 0; p--)
        {
            z = data[p - 1];
            y = data[p] -= MX;
        }

        z = data[n];
        y = data[0] -= MX;
        sum -= DELTA;
    }

    return data;
}

/**
 * Method:   xxtea_encrypt
 * @data:    Data to be encrypted
 * @len:     Length of the data to be encrypted
 * @key:     Symmetric key
 * @out_len: Pointer to output length variable
 * Returns:  Encrypted data or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer.
 */
uint8_t * xxtea_encrypt_ubyte(const uint8_t * data, size_t len, const uint8_t * key, size_t * out_len)
{
    uint8_t *out;
    uint32_t *data_array, *key_array;
    size_t data_len, key_len;

    if (!len) return NULL;

    data_array = xxtea_to_uint_array(data, len, 1, &data_len);
    if (!data_array) return NULL;

    key_array  = xxtea_to_uint_array(key, 16, 0, &key_len);
    if (!key_array)
    {
        free(data_array);
        return NULL;
    }

    out = xxtea_to_ubyte_array(xxtea_uint_encrypt(data_array, data_len, key_array), data_len, 0, out_len);

    free(data_array);
    free(key_array);

    return out;
}

void * xxtea_encrypt(const void * data, size_t len, const void * key, size_t * out_len) {
    return xxtea_encrypt_ubyte(data, len, key, out_len);
}

/**
 * Method:   xxtea_decrypt
 * @data:    Data to be decrypted
 * @len:     Length of the data to be decrypted
 * @key:     Symmetric key
 * @out_len: Pointer to output length variable
 * Returns:  Decrypted data or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer.
 */
uint8_t * xxtea_decrypt_ubyte(const uint8_t * data, size_t len, const uint8_t * key, size_t * out_len)
{
    uint8_t *out;
    uint32_t *data_array, *key_array;
    size_t data_len, key_len;

    if (!len) return NULL;

    data_array = xxtea_to_uint_array(data, len, 0, &data_len);
    if (!data_array) return NULL;

    key_array  = xxtea_to_uint_array(key, 16, 0, &key_len);
    if (!key_array)
    {
        free(data_array);
        return NULL;
    }

    out = xxtea_to_ubyte_array(xxtea_uint_decrypt(data_array, data_len, key_array), data_len, 1, out_len);

    free(data_array);
    free(key_array);

    return out;
}

void * xxtea_decrypt(const void * data, size_t len, const void * key, size_t * out_len) {
    return xxtea_decrypt_ubyte(data, len, key, out_len);
}
