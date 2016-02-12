# XXTEA for C

<a href="https://github.com/xxtea/">
    <img src="https://avatars1.githubusercontent.com/u/6683159?v=3&s=86" alt="XXTEA logo" title="XXTEA" align="right" />
</a>

## Introduction

XXTEA is a fast and secure encryption algorithm. This is a XXTEA library for C.

It is different from the original XXTEA encryption algorithm. It encrypts and decrypts raw binary data instead of 32bit integer array, and the key is also the raw binary data.

## Installation

```sh
git clone https://github.com/xxtea/xxtea-c.git
cmake .
make
make install
```

## Usage

```c
#include <stdio.h>
#include <string.h>
#include <xxtea.h>

int main() {
    const char *text = "Hello World! 你好，中国！";
    const char *key = "1234567890";
    size_t len;
    unsigned char *encrypt_data = xxtea_encrypt(text, strlen(text), key, &len);
    char *decrypt_data = xxtea_decrypt(encrypt_data, len, key, &len);
    if (strncmp(text, decrypt_data, len) == 0) {
        printf("success!\n");
    }
    else {
        printf("fail!\n");
    }
    free(encrypt_data);
    free(decrypt_data);
    return 0;
}
```
