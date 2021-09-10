//
// Created by nim on 10.09.2021.
//

#ifndef CPLUS_AES_AES_ENCODE_H
#define CPLUS_AES_AES_ENCODE_H

#include <iostream>
#include <windows.h>
#include <bcrypt.h>
#include <vector>
#include <iomanip>
#include "ptr_helper.h"

#define NT_SUCCESS(status)  (((NTSTATUS)(status)) >= 0)

class AesEncode {

private:
    constexpr static const BYTE rgb_iv[] =
            {
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
            };

    constexpr static const BYTE rgb_aes128_key[] =
            {
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
            };

//    BCRYPT_ALG_HANDLE aes_alg{};
    BCRYPT_KEY_HANDLE key_handle{};
    PBYTE key_object{};
    PBYTE bloc_ptr{};
    PBYTE cipher_text{};
    PBYTE plain_text{};
    PBYTE iv_ptr{};

public:
    virtual ~AesEncode();

    std::vector<int> EncodeAes(const std::string &text);

    static void PrintData(const std::vector<int>& data);
};


#endif //CPLUS_AES_AES_ENCODE_H
