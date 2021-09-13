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

    ptr_helper::SharedPtr aes_alg_ptr;
    DWORD key_object_size;
    DWORD block_len;
    DWORD data_size;
    ptr_helper::HeapSharedPtr iv_ptr;

public:
    virtual ~AesEncode() = default;

    void InitAes();

    std::vector<BYTE> EncodeAes(const std::vector<BYTE> &key_data, const std::string &text);

    static void PrintData(const std::vector<BYTE> &data);

};


#endif //CPLUS_AES_AES_ENCODE_H
