//
// Created by nim on 10.09.2021.
//

#ifndef CPLUS_AES_AES_ENCODE_H
#define CPLUS_AES_AES_ENCODE_H

#include <iostream>
#include <windows.h>
#include <bcrypt.h>
#include <iomanip>
#include <sstream>
#include <string>
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

public:
    using Bytes = ptr_helper::Bytes;

    virtual ~AesEncode() = default;

    static std::string BytesToHexString(const Bytes &data);

    static Bytes HexStringToBytes(const std::string& value);

    static Bytes StringToBytes(const std::string& value);

    static std::string BytesToString(const Bytes &data);

    static Bytes Md5Hash(const Bytes& value);

    void InitAes();

    Bytes EncodeAes(const Bytes &key_data, const std::string &text);

    Bytes DecodeAes(const Bytes &key_data, const Bytes &data);

    static void PrintData(const Bytes &data);

};


#endif //CPLUS_AES_AES_ENCODE_H
