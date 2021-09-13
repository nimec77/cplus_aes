#include <iostream>
#include "aes_encode.h"

constexpr static const BYTE rgb_aes128_key[] =
        {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        };

int main() {
    std::cout << "Windows AES encode starting!" << std::endl;

    auto aes_encode = AesEncode();

    aes_encode.InitAes();
    const auto key = std::vector<BYTE>(rgb_aes128_key, rgb_aes128_key + sizeof(rgb_aes128_key));
    AesEncode::PrintData(key);

    const auto encoded = aes_encode.EncodeAes(key, "Test_data");
    AesEncode::PrintData(encoded);

    std::cout << "Windows AES encode end!" << std::endl;
    return 0;
}
