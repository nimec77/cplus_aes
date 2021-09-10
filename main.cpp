#include <iostream>
#include "aes_encode.h"

int main() {
    std::cout << "Windows AES encode starting!" << std::endl;

    auto aes_encode = AesEncode();

    const auto encoded = AesEncode::EncodeAes("Test_data");
    AesEncode::PrintData(encoded);

    std::cout << "Windows AES encode end!" << std::endl;
    return 0;
}
