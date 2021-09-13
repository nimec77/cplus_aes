#include "aes_encode.h"

int main() {
    std::cout << "Windows AES encode starting!" << std::endl;

    const auto key_ = AesEncode::StringToBytes("123456");
    AesEncode::PrintData(key_);
    auto aes_encode_ = AesEncode();

    const auto md5_hash_ = AesEncode::Md5Hash(key_);
    AesEncode::PrintData(md5_hash_);

    aes_encode_.InitAes();

    const auto encoded = aes_encode_.EncodeAes(md5_hash_, "Test data!");
    AesEncode::PrintData(encoded);

    const auto decode = aes_encode_.DecodeAes(md5_hash_, encoded);
    AesEncode::PrintData(decode);

    const auto text = AesEncode::BytesToString(decode);
    std::cout << "Decode: " << text << std::endl;

    std::cout << "Windows AES encode end!" << std::endl;
    return 0;
}
