//
// Created by nim on 10.09.2021.
//

#include "aes_encode.h"

using Bytes = ptr_helper::Bytes;

std::string AesEncode::BytesToString(const Bytes &data) {
    std::stringstream stream_;

    for (int item : data) {
        stream_ << std::hex << std::setfill('0') << std::setw(2) << std::uppercase << item;
    }

    return std::string(stream_.str());
}

Bytes AesEncode::HexStringToBytes(const std::string &value) {
    Bytes result{};

    for (auto i = 0; i < value.length(); i += 2) {
        const auto item = value.substr(i, 2);
        result.push_back(std::stoul(item, nullptr, 16));
    }

    return result;
}

Bytes AesEncode::StringToBytes(const std::string &value) {
    return AesEncode::Bytes{value.begin(), value.end()};
}

Bytes AesEncode::Md5Hash(const Bytes &value) {
    BCRYPT_ALG_HANDLE md5_alg_;
    auto status_ = BCryptOpenAlgorithmProvider(&md5_alg_, BCRYPT_MD5_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(status_)) {
        std::cout << "BCryptOpenAlgorithmProvider error: " << status_ << std::endl;
        return {};
    }
    auto md5_alg_ptr_ = ptr_helper::MakeAlgorithmSharedPtr(md5_alg_);

    DWORD hash_object_size_ = 0;
    DWORD data_size_ = 0;

    status_ = BCryptGetProperty(
            md5_alg_ptr_.get(),
            BCRYPT_OBJECT_LENGTH,
            (PBYTE) &hash_object_size_,
            sizeof(DWORD),
            &data_size_,
            0);
    if (!NT_SUCCESS(status_)) {
        std::cout << "BCryptGetProperty error: " << std::hex << status_ << std::endl;
        return {};
    }

    auto hash_object_ptr_ = ptr_helper::MakeHeapUniquePtr(hash_object_size_);

    DWORD hash_size_ = 0;
    status_ = BCryptGetProperty(
            md5_alg_ptr_.get(),
            BCRYPT_HASH_LENGTH,
            (PBYTE) &hash_size_,
            sizeof(DWORD),
            &data_size_,
            0);
    if (!NT_SUCCESS(status_)) {
        std::cout << "BCryptGetProperty error: " << std::hex << status_ << std::endl;
        return {};
    }

    auto hash_ptr_ = ptr_helper::MakeHeapUniquePtr(hash_size_);

    BCRYPT_HASH_HANDLE hash_handle_;
    status_ = BCryptCreateHash(
            md5_alg_ptr_.get(),
            &hash_handle_,
            hash_object_ptr_.get(),
            hash_object_size_,
            nullptr,
            0,
            0);
    if (!NT_SUCCESS(status_)) {
        std::cout << "BCryptCreateHash error: " << std::hex << status_ << std::endl;
        return {};
    }

    auto hash_handle_ptr_ = ptr_helper::MakeKeyHandleUniquePtr(hash_handle_);
    status_ = BCryptHashData(
            hash_handle_ptr_.get(),
            (PBYTE) value.data(),
            value.size(),
            0);
    if (!NT_SUCCESS(status_)) {
        std::cout << "BCryptHashData error: " << std::hex << status_ << std::endl;
        return {};
    }

    status_ = BCryptFinishHash(
            hash_handle_ptr_.get(),
            hash_ptr_.get(),
            hash_size_,
            0);
    if (!NT_SUCCESS(status_)) {
        std::cout << "BCryptFinishHash error: " << std::hex << status_ << std::endl;
        return {};
    }

    return {hash_ptr_.get(), hash_ptr_.get() + hash_size_};
}

void AesEncode::InitAes() {
    BCRYPT_ALG_HANDLE aes_alg_;
    auto status_ = BCryptOpenAlgorithmProvider(&aes_alg_, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(status_)) {
        std::cout << "BCryptOpenAlgorithmProvider error: " << std::hex << status_ << std::endl;
        return;
    }
    aes_alg_ptr = ptr_helper::MakeAlgorithmSharedPtr(aes_alg_);

    status_ = BCryptGetProperty(
            aes_alg_ptr.get(),
            BCRYPT_OBJECT_LENGTH,
            (PBYTE) &key_object_size,
            sizeof(DWORD),
            &data_size,
            0);
    if (!NT_SUCCESS(status_)) {
        std::cout << "BCryptGetProperty error: " << std::hex << status_ << std::endl;
        aes_alg_ptr.reset();
        return;
    }

    status_ = BCryptGetProperty(
            aes_alg_ptr.get(),
            BCRYPT_BLOCK_LENGTH,
            (PBYTE) &block_len,
            sizeof(DWORD),
            &data_size,
            0);
    if (!NT_SUCCESS(status_)) {
        std::cout << "BCryptGetProperty error: " << std::hex << status_ << std::endl;
        aes_alg_ptr.reset();
        return;
    }

    if (block_len > sizeof(rgb_iv)) {
        std::cout << "Block length is longer then the provided IV length" << std::endl;
        aes_alg_ptr.reset();
        return;
    }

    iv_ptr = ptr_helper::MakeHeapSharedPtr(block_len);
    if (!iv_ptr) {
        std::cout << "HeapAlloc error iv_ptr" << std::endl;
        aes_alg_ptr.reset();
        return;
    }

    memcpy(iv_ptr.get(), rgb_iv, block_len);

    status_ = BCryptSetProperty(
            aes_alg_ptr.get(),
            BCRYPT_CHAINING_MODE,
            (PBYTE) BCRYPT_CHAIN_MODE_CBC,
            sizeof(BCRYPT_CHAIN_MODE_CBC),
            0);
    if (!NT_SUCCESS(status_)) {
        std::cout << "BCryptSetProperty error: " << std::hex << status_ << std::endl;
        aes_alg_ptr.reset();
        return;
    }
}

Bytes AesEncode::EncodeAes(const Bytes &key_data, const std::string &text) {
    if (!aes_alg_ptr) {
        std::cout << "BCRYPT_AES_ALGORITHM not initialized" << std::endl;
        return {};
    }

    auto key_object_ptr_ = ptr_helper::MakeHeapUniquePtr(key_object_size);
    if (!key_object_ptr_) {
        std::cout << "HeapAlloc error key_object" << std::endl;
        return {};
    }

    BCRYPT_KEY_HANDLE key_handle_;
    auto status_ = BCryptGenerateSymmetricKey(
            aes_alg_ptr.get(),
            &key_handle_,
            key_object_ptr_.get(),
            key_object_size,
            (PBYTE) key_data.data(),
            key_data.size(),
            0);
    if (!NT_SUCCESS(status_)) {
        std::cout << "BCryptGenerateSymmetricKey error: " << std::hex << status_ << std::endl;
        return {};
    }

    auto plain_text_size_ = text.size();
    auto plain_text_ptr_ = ptr_helper::MakeHeapUniquePtr(text.size());
    if (!plain_text_ptr_) {
        std::cout << "HeapAlloc error plain_text" << std::endl;
        return {};
    }
    memcpy(plain_text_ptr_.get(), text.c_str(), plain_text_size_);

    DWORD cipher_text_size_ = 0;

    auto key_handle_ptr_ = ptr_helper::MakeKeyHandleUniquePtr(key_handle_);
    status_ = BCryptEncrypt(
            key_handle_ptr_.get(),
            plain_text_ptr_.get(),
            plain_text_size_,
            nullptr,
            iv_ptr.get(),
            block_len,
            nullptr,
            0,
            &cipher_text_size_,
            BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status_)) {
        std::cout << "BCryptEncrypt error: " << std::hex << status_ << std::endl;
        return {};
    }

    auto cipher_text_ptr_ = ptr_helper::MakeHeapUniquePtr(cipher_text_size_);
    if (!cipher_text_ptr_) {
        std::cout << "HeapAlloc error plain_text" << std::endl;
        return {};
    }

    status_ = BCryptEncrypt(
            key_handle_ptr_.get(),
            plain_text_ptr_.get(),
            plain_text_size_,
            nullptr,
            iv_ptr.get(),
            block_len,
            cipher_text_ptr_.get(),
            cipher_text_size_,
            &data_size,
            BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status_)) {
        std::cout << "BCryptEncrypt error: " << std::hex << status_ << std::endl;
        return {};
    }

    return {cipher_text_ptr_.get(), cipher_text_ptr_.get() + cipher_text_size_};
}

void AesEncode::PrintData(const Bytes &data) {
    for (int item : data) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << std::uppercase << item;
    }
    std::cout << std::endl;
}

