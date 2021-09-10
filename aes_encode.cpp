//
// Created by nim on 10.09.2021.
//

#include "aes_encode.h"

std::vector<int> AesEncode::EncodeAes(const std::string &text) {
    BCRYPT_ALG_HANDLE aes_alg_;
    auto status = BCryptOpenAlgorithmProvider(&aes_alg_, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(status)) {
        std::cout << "BCryptOpenAlgorithmProvider error: " << status << std::endl;
        return {};
    }
    auto aes_alg_ptr_ = ptr_helper::MakeAlgorithmUniquePtr(aes_alg_);
    auto key_object_size_ = 0;
    DWORD data_size_ = 0;
    status = BCryptGetProperty(
            aes_alg_ptr_.get(),
            BCRYPT_OBJECT_LENGTH,
            (PBYTE) &key_object_size_,
            sizeof(DWORD),
            &data_size_,
            0);
    if (!NT_SUCCESS(status)) {
        std::cout << "BCryptGetProperty error: " << status << std::endl;
        return {};
    }

    auto key_object_ptr_ = ptr_helper::MakeHeapUniquePtr(key_object_size_);
    if (!key_object_ptr_) {
        std::cout << "HeapAlloc error key_object" << std::endl;
        return {};
    }

    DWORD block_len_ = 0;
    status = BCryptGetProperty(
            aes_alg_ptr_.get(),
            BCRYPT_BLOCK_LENGTH,
            (PBYTE) &block_len_,
            sizeof(DWORD),
            &data_size_,
            0);
    if (!NT_SUCCESS(status)) {
        std::cout << "BCryptGetProperty error: " << status << std::endl;
        return {};
    }

    if (block_len_ > sizeof(rgb_iv)) {
        std::cout << "Block length is longer then the provided IV length" << std::endl;
    }

    auto iv_ptr_ = ptr_helper::MakeHeapUniquePtr(block_len_);
    if (!iv_ptr_) {
        std::cout << "HeapAlloc error iv_ptr" << std::endl;
        return {};
    }

    memcpy(iv_ptr_.get(), rgb_iv, block_len_);

    status = BCryptSetProperty(
            aes_alg_ptr_.get(),
            BCRYPT_CHAINING_MODE,
            (PBYTE) BCRYPT_CHAIN_MODE_CBC,
            sizeof(BCRYPT_CHAIN_MODE_CBC),
            0);
    if (!NT_SUCCESS(status)) {
        std::cout << "BCryptGetProperty error: " << status << std::endl;
        return {};
    }

    BCRYPT_KEY_HANDLE key_handle_;
    status = BCryptGenerateSymmetricKey(
            aes_alg_ptr_.get(),
            &key_handle_,
            key_object_ptr_.get(),
            key_object_size_,
            (PBYTE) rgb_aes128_key,
            sizeof(rgb_aes128_key),
            0);
    if (!NT_SUCCESS(status)) {
        std::cout << "BCryptGenerateSymmetricKey error: " << status << std::endl;
        return {};
    }
    auto key_handle_ptr_ = ptr_helper::MakeKeyHandleUniquePtr(key_handle_);

    status = BCryptExportKey(
            key_handle_ptr_.get(),
            nullptr,
            BCRYPT_OPAQUE_KEY_BLOB,
            nullptr,
            0,
            &block_len_,
            0);
    if (!NT_SUCCESS(status)) {
        std::cout << "BCryptExportKey error: " << status << std::endl;
        return {};
    }

    auto bloc_ptr_ = ptr_helper::MakeHeapUniquePtr(block_len_);
    if (!bloc_ptr_) {
        std::cout << "HeapAlloc error bloc" << std::endl;
        return {};
    }

    status = BCryptExportKey(
            key_handle_ptr_.get(),
            nullptr,
            BCRYPT_OPAQUE_KEY_BLOB,
            bloc_ptr_.get(),
            block_len_,
            &block_len_,
            0);
    if (!NT_SUCCESS(status)) {
        std::cout << "BCryptExportKey error: " << status << std::endl;
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

    status = BCryptEncrypt(
            key_handle_ptr_.get(),
            plain_text_ptr_.get(),
            plain_text_size_,
            nullptr,
            iv_ptr_.get(),
            block_len_,
            nullptr,
            0,
            &cipher_text_size_,
            BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status)) {
        std::cout << "BCryptEncrypt error: " << status << std::endl;
        return {};
    }

    auto cipher_text_ptr_ = ptr_helper::MakeHeapUniquePtr(cipher_text_size_);
    if (!cipher_text_ptr_) {
        std::cout << "HeapAlloc error plain_text" << std::endl;
        return {};
    }

    status = BCryptEncrypt(
            key_handle_ptr_.get(),
            plain_text_ptr_.get(),
            plain_text_size_,
            nullptr,
            iv_ptr_.get(),
            block_len_,
            cipher_text_ptr_.get(),
            cipher_text_size_,
            &data_size_,
            BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status)) {
        std::cout << "BCryptEncrypt error: " << status << std::endl;
        return {};
    }

    return {cipher_text_ptr_.get(), cipher_text_ptr_.get() + cipher_text_size_};
}

void AesEncode::PrintData(const std::vector<int> &data) {
    for (auto iter : data) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << iter << " ";
    }
    std::cout << std::endl;
}

