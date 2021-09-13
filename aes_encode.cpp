//
// Created by nim on 10.09.2021.
//

#include "aes_encode.h"

void AesEncode::InitAes() {
    BCRYPT_ALG_HANDLE aes_alg_;
    auto status = BCryptOpenAlgorithmProvider(&aes_alg_, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(status)) {
        std::cout << "BCryptOpenAlgorithmProvider error: " << status << std::endl;
        return;
    }
    aes_alg_ptr = ptr_helper::MakeAlgorithmSharedPtr(aes_alg_);

    status = BCryptGetProperty(
            aes_alg_ptr.get(),
            BCRYPT_OBJECT_LENGTH,
            (PBYTE) &key_object_size,
            sizeof(DWORD),
            &data_size,
            0);
    if (!NT_SUCCESS(status)) {
        std::cout << "BCryptGetProperty error: " << status << std::endl;
        aes_alg_ptr.reset();
        return;
    }

    status = BCryptGetProperty(
            aes_alg_ptr.get(),
            BCRYPT_BLOCK_LENGTH,
            (PBYTE) &block_len,
            sizeof(DWORD),
            &data_size,
            0);
    if (!NT_SUCCESS(status)) {
        std::cout << "BCryptGetProperty error: " << status << std::endl;
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

    status = BCryptSetProperty(
            aes_alg_ptr.get(),
            BCRYPT_CHAINING_MODE,
            (PBYTE) BCRYPT_CHAIN_MODE_CBC,
            sizeof(BCRYPT_CHAIN_MODE_CBC),
            0);
    if (!NT_SUCCESS(status)) {
        std::cout << "BCryptSetProperty error: " << status << std::endl;
        aes_alg_ptr.reset();
        return;
    }
}

std::vector<BYTE> AesEncode::EncodeAes(const std::vector<BYTE>& key_data, const std::string &text) {
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
    auto status = BCryptGenerateSymmetricKey(
            aes_alg_ptr.get(),
            &key_handle_,
            key_object_ptr_.get(),
            key_object_size,
            (PBYTE) key_data.data(),
            key_data.size(),
            0);
    if (!NT_SUCCESS(status)) {
        std::cout << "BCryptGenerateSymmetricKey error: " << status << std::endl;
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
    status = BCryptEncrypt(
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
    if (!NT_SUCCESS(status)) {
        std::cout << "BCryptEncrypt error: " << std::hex << status << std::endl;
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
            iv_ptr.get(),
            block_len,
            cipher_text_ptr_.get(),
            cipher_text_size_,
            &data_size,
            BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status)) {
        std::cout << "BCryptEncrypt error: " << status << std::endl;
        return {};
    }

    return {cipher_text_ptr_.get(), cipher_text_ptr_.get() + cipher_text_size_};
}

void AesEncode::PrintData(const std::vector<BYTE> &data) {
    for (int item : data) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << item;
    }
    std::cout << std::endl;
}


