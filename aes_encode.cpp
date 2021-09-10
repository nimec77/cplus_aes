//
// Created by nim on 10.09.2021.
//

#include "aes_encode.h"

AesEncode::~AesEncode() {
    std::cout << "~AesEncode" << std::endl;
//    if (aes_alg) {
//        BCryptCloseAlgorithmProvider(aes_alg, 0);
//    }

    if (key_handle) {
        BCryptDestroyKey(key_handle);
    }

    if (cipher_text) {
        HeapFree(GetProcessHeap(), 0, cipher_text);
    }

    if (plain_text) {
        HeapFree(GetProcessHeap(), 0, plain_text);
    }

    if (key_object) {
        HeapFree(GetProcessHeap(), 0, key_object);
    }

    if (iv_ptr) {
        HeapFree(GetProcessHeap(), 0, iv_ptr);
    }
}

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

    key_object = (PBYTE) HeapAlloc(GetProcessHeap(), 0, key_object_size_);
    if (key_object == nullptr) {
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

    iv_ptr = (PBYTE) HeapAlloc(GetProcessHeap(), 0, block_len_);
    if (iv_ptr == nullptr) {
        std::cout << "HeapAlloc error iv_ptr" << std::endl;
        return {};
    }

    memcpy(iv_ptr, rgb_iv, block_len_);

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

    status = BCryptGenerateSymmetricKey(
            aes_alg_ptr_.get(),
            &key_handle,
            key_object,
            key_object_size_,
            (PBYTE) rgb_aes128_key,
            sizeof(rgb_aes128_key),
            0);
    if (!NT_SUCCESS(status)) {
        std::cout << "BCryptGenerateSymmetricKey error: " << status << std::endl;
        return {};
    }

    status = BCryptExportKey(
            key_handle,
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

    bloc_ptr = (PBYTE) HeapAlloc(GetProcessHeap(), 0, block_len_);
    if (bloc_ptr == nullptr) {
        std::cout << "HeapAlloc error bloc" << std::endl;
        return {};
    }

    status = BCryptExportKey(
            key_handle,
            nullptr,
            BCRYPT_OPAQUE_KEY_BLOB,
            bloc_ptr,
            block_len_,
            &block_len_,
            0);
    if (!NT_SUCCESS(status)) {
        std::cout << "BCryptExportKey error: " << status << std::endl;
        return {};
    }

    auto plain_text_size_ = text.size();
    plain_text = (PBYTE) HeapAlloc(GetProcessHeap(), 0, plain_text_size_);
    if (plain_text == nullptr) {
        std::cout << "HeapAlloc error plain_text" << std::endl;
        return {};
    }
    memcpy(plain_text, text.c_str(), plain_text_size_);

    DWORD cipher_text_size_ = 0;

    status = BCryptEncrypt(
            key_handle,
            plain_text,
            plain_text_size_,
            nullptr,
            iv_ptr,
            block_len_,
            nullptr,
            0,
            &cipher_text_size_,
            BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status)) {
        std::cout << "BCryptEncrypt error: " << status << std::endl;
        return {};
    }

    cipher_text = (PBYTE) HeapAlloc(GetProcessHeap(), 0, cipher_text_size_);
    if (cipher_text == nullptr) {
        std::cout << "HeapAlloc error plain_text" << std::endl;
        return {};
    }

    status = BCryptEncrypt(
            key_handle,
            plain_text,
            plain_text_size_,
            nullptr,
            iv_ptr,
            block_len_,
            cipher_text,
            cipher_text_size_,
            &data_size_,
            BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status)) {
        std::cout << "BCryptEncrypt error: " << status << std::endl;
        return {};
    }

    return {cipher_text, cipher_text + cipher_text_size_};
}

void AesEncode::PrintData(const std::vector<int>& data) {
       for(auto iter : data) {
           std::cout << std::hex << std::setfill('0') << std::setw(2) << iter << " ";
       }
       std::cout << std::endl;
}

