//
// Created by nim on 10.09.2021.
//

#ifndef CPLUS_AES_PTR_HELPER_H
#define CPLUS_AES_PTR_HELPER_H

#include <iostream>
#include <windows.h>
#include <bcrypt.h>

namespace ptr_helper {
    struct CloseAlgorithm {
        void operator()(BCRYPT_ALG_HANDLE alg_handle) const {
            if (alg_handle) {
                std::cout << "BCryptCloseAlgorithmProvider" << std::endl;
                BCryptCloseAlgorithmProvider(alg_handle, 0);
            }
        }
    };
    using AlgorithmPtr = std::unique_ptr<void, CloseAlgorithm>;
    AlgorithmPtr MakeAlgorithmUniquePtr(BCRYPT_ALG_HANDLE alg_handle) noexcept;

    struct DestroyKey {
        void operator()(BCRYPT_KEY_HANDLE key_handle) const {
            if (key_handle) {
                std::cout << "BCryptDestroyKey" << std::endl;
                BCryptDestroyKey(key_handle);
            }
        }
    };
    using KeyHandlePtr = std::unique_ptr<void, DestroyKey>;
    KeyHandlePtr MakeKeyHandleUniquePtr(BCRYPT_KEY_HANDLE key_handle) noexcept;

    struct HeapDestroy {
        void operator()(PBYTE pointer) const {
            if (pointer) {
                std::cout << "HeapFree" << std::endl;
                HeapFree(GetProcessHeap(), 0, pointer);
            }
        }
    };
    using HeapPtr = std::unique_ptr<BYTE, HeapDestroy>;
    HeapPtr MakeHeapUniquePtr(DWORD size) noexcept;
}

#endif //CPLUS_AES_PTR_HELPER_H
