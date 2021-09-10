//
// Created by nim on 10.09.2021.
//

#include "ptr_helper.h"

namespace ptr_helper {
    AlgorithmPtr MakeAlgorithmUniquePtr(BCRYPT_ALG_HANDLE alg_handle) noexcept {
        return AlgorithmPtr(alg_handle);
    }

    KeyHandlePtr MakeKeyHandleUniquePtr(BCRYPT_KEY_HANDLE key_handle) noexcept {
        return KeyHandlePtr(key_handle);
    }

    HeapPtr MakeHeapUniquePtr(DWORD size) noexcept {
        const auto pointer = (PBYTE) HeapAlloc(GetProcessHeap(), 0, size);
        return HeapPtr(pointer);
    }
}
