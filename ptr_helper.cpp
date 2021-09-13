//
// Created by nim on 10.09.2021.
//

#include "ptr_helper.h"

namespace ptr_helper {
    SharedPtr MakeAlgorithmSharedPtr(BCRYPT_ALG_HANDLE alg_handle) noexcept {
        return {alg_handle, CloseAlgorithm()};
    }

    KeyUniqueHandlePtr MakeKeyHandleUniquePtr(BCRYPT_KEY_HANDLE key_handle) noexcept {
        return KeyUniqueHandlePtr(key_handle);
    }

    HeapUniquePtr MakeHeapUniquePtr(DWORD size) noexcept {
        const auto pointer = (PBYTE) HeapAlloc(GetProcessHeap(), 0, size);
        return HeapUniquePtr(pointer);
    }

    HeapSharedPtr MakeHeapSharedPtr(DWORD size) noexcept {
        const auto pointer = (PBYTE) HeapAlloc(GetProcessHeap(), 0, size);

        return {pointer, HeapDestroy()};
    }

    SharedPtr MakeKeySharedPtr(BCRYPT_KEY_HANDLE key_handle) noexcept {
        return {key_handle, DestroyKey()};
    }

}
