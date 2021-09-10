//
// Created by nim on 10.09.2021.
//

#include "ptr_helper.h"

namespace ptr_helper {
    AlgorithmPtr MakeAlgorithmUniquePtr(BCRYPT_ALG_HANDLE alg_handle) noexcept {
        return AlgorithmPtr(alg_handle);
    }
}
