#include "BloomFilter.h"

#ifndef BLOOM_FILTER_H
#define BLOOM_FILTER_H

int VBFVerify(BloomFilter& VBF, std::string value) {
    if (VBF.contains(value)) {
        return 1;
    }
    return 0;
}

void VBFAdd(BloomFilter& VBF, std::string value) {
    VBF.add(value);
}

#endif // BLOOM_FILTER_H

