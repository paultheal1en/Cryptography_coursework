#include <iostream>
#include <cstdint>
#include <vector> 
#include <cmath>

using namespace std;

// convert integer to bytes
vector<uint8_t> int_to_bytes(uint64_t n) {
    vector<uint8_t> bytes;
    while (n > 0) {
        bytes.insert(bytes.begin(), n & 0xFF);
        n >>= 8;
    }
    return bytes;
}

// convert bytes to integer
uint64_t bytes_to_int(vector<uint8_t> byte_array) {
    uint64_t result = 0;
    for (uint8_t byte : byte_array) {
        result = (result << 8) | byte;
    }
    return result;
}

//convert float to bytes
vector<uint8_t> float_to_bytes(float f) {
    // static_assert(sizeof(float) == 4, "Float is not 4 bytes on this platform");
    uint32_t float_as_int;
    memcpy(&float_as_int, &f, sizeof(float));
    vector<uint8_t> bytes(sizeof(float_as_int));
    for (size_t i = 0; i < sizeof(float_as_int); ++i) {
        bytes[i] = (float_as_int >> (8 * (sizeof(float_as_int) - 1 - i))) & 0xFF;
    }
    return bytes;
}

// convert bytes to float
float bytes_to_float(vector<uint8_t> byte_representation) {
    // static_assert(sizeof(float) == 4, "Float is not 4 bytes on this platform");
    uint32_t float_as_int = 0;
    for (size_t i = 0; i < sizeof(float_as_int) && i < byte_representation.size(); ++i) {
        float_as_int |= static_cast<uint32_t>(byte_representation[i]) << (8 * (sizeof(float_as_int) - 1 - i));
    }
    float result;
    memcpy(&result, &float_as_int, sizeof(float));
    return result;
}

// Function to prepare keyword
uint64_t prepare_keyword(const string& k) {
    try {
        float f = stof(k);
        return static_cast<uint64_t>(round(f));
    } catch (const invalid_argument&) {
        return bytes_to_int(vector<uint8_t>(k.begin(), k.end()));
    }
}
