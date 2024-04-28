#include <iostream>
#include <vector>
#include <cmath>
#include <bitset>
#include <fstream>
#include <algorithm>
#include <functional>

class BloomFilter {
private:
    double error_rate;
    int num_slices;
    int bits_per_slice;
    int capacity;
    int num_bits;
    int count;
    std::function<std::vector<int>(std::string)> make_hashes;
    std::vector<bool> bitarray;

    std::vector<int> makeHashes(std::string key) {
        std::vector<int> hashes;
        // Tạo các hàm băm ở đây
        return hashes;
    }

public:
    BloomFilter(int _capacity, double _error_rate) {
        if (!(_error_rate > 0 && _error_rate < 1))
            throw std::invalid_argument("Error_Rate must be between 0 and 1.");
        if (!(_capacity > 0))
            throw std::invalid_argument("Capacity must be > 0");

        error_rate = _error_rate;
        num_slices = std::ceil(std::log(1.0 / error_rate) / std::log(2));
        bits_per_slice = std::ceil((_capacity * std::abs(std::log(error_rate))) /
                                    (num_slices * (std::log(2) * std::log(2))));
        capacity = _capacity;
        num_bits = num_slices * bits_per_slice;
        count = 0;

        make_hashes = std::bind(&BloomFilter::makeHashes, this, std::placeholders::_1);

        bitarray.resize(num_bits, false);
    }

    bool contains(std::string key) {
        int bits_per_slice = bits_per_slice;
        std::vector<bool>& bitarray = bitarray;
        std::vector<int> hashes = make_hashes(key);
        int offset = 0;
        for (int k : hashes) {
            if (!bitarray[offset + k]) {
                return false;
            }
            offset += bits_per_slice;
        }
        return true;
    }

    int length() {
        return count;
    }

    void add(std::string key, bool skip_check = false) {
        std::vector<bool>& bitarray = bitarray;
        int bits_per_slice = bits_per_slice;
        std::vector<int> hashes = make_hashes(key);
        bool found_all_bits = true;
        if (count > capacity) {
            throw std::out_of_range("BloomFilter is at capacity");
        }
        int offset = 0;
        for (int k : hashes) {
            if (!skip_check && found_all_bits && !bitarray[offset + k]) {
                found_all_bits = false;
            }
            bitarray[offset + k] = true;
            offset += bits_per_slice;
        }

        if (skip_check) {
            count++;
        } else if (!found_all_bits) {
            count++;
        }
    }

    BloomFilter copy() {
        BloomFilter new_filter(capacity, error_rate);
        new_filter.bitarray = bitarray;
        return new_filter;
    }

    BloomFilter _union(BloomFilter other) {
        if (capacity != other.capacity || error_rate != other.error_rate) {
            throw std::invalid_argument("Unioning filters requires both filters to have both the same capacity and error rate");
        }
        BloomFilter new_bloom(capacity, error_rate);
        new_bloom.bitarray.reserve(num_bits);
        std::transform(bitarray.begin(), bitarray.end(), other.bitarray.begin(),
                       std::back_inserter(new_bloom.bitarray),
                       std::logical_or<bool>());
        return new_bloom;
    }

    BloomFilter intersection(BloomFilter other) {
        if (capacity != other.capacity || error_rate != other.error_rate) {
            throw std::invalid_argument("Intersecting filters requires both filters to have equal capacity and error rate");
        }
        BloomFilter new_bloom(capacity, error_rate);
        new_bloom.bitarray.reserve(num_bits);
        std::transform(bitarray.begin(), bitarray.end(), other.bitarray.begin(),
                       std::back_inserter(new_bloom.bitarray),
                       std::logical_and<bool>());
        return new_bloom;
    }

    void tofile(std::ofstream& f) {
        f.write(reinterpret_cast<const char*>(&error_rate), sizeof(double));
        f.write(reinterpret_cast<const char*>(&num_slices), sizeof(int));
        f.write(reinterpret_cast<const char*>(&bits_per_slice), sizeof(int));
        f.write(reinterpret_cast<const char*>(&capacity), sizeof(int));
        f.write(reinterpret_cast<const char*>(&count), sizeof(int));
        f.write(reinterpret_cast<const char*>(&bitarray[0]), num_bits / 8);
    }

    static BloomFilter fromfile(std::ifstream& f) {
        double error_rate;
        int num_slices, bits_per_slice, capacity, count;
        f.read(reinterpret_cast<char*>(&error_rate), sizeof(double));
        f.read(reinterpret_cast<char*>(&num_slices), sizeof(int));
        f.read(reinterpret_cast<char*>(&bits_per_slice), sizeof(int));
        f.read(reinterpret_cast<char*>(&capacity), sizeof(int));
        f.read(reinterpret_cast<char*>(&count), sizeof(int));

        BloomFilter filter(capacity, error_rate);
        filter.count = count;
        filter.bitarray.resize(filter.num_bits);
        f.read(reinterpret_cast<char*>(&filter.bitarray[0]), filter.num_bits / 8);
        return filter;
    }
};
