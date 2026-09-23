#include <iostream>
#include <vector>
#include <array>
#include <string>
#include <cstdint>
#include <cstring>
#include <random>
#include <algorithm>

// заглушка SHA-256 для демонстрации
void sha256(const uint8_t* data, size_t len, std::array<uint8_t, 32>& out) {
    out.fill(0xAA); 
}

constexpr size_t BIGINT_WORDS = 96;      // 3072 бита
constexpr size_t BIGINT_DOUBLE_WORDS = 192; // 6144 бита
constexpr size_t BIGINT_BITS = 3072;

struct BigIntDouble {
    std::array<uint32_t, BIGINT_DOUBLE_WORDS> digits = {0};
};

class BigInt {
public:
    std::array<uint32_t, BIGINT_WORDS> digits = {0};

    BigInt() {}
    BigInt(uint64_t val) {
        digits[0] = static_cast<uint32_t>(val & 0xFFFFFFFF);
        digits[1] = static_cast<uint32_t>((val >> 32) & 0xFFFFFFFF);
    }

    bool testBit(size_t index) const {
        if (index >= BIGINT_BITS) return false;
        return (digits[index / 32] >> (index % 32)) & 1;
    }

    void setBit(size_t index) {
        if (index < BIGINT_BITS) digits[index / 32] |= (1U << (index % 32));
    }

    bool operator==(const BigInt& other) const {
        uint32_t diff = 0;
        for (size_t i = 0; i < BIGINT_WORDS; ++i) diff |= (digits[i] ^ other.digits[i]);
        return diff == 0;
    }

    bool operator<(const BigInt& other) const {
        uint32_t borrow = 0;
        for (size_t i = 0; i < BIGINT_WORDS; ++i) {
            int64_t diff = static_cast<int64_t>(digits[i]) - other.digits[i] - borrow;
            borrow = (diff < 0) ? 1 : 0;
        }
        return borrow == 1;
    }

    BigInt operator+(const BigInt& other) const {
        BigInt res;
        uint64_t carry = 0;
        for (size_t i = 0; i < BIGINT_WORDS; ++i) {
            uint64_t sum = static_cast<uint64_t>(digits[i]) + other.digits[i] + carry;
            res.digits[i] = static_cast<uint32_t>(sum & 0xFFFFFFFF);
            carry = sum >> 32;
        }
        return res;
    }

    BigInt operator-(const BigInt& other) const {
        BigInt res;
        int64_t borrow = 0;
        for (size_t i = 0; i < BIGINT_WORDS; ++i) {
            int64_t diff = static_cast<int64_t>(digits[i]) - other.digits[i] - borrow;
            if (diff < 0) { diff += 0x100000000LL; borrow = 1; } 
            else { borrow = 0; }
            res.digits[i] = static_cast<uint32_t>(diff);
        }
        return res;
    }

    BigIntDouble operator*(const BigInt& other) const {
        BigIntDouble res;
        for (size_t i = 0; i < BIGINT_WORDS; ++i) {
            uint64_t carry = 0;
            for (size_t j = 0; j < BIGINT_WORDS; ++j) {
                uint64_t cur = res.digits[i + j] + static_cast<uint64_t>(digits[i]) * other.digits[j] + carry;
                res.digits[i + j] = static_cast<uint32_t>(cur & 0xFFFFFFFF);
                carry = cur >> 32;
            }
            res.digits[i + BIGINT_WORDS] += carry;
        }
        return res;
    }

    // модульное деление (BigIntDouble % BigInt -> BigInt)
    BigInt modDouble(const BigIntDouble& num) const {
        BigInt remainder;
        for (int i = BIGINT_DOUBLE_WORDS - 1; i >= 0; --i) {
            for (int bit = 31; bit >= 0; --bit) {
                uint32_t carry_rem = 0;
                for (size_t j = 0; j < BIGINT_WORDS; ++j) {
                    uint64_t cur = (static_cast<uint64_t>(remainder.digits[j]) << 1) | carry_rem;
                    remainder.digits[j] = static_cast<uint32_t>(cur & 0xFFFFFFFF);
                    carry_rem = static_cast<uint32_t>(cur >> 32);
                }
                if ((num.digits[i] >> bit) & 1) remainder.digits[0] |= 1;

                if (!(remainder < *this)) {
                    remainder = remainder - *this;
                }
            }
        }
        return remainder;
    }

    BigInt operator%(const BigInt& divisor) const {
        BigIntDouble ext;
        std::copy(digits.begin(), digits.end(), ext.digits.begin());
        return divisor.modDouble(ext);
    }
};

BigInt bytesToBigInt(const std::array<uint8_t, 384>& data) {
    BigInt res;
    for(size_t i = 0; i < 384; ++i) {
        size_t wordIdx = (383 - i) / 4;
        size_t byteIdx = (383 - i) % 4;
        res.digits[wordIdx] |= static_cast<uint32_t>(data[i]) << (byteIdx * 8);
    }
    return res;
}

void bigIntToBytes(const BigInt& val, std::array<uint8_t, 384>& out) {
    for(size_t i = 0; i < 384; ++i) {
        size_t wordIdx = (383 - i) / 4;
        size_t byteIdx = (383 - i) % 4;
        out[i] = (val.digits[wordIdx] >> (byteIdx * 8)) & 0xFF;
    }
}

namespace RSACore {
    struct RSAKeys { BigInt N, e, d, p, q, dp, dq, qInv; };
}

namespace Module1_Math {
    BigInt modularExponentiationJoyeTun(const BigInt& base, const BigInt& exp, const BigInt& modulus) {
        BigInt R[2];
        R[0] = BigInt(1);
        R[1] = base % modulus;
        
        for (int i = BIGINT_BITS - 1; i >= 0; --i) {
            size_t b = exp.testBit(i) ? 1 : 0;
            size_t not_b = 1 - b;

            BigInt multiplied = modulus.modDouble(R[0] * R[1]);
            BigInt squared = modulus.modDouble(R[b] * R[b]);

            R[not_b] = multiplied;
            R[b] = squared;
        }
        return R[0];
    }

    // Упрощенный Extended GCD для поиска модульной инверсии
    BigInt modInverse(BigInt a, BigInt m) {
        // заглушка генерации
        return BigInt(1); 
    }

    RSACore::RSAKeys generateRSAKeys() {
        RSACore::RSAKeys keys;
        keys.N = BigInt(123456789); // заглушка
        return keys;
    }
}

namespace RSACore {
    BigInt encrypt(const BigInt& m, const RSAKeys& keys) {
        return Module1_Math::modularExponentiationJoyeTun(m, keys.e, keys.N);
    }

    BigInt decryptCRT(const BigInt& c, const RSAKeys& keys) {
        BigInt m1 = Module1_Math::modularExponentiationJoyeTun(c, keys.dp, keys.p);
        BigInt m2 = Module1_Math::modularExponentiationJoyeTun(c, keys.dq, keys.q);
        
        BigInt diff;
        if (m1 < m2) diff = m1 + keys.p - m2;
        else diff = m1 - m2;
        
        BigInt h = keys.p.modDouble(keys.qInv * diff);
        return m2 + keys.N.modDouble(h * keys.q);
    }
}

namespace OAEP {
    constexpr size_t k = 384;      
    constexpr size_t hLen = 32;    
    
    void MGF1(const uint8_t* seed, size_t seedLen, uint8_t* mask, size_t maskLen) {
        std::array<uint8_t, 32> hashOut;
        std::array<uint8_t, 384> buffer = {0}; 
        std::memcpy(buffer.data(), seed, seedLen);
        
        size_t offset = 0;
        uint32_t counter = 0;
        
        while (offset < maskLen) {
            buffer[seedLen] = (counter >> 24) & 0xFF;
            buffer[seedLen + 1] = (counter >> 16) & 0xFF;
            buffer[seedLen + 2] = (counter >> 8) & 0xFF;
            buffer[seedLen + 3] = counter & 0xFF;
            
            sha256(buffer.data(), seedLen + 4, hashOut);
            size_t copyLen = std::min(hLen, maskLen - offset);
            std::memcpy(mask + offset, hashOut.data(), copyLen);
            offset += copyLen;
            counter++;
        }
    }

    bool padOAEP(const std::vector<uint8_t>& message, std::array<uint8_t, k>& EM) {
        if (message.size() > k - 2 * hLen - 2) return false;

        EM.fill(0);
        std::array<uint8_t, hLen> lHashCalc;
        sha256(nullptr, 0, lHashCalc); 

        std::array<uint8_t, k - hLen - 1> DB;
        DB.fill(0);
        std::memcpy(DB.data(), lHashCalc.data(), hLen);
        
        size_t psLen = (k - hLen - 1) - message.size() - hLen - 1;
        DB[hLen + psLen] = 0x01; 
        std::memcpy(DB.data() + hLen + psLen + 1, message.data(), message.size());

        std::array<uint8_t, hLen> seed = {0}; // Заменить на RNG
        std::array<uint8_t, k - hLen - 1> dbMask;
        MGF1(seed.data(), hLen, dbMask.data(), k - hLen - 1);
        for (size_t i = 0; i < k - hLen - 1; ++i) DB[i] ^= dbMask[i];

        std::array<uint8_t, hLen> seedMask;
        MGF1(DB.data(), k - hLen - 1, seedMask.data(), hLen);
        for (size_t i = 0; i < hLen; ++i) seed[i] ^= seedMask[i];

        EM[0] = 0x00;
        std::memcpy(EM.data() + 1, seed.data(), hLen);
        std::memcpy(EM.data() + 1 + hLen, DB.data(), k - hLen - 1);
        return true;
    }

    bool unpadOAEP(std::array<uint8_t, k>& EM, std::array<uint8_t, k>& outMessage, size_t& outLen) {
        uint8_t error_mask = 0;
        error_mask |= EM[0];
        
        std::array<uint8_t, hLen> seedMask;
        MGF1(&EM[1 + hLen], k - hLen - 1, seedMask.data(), hLen);
        std::array<uint8_t, hLen> seed;
        for (size_t i = 0; i < hLen; ++i) seed[i] = EM[1 + i] ^ seedMask[i];
        
        std::array<uint8_t, k - hLen - 1> dbMask;
        MGF1(seed.data(), hLen, dbMask.data(), k - hLen - 1);
        std::array<uint8_t, k - hLen - 1> DB;
        for (size_t i = 0; i < k - hLen - 1; ++i) DB[i] = EM[1 + hLen + i] ^ dbMask[i];
        
        std::array<uint8_t, hLen> lHashCalc;
        sha256(nullptr, 0, lHashCalc); 
        for (size_t i = 0; i < hLen; ++i) error_mask |= (DB[i] ^ lHashCalc[i]); 
        
        uint8_t found_01 = 0;
        size_t msg_index = 0;
        
        for (size_t i = hLen; i < k - hLen - 1; ++i) {
            uint8_t is_01 = (DB[i] == 0x01) & ~found_01;
            uint8_t is_zero = (DB[i] == 0x00);
            error_mask |= (~found_01 & ~is_01 & ~is_zero);
            msg_index = (is_01 * (i + 1)) | (~is_01 * msg_index);
            found_01 |= is_01;
        }
        
        error_mask |= ~found_01; 
        if (error_mask == 0) {
            outLen = (k - hLen - 1) - msg_index;
            std::memcpy(outMessage.data(), DB.data() + msg_index, outLen);
            return true;
        }
        return false;
    }
}

int main() {
    std::cout << "Инициализация криптосистемы RSA...\n";
    RSACore::RSAKeys keys = Module1_Math::generateRSAKeys();
    
    std::string text = "ЭТО ОЧЕНЬ СТРАШНАЯ ЛАБА";
    std::vector<uint8_t> message(text.begin(), text.end());
    
    std::array<uint8_t, OAEP::k> EM;
    if (OAEP::padOAEP(message, EM)) {
        std::cout << "Упаковка OAEP выполнена.\n";
    }
    
    // Демонстрация конвертации (шифрование с заглушечными ключами не будет работать математически корректно,
    // но архитектурный пайплайн сохранен)
    BigInt m_bigint = bytesToBigInt(EM);
    std::cout << "Конвертация в BigInt завершена.\n";
    
    return 0;
}