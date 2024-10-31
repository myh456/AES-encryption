#include "aes-128.hpp"

// n位bitset数循环左移pos位(没有越界检查)
#define LLL(bs, pos, n)  (bs) << (pos) | (bs) >> (n - pos)
// 提取bitset<8>前4位
#define FRONT4(bs) (bs).to_ulong() >> 4
// 提取bitset<8>后4位
#define END4(bs) (bs).to_ulong() & 0xf
// 交换两个数
#define SWAP(a, b) (a) ^= (b) ^= (a) ^= (b)

// 连接4个bitset
template<size_t N>
bitset<4 * N> combine(const bitset<N> bs1, const bitset<N> bs2, const bitset<N> bs3, const bitset<N> bs4) {
    bitset<4 * N> result;
    for (int i = 0; i < N; i++) {
        result[i] = bs1[i];
        result[i + N] = bs2[i];
        result[i + 2 * N] = bs3[i];
        result[i + 3 * N] = bs4[i];
    }
    return result;
}

// 伽罗瓦域内乘法运算GF(128)
bitset<8> GaloisMultiplication(bitset<8> Num_L, bitset<8> Num_R) {
    bitset<8> Result = 0;
    while (Num_L.any()) {
        if (Num_L.test(0)) {
            // Num_L最低位是1,相当于结果+Num_R
            Result ^= Num_R;
        }
        // 处理下一位
        Num_L >>= 1;
        // Num_R最高位是否是1(是否需要模运算)
        if (Num_R.test(7)) {
            Num_R = Num_R << 1;
            // 0x1B是固定的不可约多项式，即x^8 + x^4 + x^3 + x^1 + 1
            // 最高位的x^8不会影响这8位的运算结果，所以不考虑
            // GF(128)中减法和加法(异或)等价
            Num_R ^= 0x1B;
        } else {
            Num_R = Num_R << 1;
        }
    }
    return Result;
}

// 计算列混合时的矩阵相乘
vector<vector<bitset<8>>> matrixMul(vector<vector<bitset<8>>> m1, vector<vector<bitset<8>>> m2) {
    vector<vector<bitset<8>>> res = vector<vector<bitset<8>>>(4, vector<bitset<8>>(4, 0x0));
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            res[i][j] = \
                GaloisMultiplication(m1[i][0], m2[0][j]) ^ \
                GaloisMultiplication(m1[i][1], m2[1][j]) ^ \
                GaloisMultiplication(m1[i][2], m2[2][j]) ^ \
                GaloisMultiplication(m1[i][3], m2[3][j]);
        }
    }
    return res;
}


void AES128::extendKey(bitset<128> key) {
    // 初始化
    for (int i = 0; i < 32; i++) {
        this->w[0][i] = key[i];
        this->w[1][i] = key[i + 32];
        this->w[2][i] = key[i + 64];
        this->w[3][i] = key[i + 96];
    }
    // w扩充
    for (int i = 4; i < 44; i++) {
        if (i % 4 != 0) {   // 下标不是4的倍数的
            this->w[i] = this->w[i - 1] ^ this->w[i - 4];
        } else {            // 下标是4的倍数的
            this->w[i] = this->w[i - 4] ^ this->funcT(this->w[i - 1], i / 4 - 1);
        }
    }
}

bitset<32> AES128::funcT(bitset<32> b, int count) {
    // 字循环
    bitset<32> res1 = LLL(b, 8, 32);
    // 字节代换
    bitset<32> res2 = 0x0;
    for (int i = 0; i < 4; i++) {
        res2 <<= 8;
        res2 |= this->SBox[res1.to_ulong() >> 4 & 0xf][res1.to_ulong() & 0xf].to_ulong();
        res1 >>= 8;
    }
    // 轮常量异或
    return res2 ^ this->Rconj[count];
}

void AES128::selectKey() {
    for (int i = 0; i < 11; i++) {
        this->ki[i] = combine(this->w[4 * i], this->w[4 * i + 1], this->w[4 * i + 2], this->w[4 * i + 3]);
    }
}

void AES128::subkey(bitset<128> key) {
    this->extendKey(key);
    this->selectKey();
}

bitset<128> AES128::enc(bitset<128> plain) {
    vector<vector<bitset<8>>> status = vector<vector<bitset<8>>>(4, vector<bitset<8>>(4, 0x0));
    bitset<128> res = 0x0;
    // 填充状态矩阵
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            status[i][j] |= (plain >> (j * 32 + i * 8) & bitset<128>(0xff)).to_ullong();
        }
    }

    // 首先一次轮密钥加
    for (int j = 0; j < 4; j++) {
        for (int k = 0; k < 4; k++) {
            status[k][j] ^= (this->ki[0] >> (j * 32 + k * 8) & bitset<128>(0xff)).to_ullong();
        }
    }

    for (int i = 0; i < 10; i++) {
        // 字节代换
        for (int j = 0; j < 4; j++) {
            for (int k = 0; k < 4; k++) {
                status[j][k] = this->SBox[FRONT4(status[j][k])][END4(status[j][k])];
            }
        }

        // 行移位(没找到更优雅的写法)
        // 第0行不动
        // 第1行左移1格
        SWAP(status[1][0], status[1][3]);
        SWAP(status[1][0], status[1][2]);
        SWAP(status[1][0], status[1][1]);
        // 第二行左移2格
        SWAP(status[2][0], status[2][2]);
        SWAP(status[2][1], status[2][3]);
        // 第三行左移3格
        SWAP(status[3][3], status[3][0]);
        SWAP(status[3][3], status[3][1]);
        SWAP(status[3][3], status[3][2]);

        // 列混淆(最后一轮不做)
        if (i != 9) {
            status = matrixMul(this->premulMatrix, status);
        }

        // 轮密钥加
        for (int j = 0; j < 4; j++) {
            for (int k = 0; k < 4; k++) {
                status[k][j] ^= (this->ki[i + 1] >> (j * 32 + k * 8) & bitset<128>(0xff)).to_ullong();
            }
        }
    }

    for (int i = 3; i >= 0; i--) {
        for (int j = 3; j >= 0; j--) {
            res <<= 8;
            res |= bitset<128>(status[j][i].to_ulong());
        }
    }
    return res;
}

bitset<128> AES128::dec(bitset<128> cipher) {
    vector<vector<bitset<8>>> status = vector<vector<bitset<8>>>(4, vector<bitset<8>>(4, 0x0));
    bitset<128> res = 0x0;
    // 填充状态矩阵
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            status[i][j] |= (cipher >> (j * 32 + i * 8) & bitset<128>(0xff)).to_ullong();
        }
    }

    for (int i = 0; i < 10; i++) {
        // 逆轮密钥加
        for (int j = 0; j < 4; j++) {
            for (int k = 0; k < 4; k++) {
                status[k][j] ^= (this->ki[10 - i] >> (j * 32 + k * 8) & bitset<128>(0xff)).to_ullong();
            }
        }

        // 逆列混淆(第一轮不做)
        if (i != 0) {
            status = matrixMul(this->inversePremulMatrix, status);
        }

        // 逆行移位
        // 第0行不动
        // 第1行右移1格
        SWAP(status[1][0], status[1][1]);
        SWAP(status[1][0], status[1][2]);
        SWAP(status[1][0], status[1][3]);
        // 第二行右移2格
        SWAP(status[2][0], status[2][2]);
        SWAP(status[2][1], status[2][3]);
        // 第三行右移3格
        SWAP(status[3][3], status[3][2]);
        SWAP(status[3][3], status[3][1]);
        SWAP(status[3][3], status[3][0]);

        // 逆字节代换
        for (int j = 0; j < 4; j++) {
            for (int k = 0; k < 4; k++) {
                status[j][k] = this->inverseSBox[FRONT4(status[j][k])][END4(status[j][k])];
            }
        }
    }

    // 最后一次逆轮密钥加
    for (int j = 0; j < 4; j++) {
        for (int k = 0; k < 4; k++) {
            status[k][j] ^= (this->ki[0] >> (j * 32 + k * 8) & bitset<128>(0xff)).to_ullong();
        }
    }

    for (int i = 3; i >= 0; i--) {
        for (int j = 3; j >= 0; j--) {
            res <<= 8;
            res |= bitset<128>(status[j][i].to_ulong());
        }
    }
    return res;
}

AES128::AES128() { }
AES128::AES128(bitset<128> key) {
    this->subkey(key);
}