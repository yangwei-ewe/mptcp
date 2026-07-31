// reed_solomon_v2.cpp
// Cauchy Reed-Solomon erasure code 實作 (v2 介面)
//
// 與前一版差異:
//   GaussianElimination(matrix, row, column)
//   維度改用 row / column 兩個參數明確傳入, 不再假設矩陣一定是
//   「n x 2n」的方陣增廣形式, 由呼叫端自行決定要消去的矩陣形狀。
//   (本檔案中用法仍是 n x 2n 的 [A|I] 增廣矩陣, 只是維度不再靠內部推算/暫存)
//
// 索引慣例 (供 DecodeImpl 的 symbol 使用):
//   index ∈ [0, K)        -> 原始封包 (K = pack_num)
//   index ∈ [K, K+M)      -> 第 (index-K) 個冗餘封包 (M = ecc_len)
//
// 生成矩陣 G (概念上, 共 K+M 列, K 行):
//   前 K 列 = 單位矩陣 I_K      (代表原始封包直接透傳)
//   後 M 列 = Cauchy 矩陣(M x K) (代表冗餘封包的線性組合係數)
//
// 適用情境: 純封包抹除(erasure)還原 —— 只要收到任意 K 個「內容正確」的
// 封包(不論是原始封包或冗餘封包), 即可還原全部 K 個原始封包。
// 不處理封包內容本身遭竄改/毀損的錯誤更正(error-correction)。
//
// 前提(由呼叫端保證):
//   - 同一批次內所有 SymbBlock 的 symb_len 皆相同
//   - DecodeImpl 收到的 symbol 中, pack_id 與 SymbBlock 為正確對應
//
// stateless 設計: 所有方法皆不依賴任何跨呼叫才有意義的成員變數,
// GF(256) log/exp 表僅在建構時寫入一次, 之後對所有方法而言皆為唯讀常數,
// 可安全地讓多執行緒同時呼叫同一個 ReedSolomon 實例。
//
// 注意: 呼叫端需自行負責釋放回傳 SymbBlock.symb 的記憶體 (new[] 配置, 需 delete[])

#include "reed_solomon.h"

NS_LOG_COMPONENT_DEFINE("ReedSolomonFec");

// ========================= GF(256) 運算 =========================

uint8_t gf_exp[512];
uint8_t gf_log[256];

constexpr uint16_t GF_PRIM = 0x11d; // x^8 + x^4 + x^3 + x^2 + 1

namespace ns3 {
    inline void initTables() {
        uint16_t x = 1;
        for (int i = 0; i < 255; ++i) {
            gf_exp[i] = static_cast<uint8_t>(x);
            gf_log[x] = static_cast<uint8_t>(i);
            x <<= 1;
            if (x & 0x100) {
                x ^= 0x11d;
            }
        }
        for (int i = 255; i < 512; ++i) {
            gf_exp[i] = gf_exp[i - 255]; // 方便乘法時不用取模
        }
        gf_log[0] = 0; // 0 沒有 log, 使用時需另外判斷
    }

    ReedSolomonFec::ReedSolomonFec() {
        initTables();
    }

    uint8_t ReedSolomonFec::gfMul(uint8_t a, uint8_t b) const {
        if (a == 0 || b == 0) {
            return 0;
        }
        return gf_exp[gf_log[a] + gf_log[b]]; // gf_exp 長度 512, 不會溢位
    }

    uint8_t ReedSolomonFec::gfInv(uint8_t a) const {
        if (a == 0) {
            throw std::runtime_error("0 has no inverse in GF(256)");
        }
        return gf_exp[(255 - gf_log[a]) % 255];
    }

    // ========================= 矩陣輔助函式 =========================

    uint8_t** ReedSolomonFec::allocMatrix(size_t rows, size_t cols) {
        uint8_t** m = new uint8_t*[rows];
        for (size_t i = 0; i < rows; ++i) {
            m[i] = new uint8_t[cols];
            memset(m[i], 0, cols);
        }
        return m;
    }

    void ReedSolomonFec::freeMatrix(uint8_t** m, size_t rows) {
        for (size_t i = 0; i < rows; ++i) {
            delete[] m[i];
        }
        delete[] m;
    }

    // ========================= Cauchy 矩陣 =========================
    //
    // matrix[i][j] = 1 / (Xi xor Yj) , i=0..M-1, j=0..K-1
    // 取 Xi = i, Yj = M+j : 兩組值域不重疊 -> Xi xor Yj 恆不為 0
    // 這是 Cauchy 矩陣任意子矩陣皆可逆的標準建構方式 (K+M <= 256 時成立)
    void ReedSolomonFec::makeCauchyMatrix(uint8_t** matrix, size_t K, size_t M) {
        if (K + M > 256) {
            throw std::runtime_error("K + M 超過 GF(256) 大小上限, 無法建立 Cauchy 矩陣");
        }
        for (size_t i = 0; i < M; ++i) {
            uint8_t xi = static_cast<uint8_t>(i);
            for (size_t j = 0; j < K; ++j) {
                uint8_t yj = static_cast<uint8_t>(M + j);
                uint8_t denom = xi ^ yj; // 保證 != 0
                matrix[i][j] = gfInv(denom);
            }
        }
    }

    // ========================= Gauss-Jordan 消去法 =========================
    //
    // matrix: row x column 矩陣 (例如本檔案用法中的 [A | I], column == 2*row)
    // row:    要消去成單位矩陣的維度 (即 pivot 只在前 row 欄進行)
    // column: 矩陣總行數, 每次列運算作用在整個 column 範圍
    //
    // 執行完畢後 matrix 的前 row 欄會變成單位矩陣 I_row,
    // 其餘欄位 (row..column-1) 同步套用相同的列運算
    // (若原本是 [A|I], 結果即為 [I|A^-1])
    //
    // 若 A 不可逆(理論上 Cauchy 子矩陣不會發生), 拋出例外
    void ReedSolomonFec::GaussianElimination(uint8_t** matrix, size_t row, size_t column) {
        if (row == 0) {
            throw std::runtime_error("row 不可為 0");
        }
        if (column < row) {
            throw std::runtime_error("column 必須 >= row");
        }

        for (size_t col = 0; col < row; ++col) {
            // 找主元 (pivot), 若當前列為 0 則往下找可交換的列
            size_t pivot = col;
            while (pivot < row && matrix[pivot][col] == 0) {
                ++pivot;
            }
            if (pivot == row) {
                throw std::runtime_error("矩陣為奇異矩陣(singular), 無法求反矩陣");
            }
            if (pivot != col) {
                std::swap(matrix[pivot], matrix[col]);
            }

            // 將主元列正規化, 使 matrix[col][col] == 1
            uint8_t pivVal = matrix[col][col];
            if (pivVal != 1) {
                uint8_t invPiv = gfInv(pivVal);
                for (size_t k = 0; k < column; ++k) {
                    matrix[col][k] = gfMul(matrix[col][k], invPiv);
                }
            }

            // 消去其他列在該欄的值
            for (size_t r = 0; r < row; ++r) {
                if (r == col) {
                    continue;
                }
                uint8_t factor = matrix[r][col];
                if (factor == 0) {
                    continue;
                }
                for (size_t k = 0; k < column; ++k) {
                    matrix[r][k] ^= gfMul(factor, matrix[col][k]);
                }
            }
        }
    }

    // ========================= 編碼 =========================
    //
    // source: K 個原始封包 (K = source.size())
    // ecc_len: 欲產生的冗餘封包數量 M
    // 回傳: M 個冗餘封包 (對應索引 K, K+1, ..., K+M-1)
    std::vector<SymbBlock> ReedSolomonFec::EncodeImpl(const std::vector<SymbBlock>& source,
                                                      size_t ecc_len) {
        NS_LOG_FUNCTION(this << source.size() << ecc_len);
        const size_t K = source.size();
        const size_t M = ecc_len;
        if (K == 0) {
            NS_FATAL_ERROR("ReedSolomonFec::EncodeImpl -> source cannot be null!");
        }

        const size_t len = source[0].symb_len;

        uint8_t** cauchy = allocMatrix(M, K);
        this->makeCauchyMatrix(cauchy, K, M);

        std::vector<SymbBlock> result;
        result.reserve(M);

        // parity[i] = sum_j cauchy[i][j] * source[j]  (GF(256) 下逐 byte 運算)
        for (size_t i = 0; i < M; ++i) {
            uint8_t* parity = new uint8_t[len];
            memset(parity, 0, len);
            for (size_t j{0}; j < K; ++j) {
                uint8_t coeff = cauchy[i][j];
                if (coeff == 0) {
                    continue;
                }
                const uint8_t* src = source[j].symb;
                for (size_t b = 0; b < len; ++b) {
                    parity[b] ^= gfMul(coeff, src[b]);
                }
            }
            result.push_back({parity, len});
        }

        freeMatrix(cauchy, M);
        return result;
    }

    // ========================= 解碼 =========================
    //
    // symbol: 收到的 (pack_id, data) pair, pack_id 依照上方索引慣例
    //         只處理「封包抹除(erasure)」情境: 收到的封包內容皆視為正確,
    //         不做錯誤更正(error-correction) / 伴隨式(syndrome)檢查
    // m: 原始冗餘封包數量 (ecc_len)
    // pack_num: 原始封包數量 (K)
    // 回傳: 還原後的 K 個原始封包 (依序對應 index 0..K-1)
    //
    // 前提: symbol.size() >= pack_num (只要收到 K 個存活封包即可還原, 不論其為原始或冗餘封包)
    std::vector<SymbBlock> ReedSolomonFec::DecodeImpl(
        const std::vector<std::pair<int, SymbBlock>>& symbol,
        size_t m,
        size_t pack_num) {
        NS_LOG_FUNCTION(this << symbol.size() << m << pack_num);
        size_t K = pack_num;
        size_t M = m;

        if (symbol.size() < K) {
            throw std::runtime_error("收到的封包數量不足, 無法還原原始資料");
        }

        // 建立完整生成矩陣 G ((K+M) x K): 前 K 列為單位矩陣, 後 M 列為 Cauchy 矩陣
        uint8_t** cauchy = allocMatrix(M, K);
        makeCauchyMatrix(cauchy, K, M);

        uint8_t** G = allocMatrix(K + M, K);
        for (size_t i = 0; i < K; ++i) {
            G[i][i] = 1;
        }
        for (size_t i = 0; i < M; ++i) {
            for (size_t j = 0; j < K; ++j) {
                G[K + i][j] = cauchy[i][j];
            }
        }
        freeMatrix(cauchy, M);

        // 任取 K 個可用封包 (Cauchy 矩陣任意子矩陣皆可逆, 故不須挑選特定組合)
        std::vector<std::pair<int, SymbBlock>> chosen;
        chosen.reserve(K);
        for (auto& s : symbol) {
            if (s.first < 0 || static_cast<size_t>(s.first) >= K + M) {
                throw std::runtime_error("symbol 索引超出範圍");
            }
            chosen.push_back(s);
            if (chosen.size() == K) {
                break;
            }
        }

        size_t len = chosen[0].second.symb_len; // 呼叫端保證所有封包長度一致

        // 組成 [A | I] 增廣矩陣, A 為 chosen 對應在 G 中的 K x K 子矩陣
        size_t n = K;
        uint8_t** aug = allocMatrix(n, 2 * n);
        for (size_t i = 0; i < n; ++i) {
            int idx = chosen[i].first;
            for (size_t j = 0; j < n; ++j) {
                aug[i][j] = G[idx][j];
            }
            aug[i][n + i] = 1;
        }
        freeMatrix(G, K + M);

        // 消去求反矩陣: [A|I] -> [I|A^-1]
        // row = n (欲消去成單位矩陣的維度), column = 2*n (整個增廣矩陣寬度)
        GaussianElimination(aug, n, 2 * n);

        uint8_t** Ainv = allocMatrix(n, n);
        for (size_t i = 0; i < n; ++i) {
            for (size_t j = 0; j < n; ++j) {
                Ainv[i][j] = aug[i][n + j];
            }
        }
        freeMatrix(aug, n);

        // 還原: original[j] = sum_i Ainv[j][i] * chosen[i].data
        std::vector<SymbBlock> result;
        result.reserve(K);
        for (size_t j = 0; j < K; ++j) {
            uint8_t* out = new uint8_t[len];
            memset(out, 0, len);
            for (size_t i = 0; i < n; ++i) {
                uint8_t coeff = Ainv[j][i];
                if (coeff == 0) {
                    continue;
                }
                const uint8_t* src = chosen[i].second.symb;
                for (size_t b = 0; b < len; ++b) {
                    out[b] ^= gfMul(coeff, src[b]);
                }
            }
            result.push_back(SymbBlock{out, len});
        }

        freeMatrix(Ainv, n);
        return result;
    }

    std::pair<uint8_t, double> ReedSolomonFec::Update(size_t rtt) {
        return {6, 0.4};
    }
} // namespace ns3
