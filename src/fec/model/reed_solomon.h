#ifndef REED_SOLOMON_H
#define REED_SOLOMON_H

#include "ns3/fec.h"

namespace ns3 {
    class ReedSolomonFec : public MpTcpFec {
      public:
        ReedSolomonFec();
        std::pair<uint8_t, double> Update(size_t rtt);
        void makeCauchyMatrix(uint8_t** matrix, size_t K, size_t M);

        // row: 矩陣列數 (要消去成單位矩陣的維度)
        // column: 矩陣行數 (row <= column, 本檔案用法為 column == 2*row 的 [A|I] 增廣矩陣)
        // 執行完畢後, matrix 的前 row 行會變成單位矩陣, 其餘部分同步做對應的列運算
        void GaussianElimination(uint8_t** matrix, size_t row, size_t column);

        std::vector<SymbBlock> EncodeImpl(const std::vector<SymbBlock>& source, size_t ecc_len);
        std::vector<SymbBlock> DecodeImpl(const std::vector<std::pair<int, SymbBlock>>& symbol,
                                          size_t m,
                                          size_t pack_num);

      private:
        // ---- GF(2^8) 運算表: 建構後唯讀, 不構成跨呼叫狀態 ----
        uint8_t gfMul(uint8_t a, uint8_t b) const;
        uint8_t gfInv(uint8_t a) const;

        static uint8_t** allocMatrix(size_t rows, size_t cols);
        static void freeMatrix(uint8_t** m, size_t rows);
    };
} // namespace ns3

#endif // REED_SOLOMON_H
