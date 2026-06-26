/* Author: Mike Lubinets (aka mersinvald)
 * Date: 29.12.15
 *
 * See LICENSE */

#ifndef RS_HPP
#define RS_HPP
#include "ns3/fec.h"
#include "ns3/rscode-gf.hpp"
#include "ns3/rscode-poly.hpp"

#include <stdint.h>
#include <string.h>

namespace ns3 {

#define MSG_CNT 3   // message-length polynomials count
#define POLY_CNT 14 // (ecc_length*2)-length polynomials count

    class ReedSolomonFec : public MpTcpFec {
      public:
        ReedSolomonFec();
        ReedSolomonFec(size_t symbol_len, uint8_t msg_len, uint8_t ecc_len);

        ~ReedSolomonFec() {
            // Dummy destructor, gcc-generated one crashes program
            memory = NULL;
        }

      protected:
        /**
         * @brief
         *
         * @param symb
         * @param ecc_len
         * @return std::vector<SymbBlock>
         */
        // std::vector<SymbBlock> EncodeImpl(const std::vector<SymbBlock>& symb,
        //                                   size_t ecc_len) override;
        std::vector<SymbBlock> EncodeImpl(const std::vector<SymbBlock>& symb,
                                          size_t ecc_len) override;
        /**
         * @brief
         *
         * @param symbol
         * @param pack_num
         * @return std::vector<SymbBlock>
         */
        std::vector<SymbBlock> DecodeImpl(const std::vector<std::pair<int, SymbBlock>>& symbol,
                                          size_t pack_num) override;
        /**
         * @brief
         *
         * @param symbol
         * @return std::vector<SymbBlock>
         */
        // std::vector<SymbBlock> DecodeImpl(const std::vector<SymbBlock>& symbol) override;
        /* @brief Message block decoding
         * @param *src         - encoded message buffer   (msg_length + ecc_length size)
         * @param *msg_out     - output buffer            (msg_length size at least)
         * @param *erase_pos   - known errors positions
         * @param erase_count  - count of known errors
         * @return RESULT_SUCCESS if successful, error code otherwise */
        // int Decode(const void* src, void* dst, uint8_t* erase_pos = NULL, size_t erase_count =
        // 0);

      private:
        uint8_t msg_length;
        uint8_t ecc_length;
        size_t symb_length; // how many byte in each symbol, set to mss in mptcp

        enum POLY_ID {
            ID_MSG_IN = 0,
            ID_MSG_OUT,
            ID_GENERATOR, // 3
            ID_TPOLY1,    // T for Temporary
            ID_TPOLY2,
            ID_MSG_E,  // 5
            ID_TPOLY3, // 6
            ID_TPOLY4,
            ID_SYNDROMES,
            ID_FORNEY,
            ID_ERASURES_LOC,
            ID_ERRORS_LOC,
            ID_ERASURES,
            ID_ERRORS,
            ID_COEF_POS,
            ID_ERR_EVAL
        };

        // Pointer for polynomials memory on stack
        uint8_t* memory;
        Poly polynoms[MSG_CNT + POLY_CNT];

        void GeneratorPoly();
        void CalcSyndromes(const Poly* msg);
        void FindErrataLocator(const Poly* epos);
        void FindErrorEvaluator(const Poly* synd,
                                const Poly* errata_loc,
                                Poly* dst,
                                uint8_t ecclen);

        void CorrectErrata(const Poly* synd, const Poly* err_pos, const Poly* msg_in);
        bool FindErrorLocator(const Poly* synd, Poly* erase_loc = NULL, size_t erase_count = 0);
        bool FindErrors(const Poly* error_loc, size_t msg_in_size);
        void CalcForneySyndromes(const Poly* synd, const Poly* erasures_pos, size_t msg_in_size);

        /* @brief Message block encoding
         * @param src_blocks - input message blocks array (msg_length SymbBlocks)
         * @param dst_blocks - output buffer for ecc blocks (ecc_length SymbBlocks) */
        void EncodeBlock(const SymbBlock* src_blocks, SymbBlock* dst_blocks);
        /* @brief Message block decoding
         * @param src_blocks   - encoded message blocks (msg_length SymbBlocks)
         * @param ecc_blocks   - ecc blocks (ecc_length SymbBlocks)
         * @param dst_blocks   - output buffer (msg_length SymbBlocks)
         * @param erase_pos    - known errors positions
         * @param erase_count  - count of known errors
         * @return RESULT_SUCCESS if successful, error code otherwise */
        int DecodeBlock(const SymbBlock* src_blocks,
                        const SymbBlock* ecc_blocks,
                        SymbBlock* dst_blocks,
                        uint8_t* erase_pos = NULL,
                        size_t erase_count = 0);
    };

} // namespace ns3

#endif // RS_HPP
