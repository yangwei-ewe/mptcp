/* Author: Mike Lubinets (aka mersinvald)
 * Date: 29.12.15
 *
 * See LICENSE */

#include "ns3/rscode.h"

#include "ns3/core-module.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

NS_LOG_COMPONENT_DEFINE("FecRSCode");

namespace ns3 {

#define MSG_CNT 3   // message-length polynomials count
#define POLY_CNT 14 // (this->ecc_length*2)-length polynomials count

    ReedSolomonFec::ReedSolomonFec()
        : msg_length(0),
          ecc_length(0),
          symb_length(0) {
        // Dummy constructor, gcc-generated one crashes program
    }

    ReedSolomonFec::ReedSolomonFec(size_t symbol_len, uint8_t msg_len, uint8_t ecc_len) {
        this->msg_length = msg_len;
        this->ecc_length = ecc_len;
        this->symb_length = symbol_len;
        NS_ASSERT(this->msg_length + this->ecc_length < 256);
        const uint8_t enc_len = this->msg_length + this->ecc_length;
        const uint8_t poly_len = this->ecc_length * 2;
        uint8_t** memptr = &memory;
        uint16_t offset = 0;

        /* Initialize first six polys manually cause their amount depends on template parameters
         */

        polynoms[0].Init(ID_MSG_IN, offset, enc_len, memptr);
        offset += enc_len;

        polynoms[1].Init(ID_MSG_OUT, offset, enc_len, memptr);
        offset += enc_len;

        for (uint8_t i = ID_GENERATOR; i < ID_MSG_E; i++) {
            polynoms[i].Init(i, offset, poly_len, memptr);
            offset += poly_len;
        }

        polynoms[5].Init(ID_MSG_E, offset, enc_len, memptr);
        offset += enc_len;

        for (uint8_t i = ID_TPOLY3; i < ID_ERR_EVAL + 2; i++) {
            polynoms[i].Init(i, offset, poly_len, memptr);
            offset += poly_len;
        }
    }

    /* @brief Message block encoding for variable-length symbols
     * @param src_blocks - input message blocks array (msg_length SymbBlocks)
     * @param dst_blocks - output buffer for ecc blocks (ecc_length SymbBlocks) */
    void ReedSolomonFec::EncodeBlock(const SymbBlock* src_blocks, SymbBlock* dst_blocks) {
        /* Generator cache, it doesn't change for one template parameters */
        uint8_t generator_cache[this->ecc_length + 1] = {0};
        bool generator_cached = false;

        /* Allocating memory on stack for polynomials storage */
        uint8_t stack_memory[MSG_CNT * this->msg_length + POLY_CNT * this->ecc_length * 2];
        this->memory = stack_memory;

        Poly* msg_in = &polynoms[ID_MSG_IN];
        Poly* msg_out = &polynoms[ID_MSG_OUT];
        Poly* gen = &polynoms[ID_GENERATOR];

        // Process each byte position across all symbols
        for (size_t byte_pos = 0; byte_pos < this->symb_length; byte_pos++) {
            // Extract bytes at this position from all source symbols
            uint8_t input_bytes[this->msg_length];
            for (uint8_t i = 0; i < this->msg_length; i++) {
                if (byte_pos < src_blocks[i].symb_len) {
                    input_bytes[i] = src_blocks[i].symb[byte_pos];
                } else {
                    input_bytes[i] = 0; // Pad with zeros
                }
            }

            // Reset polynomials for this iteration
            msg_in->Reset();
            msg_out->Reset();

            // Generate or use cached generator polynomial
            if (!generator_cached) {
                GeneratorPoly();
                memcpy(generator_cache, gen->ptr(), gen->length);
                generator_cached = true;
            } else {
                gen->Set(generator_cache, gen->length);
            }

            // Copy input message to internal polynomial
            msg_in->Set(input_bytes, this->msg_length);
            msg_out->Set(input_bytes, this->msg_length);
            msg_out->length = msg_in->length + this->ecc_length;

            // Perform Reed-Solomon encoding
            uint8_t coef = 0; // cache
            for (uint8_t i = 0; i < this->msg_length; i++) {
                coef = msg_out->at(i);
                if (coef != 0) {
                    for (uint32_t j = 1; j < gen->length; j++) {
                        msg_out->at(i + j) ^= gf::mul(gen->at(j), coef);
                    }
                }
            }

            // Copy ECC bytes to output blocks
            for (uint8_t i = 0; i < this->ecc_length; i++) {
                if (byte_pos < dst_blocks[i].symb_len) {
                    dst_blocks[i].symb[byte_pos] = msg_out->at(this->msg_length + i);
                }
            }
        }
    }

    /* @brief Message encoding with variable-length symbols
     * @param symb - input symbols (msg_length SymbBlocks)
     * @param ecc_len - number of ECC symbols to generate
     * @return encoded symbols (msg_length + ecc_len SymbBlocks)
     */
    std::vector<SymbBlock> ReedSolomonFec::EncodeImpl(const std::vector<SymbBlock>& symb,
                                                      size_t ecc_len) {
        std::vector<SymbBlock> result;

        // Copy input symbols
        for (const auto& sym : symb) {
            SymbBlock sb;
            sb.symb_len = sym.symb_len;
            sb.symb = new uint8_t[sym.symb_len];
            memcpy(sb.symb, sym.symb, sym.symb_len);
            result.push_back(sb);
        }

        // Allocate ECC symbols
        std::vector<SymbBlock> ecc_blocks;
        for (size_t i = 0; i < ecc_len; i++) {
            SymbBlock sb;
            sb.symb_len = this->symb_length;
            sb.symb = new uint8_t[this->symb_length];
            memset(sb.symb, 0, this->symb_length);
            ecc_blocks.push_back(sb);
        }

        // Perform encoding
        if (symb.size() >= this->msg_length && ecc_len >= this->ecc_length) {
            this->EncodeBlock(symb.data(), ecc_blocks.data());
        }

        // Append ECC blocks to result
        for (auto& ecc : ecc_blocks) {
            result.push_back(ecc);
        }

        return result;
    }

    /* @brief Message block decoding
     * @param *src         - encoded message buffer   (this->msg_length size)
     * @param *ecc         - ecc buffer               (this->ecc_length size)
     * @param *msg_out     - output buffer            (this->msg_length size at least)
     * @param *erase_pos   - known errors positions
     * @param erase_count  - count of known errors
     * @return RESULT_SUCCESS if successful, error code otherwise */
    /* @brief Message block decoding for variable-length symbols
     * @param src_blocks    - encoded message blocks (msg_length SymbBlocks)
     * @param ecc_blocks    - ecc blocks (ecc_length SymbBlocks)
     * @param dst_blocks    - output buffer (msg_length SymbBlocks)
     * @param erase_pos     - known errors positions
     * @param erase_count   - count of known errors
     * @return RESULT_SUCCESS if successful, error code otherwise */
    int ReedSolomonFec::DecodeBlock(const SymbBlock* src_blocks,
                                    const SymbBlock* ecc_blocks,
                                    SymbBlock* dst_blocks,
                                    uint8_t* erase_pos,
                                    size_t erase_count) {
        const uint8_t src_len = this->msg_length + this->ecc_length;

        /* Allocation memory on stack */
        uint8_t stack_memory[MSG_CNT * this->msg_length + POLY_CNT * this->ecc_length * 2];
        this->memory = stack_memory;

        // Process each byte position
        for (size_t byte_pos = 0; byte_pos < this->symb_length; byte_pos++) {
            // Extract bytes at this position
            uint8_t input_bytes[this->msg_length + this->ecc_length];

            for (uint8_t i = 0; i < this->msg_length; i++) {
                if (byte_pos < src_blocks[i].symb_len) {
                    input_bytes[i] = src_blocks[i].symb[byte_pos];
                } else {
                    input_bytes[i] = 0;
                }
            }

            for (uint8_t i = 0; i < this->ecc_length; i++) {
                if (byte_pos < ecc_blocks[i].symb_len) {
                    input_bytes[this->msg_length + i] = ecc_blocks[i].symb[byte_pos];
                } else {
                    input_bytes[this->msg_length + i] = 0;
                }
            }

            bool ok;
            Poly* msg_in = &polynoms[ID_MSG_IN];
            Poly* msg_out = &polynoms[ID_MSG_OUT];
            Poly* epos = &polynoms[ID_ERASURES];

            // Copy message to polynomials memory
            msg_in->Set(input_bytes, this->msg_length);
            msg_in->Set(input_bytes + this->msg_length, this->ecc_length, this->msg_length);
            msg_out->Copy(msg_in);

            // Copy known errors to polynomial
            if (erase_pos != NULL && erase_count > 0) {
                epos->Set(erase_pos, erase_count);
                for (uint8_t i = 0; i < epos->length; i++) {
                    msg_in->at(epos->at(i)) = 0;
                }
            } else {
                epos->length = 0;
            }

            // Too many errors
            if (epos->length > this->ecc_length) {
                return 1;
            }

            Poly* synd = &polynoms[ID_SYNDROMES];
            Poly* eloc = &polynoms[ID_ERRORS_LOC];
            Poly* reloc = &polynoms[ID_TPOLY1];
            Poly* err = &polynoms[ID_ERRORS];
            Poly* forney = &polynoms[ID_FORNEY];

            // Calculate syndrome
            CalcSyndromes(msg_in);

            // Check for errors
            bool has_errors = false;
            for (uint8_t i = 0; i < synd->length; i++) {
                if (synd->at(i) != 0) {
                    has_errors = true;
                    break;
                }
            }

            // Skip if no errors
            if (!has_errors) {
                // Copy corrected bytes to output
                for (uint8_t i = 0; i < this->msg_length; i++) {
                    if (byte_pos < dst_blocks[i].symb_len) {
                        dst_blocks[i].symb[byte_pos] = msg_out->at(i);
                    }
                }
                continue;
            }

            CalcForneySyndromes(synd, epos, src_len);
            FindErrorLocator(forney, NULL, epos->length);

            // Reverse syndrome
            reloc->length = eloc->length;
            for (int8_t i = eloc->length - 1, j = 0; i >= 0; i--, j++) {
                reloc->at(j) = eloc->at(i);
            }

            // Find errors
            ok = FindErrors(reloc, src_len);
            if (!ok) {
                return 1;
            }

            // Error happened while finding errors
            if (err->length == 0) {
                return 1;
            }

            // Add found errors with known
            for (uint8_t i = 0; i < err->length; i++) {
                epos->Append(err->at(i));
            }

            // Correct errors
            CorrectErrata(synd, epos, msg_in);

            // Copy corrected bytes to output
            for (uint8_t i = 0; i < this->msg_length; i++) {
                if (byte_pos < dst_blocks[i].symb_len) {
                    dst_blocks[i].symb[byte_pos] = msg_out->at(i);
                }
            }
        }

        return 0;
    }

    /* @brief Message block decoding
     * @param *src         - encoded message buffer   (this->msg_length + this->ecc_length size)
     * @param *msg_out     - output buffer            (this->msg_length size at least)
     * @param *erase_pos   - known errors positions
     * @param erase_count  - count of known errors
     * @return RESULT_SUCCESS if successful, error code otherwise */
    // int ReedSolomonFec::Decode(const void* src,
    //                            void* dst,
    //                            uint8_t* erase_pos = NULL,
    //                            size_t erase_count = 0) {
    //     const uint8_t* src_ptr = (const uint8_t*)src;
    //     const uint8_t* ecc_ptr = src_ptr + this->msg_length;

    //     return DecodeBlock(src, ecc_ptr, dst, erase_pos, erase_count);
    // }

    std::vector<SymbBlock> ReedSolomonFec::DecodeImpl(
        const std::vector<std::pair<int, SymbBlock>>& symbol,
        size_t pack_num) {
        std::vector<SymbBlock> result;

        // Verify that we have enough symbols
        if (symbol.size() < this->msg_length + this->ecc_length) {
            // Not enough symbols for decoding
            return result;
        }

        // Separate message and ECC blocks
        std::vector<SymbBlock> src_blocks;
        std::vector<SymbBlock> ecc_blocks;

        for (size_t i = 0; i < this->msg_length; i++) {
            src_blocks.push_back(symbol[i].second); // ?
        }

        for (size_t i = 0; i < this->ecc_length; i++) {
            ecc_blocks.push_back(symbol[this->msg_length + i].second); //?
        }

        // Allocate output blocks
        std::vector<SymbBlock> dst_blocks;
        for (size_t i = 0; i < this->msg_length; i++) {
            SymbBlock sb;
            sb.symb_len = this->symb_length;
            sb.symb = new uint8_t[this->symb_length];
            memset(sb.symb, 0, this->symb_length);
            dst_blocks.push_back(sb);
        }

        // Perform decoding
        int decode_result =
            this->DecodeBlock(src_blocks.data(), ecc_blocks.data(), dst_blocks.data(), NULL, 0);

        if (decode_result == 0) {
            // Decoding successful, copy to result
            for (auto& block : dst_blocks) {
                result.push_back(block);
            }
        } else {
            // Decoding failed, clean up
            for (auto& block : dst_blocks) {
                delete[] block.symb;
            }
        }

        return result;
    }

    void ReedSolomonFec::GeneratorPoly() {
        Poly* gen = polynoms + ID_GENERATOR;
        gen->at(0) = 1;
        gen->length = 1;

        Poly* mulp = polynoms + ID_TPOLY1;
        Poly* temp = polynoms + ID_TPOLY2;
        mulp->length = 2;

        for (int8_t i = 0; i < this->ecc_length; i++) {
            mulp->at(0) = 1;
            mulp->at(1) = gf::pow(2, i);

            gf::poly_mul(gen, mulp, temp);

            gen->Copy(temp);
        }
    }

    void ReedSolomonFec::CalcSyndromes(const Poly* msg) {
        Poly* synd = &polynoms[ID_SYNDROMES];
        synd->length = this->ecc_length + 1;
        synd->at(0) = 0;
        for (uint8_t i = 1; i < this->ecc_length + 1; i++) {
            synd->at(i) = gf::poly_eval(msg, gf::pow(2, i - 1));
        }
    }

    void ReedSolomonFec::FindErrataLocator(const Poly* epos) {
        Poly* errata_loc = &polynoms[ID_ERASURES_LOC];
        Poly* mulp = &polynoms[ID_TPOLY1];
        Poly* addp = &polynoms[ID_TPOLY2];
        Poly* apol = &polynoms[ID_TPOLY3];
        Poly* temp = &polynoms[ID_TPOLY4];

        errata_loc->length = 1;
        errata_loc->at(0) = 1;

        mulp->length = 1;
        addp->length = 2;

        for (uint8_t i = 0; i < epos->length; i++) {
            mulp->at(0) = 1;
            addp->at(0) = gf::pow(2, epos->at(i));
            addp->at(1) = 0;

            gf::poly_add(mulp, addp, apol);
            gf::poly_mul(errata_loc, apol, temp);

            errata_loc->Copy(temp);
        }
    }

    void ReedSolomonFec::FindErrorEvaluator(const Poly* synd,
                                            const Poly* errata_loc,
                                            Poly* dst,
                                            uint8_t ecclen) {
        Poly* mulp = &polynoms[ID_TPOLY1];
        gf::poly_mul(synd, errata_loc, mulp);

        Poly* divisor = &polynoms[ID_TPOLY2];
        divisor->length = ecclen + 2;

        divisor->Reset();
        divisor->at(0) = 1;

        gf::poly_div(mulp, divisor, dst);
    }

    void ReedSolomonFec::CorrectErrata(const Poly* synd, const Poly* err_pos, const Poly* msg_in) {
        Poly* c_pos = &polynoms[ID_COEF_POS];
        Poly* corrected = &polynoms[ID_MSG_OUT];
        c_pos->length = err_pos->length;

        for (uint8_t i = 0; i < err_pos->length; i++) {
            c_pos->at(i) = msg_in->length - 1 - err_pos->at(i);
        }

        /* uses t_poly 1, 2, 3, 4 */
        FindErrataLocator(c_pos);
        Poly* errata_loc = &polynoms[ID_ERASURES_LOC];

        /* reversing syndromes */
        Poly* rsynd = &polynoms[ID_TPOLY3];
        rsynd->length = synd->length;

        for (int8_t i = synd->length - 1, j = 0; i >= 0; i--, j++) {
            rsynd->at(j) = synd->at(i);
        }

        /* getting reversed error evaluator polynomial */
        Poly* re_eval = &polynoms[ID_TPOLY4];

        /* uses T_POLY 1, 2 */
        FindErrorEvaluator(rsynd, errata_loc, re_eval, errata_loc->length - 1);

        /* reversing it back */
        Poly* e_eval = &polynoms[ID_ERR_EVAL];
        e_eval->length = re_eval->length;
        for (int8_t i = re_eval->length - 1, j = 0; i >= 0; i--, j++) {
            e_eval->at(j) = re_eval->at(i);
        }

        Poly* X = &polynoms[ID_TPOLY1]; /* this will store errors positions */
        X->length = 0;

        int16_t l;
        for (uint8_t i = 0; i < c_pos->length; i++) {
            l = 255 - c_pos->at(i);
            X->Append(gf::pow(2, -l));
        }

        /* Magnitude polynomial
           Shit just got real */
        Poly* E = &polynoms[ID_MSG_E];
        E->Reset();
        E->length = msg_in->length;

        uint8_t Xi_inv;

        Poly* err_loc_prime_temp = &polynoms[ID_TPOLY2];

        uint8_t err_loc_prime;
        uint8_t y;

        for (uint8_t i = 0; i < X->length; i++) {
            Xi_inv = gf::inverse(X->at(i));

            err_loc_prime_temp->length = 0;
            for (uint8_t j = 0; j < X->length; j++) {
                if (j != i) {
                    err_loc_prime_temp->Append(gf::sub(1, gf::mul(Xi_inv, X->at(j))));
                }
            }

            err_loc_prime = 1;
            for (uint8_t j = 0; j < err_loc_prime_temp->length; j++) {
                err_loc_prime = gf::mul(err_loc_prime, err_loc_prime_temp->at(j));
            }

            y = gf::poly_eval(re_eval, Xi_inv);
            y = gf::mul(gf::pow(X->at(i), 1), y);

            E->at(err_pos->at(i)) = gf::div(y, err_loc_prime);
        }

        gf::poly_add(msg_in, E, corrected);
    }

    bool ReedSolomonFec::FindErrorLocator(const Poly* synd,
                                          Poly* erase_loc = NULL,
                                          size_t erase_count = 0) {
        Poly* error_loc = &polynoms[ID_ERRORS_LOC];
        Poly* err_loc = &polynoms[ID_TPOLY1];
        Poly* old_loc = &polynoms[ID_TPOLY2];
        Poly* temp = &polynoms[ID_TPOLY3];
        Poly* temp2 = &polynoms[ID_TPOLY4];

        if (erase_loc != NULL) {
            err_loc->Copy(erase_loc);
            old_loc->Copy(erase_loc);
        } else {
            err_loc->length = 1;
            old_loc->length = 1;
            err_loc->at(0) = 1;
            old_loc->at(0) = 1;
        }

        uint8_t synd_shift = 0;
        if (synd->length > this->ecc_length) {
            synd_shift = synd->length - this->ecc_length;
        }

        uint8_t K = 0;
        uint8_t delta = 0;
        uint8_t index;

        for (uint8_t i = 0; i < this->ecc_length - erase_count; i++) {
            if (erase_loc != NULL) {
                K = erase_count + i + synd_shift;
            } else {
                K = i + synd_shift;
            }

            delta = synd->at(K);
            for (uint8_t j = 1; j < err_loc->length; j++) {
                index = err_loc->length - j - 1;
                delta ^= gf::mul(err_loc->at(index), synd->at(K - j));
            }

            old_loc->Append(0);

            if (delta != 0) {
                if (old_loc->length > err_loc->length) {
                    gf::poly_scale(old_loc, temp, delta);
                    gf::poly_scale(err_loc, old_loc, gf::inverse(delta));
                    err_loc->Copy(temp);
                }
                gf::poly_scale(old_loc, temp, delta);
                gf::poly_add(err_loc, temp, temp2);
                err_loc->Copy(temp2);
            }
        }

        uint32_t shift = 0;
        while (err_loc->length && err_loc->at(shift) == 0) {
            shift++;
        }

        uint32_t errs = err_loc->length - shift - 1;
        if (((errs - erase_count) * 2 + erase_count) > this->ecc_length) {
            return false; /* Error count is greater than we can fix! */
        }

        memcpy(error_loc->ptr(),
               err_loc->ptr() + shift,
               (err_loc->length - shift) * sizeof(uint8_t));
        error_loc->length = (err_loc->length - shift);
        return true;
    }

    bool ReedSolomonFec::FindErrors(const Poly* error_loc, size_t msg_in_size) {
        Poly* err = &polynoms[ID_ERRORS];

        uint8_t errs = error_loc->length - 1;
        err->length = 0;

        for (uint8_t i = 0; i < msg_in_size; i++) {
            if (gf::poly_eval(error_loc, gf::pow(2, i)) == 0) {
                err->Append(msg_in_size - 1 - i);
            }
        }

        /* Sanity check:
         * the number of err/errata positions found
         * should be exactly the same as the length of the errata locator polynomial */
        if (err->length != errs) {
            /* couldn't find error locations */
            return false;
        }
        return true;
    }

    void ReedSolomonFec::CalcForneySyndromes(const Poly* synd,
                                             const Poly* erasures_pos,
                                             size_t msg_in_size) {
        Poly* erase_pos_reversed = &polynoms[ID_TPOLY1];
        Poly* forney_synd = &polynoms[ID_FORNEY];
        erase_pos_reversed->length = 0;

        for (uint8_t i = 0; i < erasures_pos->length; i++) {
            erase_pos_reversed->Append(msg_in_size - 1 - erasures_pos->at(i));
        }

        forney_synd->Reset();
        forney_synd->Set(synd->ptr() + 1, synd->length - 1);

        uint8_t x;
        for (uint8_t i = 0; i < erasures_pos->length; i++) {
            x = gf::pow(2, erase_pos_reversed->at(i));
            for (int8_t j = 0; j < forney_synd->length - 1; j++) {
                forney_synd->at(j) = gf::mul(forney_synd->at(j), x) ^ forney_synd->at(j + 1);
            }
        }
    }
}; // namespace ns3
