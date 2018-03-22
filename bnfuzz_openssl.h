
#ifndef BNFUZZ_IMPL_OPENSSL_H_
#define BNFUZZ_IMPL_OPENSSL_H_

#include "bnfuzz.h"
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <functional>

namespace BN_Fuzz {

class OpenSSL_BN_Lib : public BN_Lib
   {
   private:
      EC_GROUP* secp256r1;
      EC_GROUP* secp384r1;
      EC_GROUP* secp521r1;
      EC_GROUP* bp256r1;

      typedef std::unique_ptr<BIGNUM, std::function<void (BIGNUM*)>> BN_ptr;

      std::string string_of(const BN_ptr& a)
         {
         char* hex = BN_bn2hex(a.get());
         std::string s(hex);
         CRYPTO_free(hex, __FILE__, __LINE__);
         return s;
         }

   public:

      OpenSSL_BN_Lib()
         {
         m_ctx = BN_CTX_new();

         secp256r1 = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
         secp384r1 = EC_GROUP_new_by_curve_name(NID_secp384r1);
         secp521r1 = EC_GROUP_new_by_curve_name(NID_secp521r1);
         bp256r1 = EC_GROUP_new_by_curve_name(NID_brainpoolP256r1);

         EC_GROUP_precompute_mult(secp256r1, m_ctx);
         EC_GROUP_precompute_mult(secp384r1, m_ctx);
         EC_GROUP_precompute_mult(secp521r1, m_ctx);
         EC_GROUP_precompute_mult(bp256r1, m_ctx);
         }

      ~OpenSSL_BN_Lib()
         {
         BN_CTX_free(m_ctx);
         }

      std::string name() const override { return "openssl"; }

      std::string op(BN_op operation,
                     const std::vector<uint8_t>& a8, bool a_neg,
                     const std::vector<uint8_t>& b8, bool b_neg,
                     const std::vector<uint8_t>& c8, bool c_neg,
                     uint8_t variant) override
         {
         BN_ptr a(BN_bin2bn(a8.data(), a8.size(), NULL), BN_free);
         BN_ptr b(BN_bin2bn(b8.data(), b8.size(), NULL), BN_free);
         BN_ptr c(BN_bin2bn(c8.data(), c8.size(), NULL), BN_free);
         BN_ptr r(BN_new(), BN_free);

         BN_set_negative(a.get(), a_neg);
         BN_set_negative(b.get(), b_neg);
         BN_set_negative(c.get(), c_neg);

         switch(operation)
            {
            case BN_op::Add:
               {
               if(variant & 1)
                  BN_add(a.get(), a.get(), b.get());
               else
                  BN_add(a.get(), b.get(), a.get());
               return string_of(a);
               }

            case BN_op::Sub:
               BN_sub(a.get(), a.get(), b.get());
               return string_of(a);

            case BN_op::Mul:
               {
               if(variant & 1)
                  BN_mul(a.get(), a.get(), b.get(), m_ctx);
               else
                  BN_mul(a.get(), b.get(), a.get(), m_ctx);
               return string_of(a);
               }

            case BN_op::Div:
               BN_div(r.get(), nullptr, a.get(), b.get(), m_ctx);
               return string_of(r);

            case BN_op::Rem:
               BN_div(nullptr, r.get(), a.get(), b.get(), m_ctx);
               return string_of(r);

            case BN_op::ModExp:
               BN_mod_exp(r.get(), a.get(), b.get(), c.get(), m_ctx);
               return string_of(r);

            case BN_op::ModSqr:
               BN_mod_sqr(r.get(), a.get(), b.get(), m_ctx);
               return string_of(r);

            case BN_op::ModMul:
               BN_mod_mul(r.get(), a.get(), b.get(), c.get(), m_ctx);
               return string_of(r);

            case BN_op::ModInv:
               BN_mod_inverse(r.get(), a.get(), b.get(), m_ctx);
               return string_of(r);

            case BN_op::P256_mul_x:
               {
               EC_POINT* pt = EC_POINT_new(secp256r1);
               EC_POINT_mul(secp256r1, pt, a.get(), nullptr, nullptr, m_ctx);
               EC_POINT_get_affine_coordinates_GFp(secp256r1, pt, r.get(), nullptr, m_ctx);
               EC_POINT_free(pt);
               return string_of(r);
               }

            case BN_op::P384_mul_x:
               {
               EC_POINT* pt = EC_POINT_new(secp384r1);
               EC_POINT_mul(secp384r1, pt, a.get(), nullptr, nullptr, m_ctx);
               EC_POINT_get_affine_coordinates_GFp(secp384r1, pt, r.get(), nullptr, m_ctx);
               EC_POINT_free(pt);
               return string_of(r);
               }

            case BN_op::P521_mul_x:
               {
               EC_POINT* pt = EC_POINT_new(secp521r1);
               EC_POINT_mul(secp521r1, pt, a.get(), nullptr, nullptr, m_ctx);
               EC_POINT_get_affine_coordinates_GFp(secp521r1, pt, r.get(), nullptr, m_ctx);
               EC_POINT_free(pt);
               return string_of(r);
               }

            case BN_op::BP256_mul_x:
               {
               EC_POINT* pt = EC_POINT_new(bp256r1);
               EC_POINT_mul(bp256r1, pt, a.get(), nullptr, nullptr, m_ctx);
               EC_POINT_get_affine_coordinates_GFp(bp256r1, pt, r.get(), nullptr, m_ctx);
               EC_POINT_free(pt);
               return string_of(r);
               }
            }

         return "";
         }

   private:
      BN_CTX* m_ctx;
   };

}

#endif
