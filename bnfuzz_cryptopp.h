
#ifndef BNFUZZ_IMPL_CRYPTOPP_H_
#define BNFUZZ_IMPL_CRYPTOPP_H_

#include "bnfuzz.h"
#include <cryptopp/integer.h>
#include <cryptopp/hex.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>

namespace BN_Fuzz {

class CryptoPP_BN_Lib : public BN_Lib
   {
   private:
      CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> secp256r1;
      CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> secp384r1;
      CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> secp521r1;
      CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> bp256r1;
      /* whatever */

      std::string hex_encode(const uint8_t* b, size_t len)
         {
         CryptoPP::HexEncoder hex;
         hex.Put(b, len);
         hex.MessageEnd();

         size_t size = hex.MaxRetrievable();
         std::string str;
         if(size)
            {
            str.resize(size);
            hex.Get((uint8_t*)str.data(), size);
            }
         return str;
         }

      std::string to_string(const CryptoPP::Integer& x)
         {
         if(x == 0)
            return "0";

         std::vector<uint8_t> bits(x.MinEncodedSize());
         x.Encode(bits.data(), bits.size());

         std::string hex = hex_encode(bits.data(), bits.size());
         if(x < 0)
            return "-" + hex;
         else
            return hex;
         }

   public:
      CryptoPP_BN_Lib() :
         secp256r1(CryptoPP::ASN1::secp256r1()),
         secp384r1(CryptoPP::ASN1::secp384r1()),
         secp521r1(CryptoPP::ASN1::secp521r1()),
         bp256r1(CryptoPP::ASN1::brainpoolP256r1())
         {
         }

      std::string name() const override { return "cryptopp"; }

      std::string op(BN_op operation,
                     const std::vector<uint8_t>& a8, bool a_neg,
                     const std::vector<uint8_t>& b8, bool b_neg,
                     const std::vector<uint8_t>& c8, bool c_neg,
                     uint8_t variant) override
         {
         using CryptoPP::Integer;

         Integer a(a8.data(), a8.size());
         Integer b(b8.data(), b8.size());
         Integer c(c8.data(), c8.size());
         if(a_neg)
            a.SetNegative();
         if(b_neg)
            b.SetNegative();
         if(c_neg)
            c.SetNegative();

         switch(operation)
            {
            case BN_op::Add:
               return to_string(a + b);

            case BN_op::Sub:
               return to_string(a - b);

            case BN_op::Mul:
               return to_string(a * b);

            case BN_op::Div:
               if(b <= 0)
                  return "0";
               else
                  return to_string(a / b);

            case BN_op::Rem:
               if(b <= 0)
                  return "0";
               else
                  return to_string(a % b);

            case BN_op::ModExp:
               if(c < 0 || c == 1)
                  return "0";
               if(a == 0 || c == 0)
                  {
                  if(b == 0)
                     return "01";
                  else
                     return "0";
                  }
               return to_string(a_exp_b_mod_c(a, b, c));

            case BN_op::ModSqr:
               if(b < 0)
                  return "0";
               else if(b == 0)
                  return to_string(a.Squared());
               else
                  return to_string((a.Squared())%b);

            case BN_op::ModMul:
               if(c <= 0)
                  return "0";
               return to_string(a_times_b_mod_c(a, b, c));

            case BN_op::ModInv:
               if(b == 0)
                  return "0";
               return to_string((a % b).InverseMod(b));

            case BN_op::P256_mul_x:
               return to_string(secp256r1.ExponentiateBase(a).x);

            case BN_op::P384_mul_x:
               return to_string(secp384r1.ExponentiateBase(a).x);

            case BN_op::P521_mul_x:
               return to_string(secp521r1.ExponentiateBase(a).x);

            case BN_op::BP256_mul_x:
               return to_string(bp256r1.ExponentiateBase(a).x);

            }

         return "";
         }
   };

}

#endif
