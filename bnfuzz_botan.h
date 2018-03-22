
#ifndef BNFUZZ_IMPL_BOTAN_H_
#define BNFUZZ_IMPL_BOTAN_H_

#include "bnfuzz.h"
#include <botan/bigint.h>
#include <botan/numthry.h>
#include <botan/ec_group.h>
#include <botan/system_rng.h>
#include <botan/reducer.h>
#include <botan/hex.h>

namespace BN_Fuzz {

class Botan_BN_Lib : public BN_Lib
   {
   private:
      std::vector<Botan::BigInt> ec_ws;
      Botan::EC_Group secp256r1;
      Botan::EC_Group secp384r1;
      Botan::EC_Group secp521r1;
      Botan::EC_Group bp256r1;

      std::string to_string(const Botan::BigInt& x) const
         {
         if(x == 0)
            return "0";
         std::vector<uint8_t> bits = Botan::BigInt::encode(x);
         std::string hex = Botan::hex_encode(bits);

         if(x.is_negative())
            return "-" + hex;
         else
            return hex;
         }

   public:
      Botan_BN_Lib()
         {
         ::setenv("BOTAN_MLOCK_POOL_SIZE", "0", 1);

         secp256r1 = Botan::EC_Group("secp256r1");
         secp384r1 = Botan::EC_Group("secp384r1");
         secp521r1 = Botan::EC_Group("secp521r1");
         bp256r1 = Botan::EC_Group("brainpool256r1");
         }

      std::string name() const override { return "botan"; }

      std::string op(BN_op operation,
                     const std::vector<uint8_t>& a8, bool a_neg,
                     const std::vector<uint8_t>& b8, bool b_neg,
                     const std::vector<uint8_t>& c8, bool c_neg,
                     uint8_t variant) override
         {
         using namespace Botan;

         BigInt a(a8.data(), a8.size());
         BigInt b(b8.data(), b8.size());
         BigInt c(c8.data(), c8.size());

         if(a_neg)
            a.flip_sign();
         if(b_neg)
            b.flip_sign();
         if(c_neg)
            c.flip_sign();

         switch(operation)
            {
            case BN_op::Add:
               {
               if(variant & 1)
                  {
                  return to_string(a + b);
                  }
               else
                  {
                  a += b;
                  return to_string(a);
                  }
               }

            case BN_op::Sub:
               {
               if(variant & 1)
                  {
                  return to_string(a - b);
                  }
               else
                  {
                  a -= b;
                  return to_string(a);
                  }
               }

            case BN_op::Mul:
               {
               if(variant & 1)
                  {
                  return to_string(a * b);
                  }
               else
                  {
                  a *= b;
                  return to_string(a);
                  }
               }

            case BN_op::Div:
               if(b <= 0)
                  return "0";
               else
                  {
                  if(variant & 1)
                     return to_string(a / b);
                  else
                     {
                     a /= b;
                     return to_string(a);
                     }
                  }

            case BN_op::Rem:
               if(b <= 0)
                  return "0";
               else
                  return to_string(a % b);

            case BN_op::ModExp:
               return to_string(power_mod(a, b, c));

            case BN_op::ModSqr:
               // Match BN_mod_mul behavior
               if(b == 0)
                  {
                  return to_string(square(a));
                  }
               else if(b.is_negative())
                  {
                  return "0";
                  }
               else
                  {
                  if(variant & 1)
                     {
                     Modular_Reducer mod_b(b);
                     return to_string(mod_b.square(a));
                     }
                  else
                     return to_string(square(a) % b);
                  }

            case BN_op::ModMul:
               // Match BN_mod_mul behavior
               if(c <= 0)
                  {
                  return "0";
                  }
               else
                  {
                  if(variant & 1)
                     {
                     Modular_Reducer mod_c(c);
                     return to_string(mod_c.multiply(a, b));
                     }
                  else
                     {
                     return to_string((a*b) % c);
                     }
                  }

            case BN_op::ModInv:
               if(b == 0 || a_neg || b_neg)
                  return "0";
               return to_string(inverse_mod(a, b));

            case BN_op::P256_mul_x:
               {
               return to_string(
                  secp256r1.blinded_base_point_multiply_x(a, Botan::system_rng(), ec_ws));
               }

            case BN_op::P384_mul_x:
               {
               return to_string(
                  secp384r1.blinded_base_point_multiply_x(a, Botan::system_rng(), ec_ws));
               }

            case BN_op::P521_mul_x:
               {
               return to_string(
                  secp521r1.blinded_base_point_multiply_x(a, Botan::system_rng(), ec_ws));
               }

            case BN_op::BP256_mul_x:
               {
               return to_string(
                  bp256r1.blinded_base_point_multiply_x(a, Botan::system_rng(), ec_ws));
               }
            }

         return "";
         }
   };

}

#endif
