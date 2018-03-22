#include "bnfuzz.h"
#include <botan/bigint.h>
#include <botan/numthry.h>
#include <sstream>
#include <iostream>

namespace BN_Fuzz {

class Botan_BN_Lib : public BN_Lib
   {
   public:
      Botan_BN_Lib()
         {
         ::setenv("BOTAN_MLOCK_POOL_SIZE", "0", 1);
         }

      std::string op(BN_op operation,
                     const std::vector<uint8_t>& a8,
                     const std::vector<uint8_t>& b8,
                     const std::vector<uint8_t>& c8,
                     const std::vector<uint8_t>& d8) override
         {
         using namespace Botan;

         BigInt a(a8.data(), a8.size());
         BigInt b(b8.data(), b8.size());
         BigInt c(c8.data(), c8.size());
         std::stringstream out;

         switch(operation)
            {
            case BN_op::Add:
               out << (a + b);
               break;

            case BN_op::Sub:
               out << (a - b);
               break;

            case BN_op::Mul:
               out << (a * b);
               break;

            case BN_op::Div:
               if(b == 0)
                  out << "0";
               else
                  out << (a / b);
               break;

            case BN_op::Rem:
               if(b == 0)
                  out << "0";
               else
                  out << (a % b);
               break;

            case BN_op::ModExp:
               out << power_mod(a, b, c);
               break;
            }

         return out.str();
         }
   };

}
