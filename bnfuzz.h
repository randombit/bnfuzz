
#ifndef BNFUZZ_H_
#define BNFUZZ_H_

#include <vector>
#include <string>

namespace BN_Fuzz {

enum class BN_op {
   Add,
   Sub,
   Mul,
   Div,
   Rem,
   ModExp,
   /*
   ModAdd,
   ModMul,
   Exp,
   Lshift,
   Rshift,
   */

   Last = ModExp,
};

class BN_Lib
   {
   public:
      virtual ~BN_Lib() = default;

      virtual std::string op(BN_op operation,
                             const std::vector<uint8_t>& a,
                             const std::vector<uint8_t>& b,
                             const std::vector<uint8_t>& c,
                             const std::vector<uint8_t>& d) = 0;
   };

}

#endif
