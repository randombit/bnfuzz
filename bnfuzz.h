
#ifndef BNFUZZ_H_
#define BNFUZZ_H_

#include <vector>
#include <string>
#include <memory>

namespace BN_Fuzz {

enum class BN_op {
   Add,
   Sub,
   Mul,
   Div,
   Rem,
   ModSqr,
   ModMul,
   ModInv,
   ModExp,

   P256_mul_x,
   P384_mul_x,
   P521_mul_x,
   BP256_mul_x,

   Last = ModExp,
};

std::string to_string(BN_op op);

size_t operands(BN_op op);

class BN_Lib
   {
   public:
      virtual ~BN_Lib() = default;

      virtual std::string name() const = 0;

      virtual std::string op(BN_op operation,
                             const std::vector<uint8_t>& a, bool a_neg,
                             const std::vector<uint8_t>& b, bool b_neg,
                             const std::vector<uint8_t>& c, bool c_neg,
                             uint8_t variant) = 0;
   };

std::shared_ptr<BN_Lib> load_bn_lib(const std::string& name);

std::vector<std::string> all_bn_libs();

}

#endif
