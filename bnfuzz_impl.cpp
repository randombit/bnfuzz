#include "bnfuzz.h"

#if defined(BNFUZZ_USE_OPENSSL)
  #include "bnfuzz_openssl.h"
#endif

#if defined(BNFUZZ_USE_BOTAN)
  #include "bnfuzz_botan.h"
#endif

#if defined(BNFUZZ_USE_CRYPTOPP)
  #include "bnfuzz_cryptopp.h"
#endif

namespace BN_Fuzz {

std::shared_ptr<BN_Lib> load_bn_lib(const std::string& name)
   {
#if defined(BNFUZZ_USE_BOTAN)
   if(name == "botan")
      return std::make_shared<Botan_BN_Lib>();
#endif

#if defined(BNFUZZ_USE_CRYPTOPP)
   if(name == "cryptopp")
      return std::make_shared<CryptoPP_BN_Lib>();
#endif

#if defined(BNFUZZ_USE_OPENSSL)
   if(name == "openssl")
      return std::make_shared<OpenSSL_BN_Lib>();
#endif

   throw std::runtime_error("Unknown bn library '" + name + "'");
   }

std::vector<std::string> all_bn_libs()
   {
   std::vector<std::string> impl;

#if defined(BNFUZZ_USE_OPENSSL)
   impl.push_back("openssl");
#endif

#if defined(BNFUZZ_USE_BOTAN)
   impl.push_back("botan");
#endif

#if defined(BNFUZZ_USE_CRYPTOPP)
   impl.push_back("cryptopp");
#endif

   return impl;
   }

size_t operands(BN_op op)
   {
   switch(op)
      {
      case BN_op::Add:
      case BN_op::Sub:
      case BN_op::Mul:
      case BN_op::Div:
      case BN_op::Rem:
      case BN_op::ModSqr:
      case BN_op::ModInv:
         return 2;

      case BN_op::ModExp:
      case BN_op::ModMul:
         return 3;

      case BN_op::P256_mul_x:
      case BN_op::P384_mul_x:
      case BN_op::P521_mul_x:
      case BN_op::BP256_mul_x:
         return 1;
      }
   return 0;
   }

std::string to_string(BN_op op)
   {
   switch(op)
      {
      case BN_op::Add:
         return "add";
      case BN_op::Sub:
         return "sub";
      case BN_op::Mul:
         return "mul";
      case BN_op::Div:
         return "div";
      case BN_op::Rem:
         return "rem";
      case BN_op::ModExp:
         return "modexp";
      case BN_op::ModSqr:
         return "modsqr";
      case BN_op::ModMul:
         return "modmul";
      case BN_op::ModInv:
         return "modinv";
      case BN_op::P256_mul_x:
         return "p256_mul_x";
      case BN_op::P384_mul_x:
         return "p384_mul_x";
      case BN_op::P521_mul_x:
         return "p521_mul_x";
      case BN_op::BP256_mul_x:
         return "bp256_mul_x";
      }

   return "";
   }

}

