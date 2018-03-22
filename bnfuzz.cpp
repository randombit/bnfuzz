
#include "bnfuzz.h"
#include "bnfuzz_openssl.h"
#include "bnfuzz_botan.h"
#include <iostream>

std::vector<std::shared_ptr<BN_Fuzz::BN_Lib>> g_libs;

extern "C" void LLVMFuzzerInitialize()
   {
   using namespace BN_Fuzz;

   g_libs.push_back(std::make_shared<Botan_BN_Lib>());
   g_libs.push_back(std::make_shared<OpenSSL_BN_Lib>());

   if(g_libs.size() < 2)
      abort();
   }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t v[], size_t len)
   {
   if(g_libs.size() < 2)
      abort();
   if(len < 10)
      return 0;

   // cache these
   uint8_t op8 = v[0];

   uint8_t a_len = v[1];
   uint8_t b_len = v[2];
   uint8_t c_len = v[3];
   uint8_t d_len = v[4];

   uint8_t a_off = v[5];
   uint8_t b_off = v[6];
   uint8_t c_off = v[7];
   uint8_t d_off = v[8];

   if(a_len + a_off > len)
      return 0;
   if(b_len + b_off > len)
      return 0;
   if(c_len + c_off > len)
      return 0;
   if(d_len + d_off > len)
      return 0;

   std::vector<uint8_t> a(v + a_off, v + a_off + a_len);
   std::vector<uint8_t> b(v + b_off, v + b_off + b_len);
   std::vector<uint8_t> c(v + c_off, v + c_off + c_len);
   std::vector<uint8_t> d(v + d_off, v + d_off + d_len);
   std::vector<std::string> outputs(g_libs.size());

   using namespace BN_Fuzz;

   BN_op op = static_cast<BN_op>(op8 % (static_cast<int>(BN_op::Last) + 1));

   for(size_t i = 0; i != g_libs.size(); ++i)
      {
      outputs[i] = g_libs[i]->op(op, a, b, c, d);
      }
   //std::cout << outputs[0] << "\n";

   for(size_t i = 1; i != outputs.size(); ++i)
      {
      if(outputs[i] != outputs[0])
         {
         std::cout << "Discrepency: " << outputs[i] << " != " << outputs[0] << "\n";;
         abort();
         }
      //std::cout << outputs[i] << "\n";
      }

   return 0;
   }
