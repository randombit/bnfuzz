
#include "bnfuzz.h"
#include <stdio.h>

std::vector<std::shared_ptr<BN_Fuzz::BN_Lib>> g_libs;

std::vector<std::string> split(const std::string& str)
   {
   std::vector<std::string> elems;
   if(str.empty()) return elems;

   std::string substr;
   for(auto i = str.begin(); i != str.end(); ++i)
      {
      if(*i == ',')
         {
         if(!substr.empty())
            elems.push_back(substr);
         substr.clear();
         }
      else
         substr += *i;
      }

   elems.push_back(substr);

   return elems;
   }

extern "C" void LLVMFuzzerInitialize()
   {
   using namespace BN_Fuzz;

   const char* impls = getenv("BNFUZZ_LIBS");

   std::vector<std::string> enabled;

   if(impls == nullptr)
      {
      enabled = all_bn_libs();
      }
   else
      {
      enabled = split(impls);
      }

   for(auto lib : enabled)
      {
      g_libs.push_back(load_bn_lib(lib));
      }

   if(g_libs.size() < 2)
      {
      printf("Not enough libraries enabled to test\n");
      abort();
      }
   }

void dump_vector(const char* name, const std::vector<uint8_t>& vec, bool neg)
   {
   printf("%s = %s0x", name, neg ? "-" : "");

   if(vec.empty())
      {
      printf("00");
      }
   else
      {
      for(size_t i = 0; i != vec.size(); ++i)
         printf("%02X", vec[i]);
      }
   printf("\n");
   }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t v[], size_t len)
   {
   if(g_libs.size() < 2)
      abort();
   if(len < 10)
      return 0;

   const uint8_t op8 = v[0];
   const uint8_t a_len = v[1];
   const uint8_t b_len = v[2];
   const uint8_t c_len = v[3];
   const uint8_t a_off = v[4];
   const uint8_t b_off = v[5];
   const uint8_t c_off = v[6];
   //const uint8_t signs = v[7];
   const uint8_t variant = v[8];

   if(a_len + a_off > len)
      return 0;
   if(b_len + b_off > len)
      return 0;
   if(c_len + c_off > len)
      return 0;

#if 0
   const bool a_neg = signs & 1;
   const bool b_neg = signs & 2;
   const bool c_neg = signs & 4;
#else
   const bool a_neg = false;
   const bool b_neg = false;
   const bool c_neg = false;
#endif

   std::vector<uint8_t> a(v + a_off, v + a_off + a_len);
   std::vector<uint8_t> b(v + b_off, v + b_off + b_len);
   std::vector<uint8_t> c(v + c_off, v + c_off + c_len);
   std::vector<std::string> outputs(g_libs.size());

   using namespace BN_Fuzz;

   BN_op op = static_cast<BN_op>(op8 % (static_cast<int>(BN_op::Last) + 1));

   for(size_t i = 0; i != g_libs.size(); ++i)
      {
      try
         {
         outputs[i] = g_libs[i]->op(op, a, a_neg, b, b_neg, c, c_neg, variant);
         }
      catch(std::exception& e)
         {
         outputs[i] = "Exception " + std::string(e.what());
         }
      }
   //std::cout << outputs[0] << "\n";

   bool all_same = true;
   for(size_t i = 1; i != outputs.size(); ++i)
      {
      if(outputs[i] != outputs[0])
         {
         all_same = false;
         }
      }

   if(all_same == false)
      {
      printf("Discrepency in %s\n", to_string(op).c_str());

      dump_vector("a", a, a_neg);
      if(operands(op) >= 2)
         dump_vector("b", b, b_neg);
      if(operands(op) >= 3)
         dump_vector("c", c, c_neg);

      for(size_t i = 0; i != outputs.size(); ++i)
         printf("Lib %s output 0x%s\n", g_libs[i]->name().c_str(), outputs[i].c_str());
      fflush(stdout);

      abort();
      }

   return 0;
   }
