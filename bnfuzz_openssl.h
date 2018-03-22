#include "bnfuzz.h"
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <memory>
#include <functional>

namespace BN_Fuzz {

class OpenSSL_BN_Lib : public BN_Lib
   {
   public:

      OpenSSL_BN_Lib()
         {
         m_ctx = BN_CTX_new();
         }

      ~OpenSSL_BN_Lib()
         {
         BN_CTX_free(m_ctx);
         }

      typedef std::unique_ptr<BIGNUM, std::function<void (BIGNUM*)>> BN_ptr;

      std::string string_of(const BN_ptr& a)
         {
         char* dec = BN_bn2dec(a.get());
         std::string s(dec);
         CRYPTO_free(dec, __FILE__, __LINE__);
         return s;
         }

      std::string op(BN_op operation,
                     const std::vector<uint8_t>& a8,
                     const std::vector<uint8_t>& b8,
                     const std::vector<uint8_t>& c8,
                     const std::vector<uint8_t>& d8) override
         {
         BN_ptr a(BN_bin2bn(a8.data(), a8.size(), NULL), BN_free);
         BN_ptr b(BN_bin2bn(b8.data(), b8.size(), NULL), BN_free);
         BN_ptr c(BN_bin2bn(c8.data(), c8.size(), NULL), BN_free);
         BN_ptr r(BN_new(), BN_free);

         switch(operation)
            {
            case BN_op::Add:
               BN_add(a.get(), a.get(), b.get());
               return string_of(a);

            case BN_op::Sub:
               BN_sub(a.get(), a.get(), b.get());
               return string_of(a);

            case BN_op::Mul:
               BN_mul(a.get(), a.get(), b.get(), m_ctx);
               return string_of(a);

            case BN_op::Div:
               BN_div(r.get(), nullptr, a.get(), b.get(), m_ctx);
               return string_of(r);

            case BN_op::Rem:
               BN_div(nullptr, r.get(), a.get(), b.get(), m_ctx);
               return string_of(r);

            case BN_op::ModExp:
               BN_mod_exp(r.get(), a.get(), b.get(), c.get(), m_ctx);
               return string_of(r);
            }

         return "";
         }

   private:
      BN_CTX* m_ctx;
   };

}
