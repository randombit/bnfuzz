USE_OPENSSL=1
USE_BOTAN=0
USE_CRYPTOPP=1

CXX = clang++
CXXFLAGS = -fsanitize-coverage=trace-pc-guard -std=c++11 -g -O2 -Wall -Wextra

SOURCE=bnfuzz.cpp bnfuzz_impl.cpp
IMPLS=$(wildcard bnfuzz_*.h)

LIBS=
INCLUDES=

ifeq ($(USE_OPENSSL),1)
   LIBS += -lcrypto
   CXXFLAGS += -DBNFUZZ_USE_OPENSSL
endif

ifeq ($(USE_CRYPTOPP),1)
   LIBS += -lcryptopp
   CXXFLAGS += -DBNFUZZ_USE_CRYPTOPP
endif

ifeq ($(USE_BOTAN),1)
   LIBS += -lbotan-2
   CXXFLAGS += -DBNFUZZ_USE_BOTAN
endif

bnfuzz: $(SOURCE) $(IMPLS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(SOURCE) -lFuzzer $(LIBS) -o bnfuzz

clean:
	rm -f bnfuzz
