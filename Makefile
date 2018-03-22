
CXX = clang++
CXXFLAGS = -fsanitize-coverage=trace-pc-guard -std=c++11 -g -O2 -Wall -Wextra
#INCLUDES=-I/usr/include/botan-2
INCLUDES=-I/home/jack/work/botan/build/include
LIBS=-L/home/jack/work/botan -lbotan-2 -lcrypto

bnfuzz: bnfuzz.cpp bnfuzz_botan.h bnfuzz_openssl.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) bnfuzz.cpp -lFuzzer $(LIBS) -o bnfuzz

clean:
	rm -f bnfuzz
