bnfuzz - bignum fuzzer
==========================================

Inspired by https://github.com/guidovranken/bignum-fuzzer but with a
rather different implementation.

Takes input from LLVM libFuzzer to create input elements, then runs
the same operation in several big integer math libraries in an attempt
to find discrepencies (aka bugs).

Currently supported operations are addition, subtraction, multiplication,
divide, remainder, modular squaring, modular multiplication, modular inverse,
modular exponentiation, and ECC point multiplication (P-256, P-384, P-521 and
Brainpool-256).
