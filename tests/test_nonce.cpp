#include "qv/core/nonce.h"
#include <cassert>
#include <iostream>

int main() {
  qv::core::NonceGenerator ng(7, 0);
  auto a = ng.Next();
  auto b = ng.Next();
  assert(!(a == b) && "nonces must be unique");
  std::cout << "nonce test ok\n";
  return 0;
}
