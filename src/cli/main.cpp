#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include "qv/orchestrator/volume_manager.h"
#include "qv/core/pqc_hybrid_kdf.h"
#include "qv/core/nonce.h"

using namespace std;

int main(int argc, char** argv) {
  if (argc < 2) {
    cout << "QuantumVault (skeleton)\n";
    cout << "Usage:\n";
    cout << "  qv create <container> <password>\n";
    cout << "  qv mount  <container> <password>\n";
    cout << "  qv migrate-nonces <container>\n";
    return 0;
  }
  std::string cmd = argv[1];
  qv::orchestrator::VolumeManager vm;
  if (cmd == "create" && argc >= 4) {
    auto h = vm.Create(argv[2], argv[3]);
    cout << (h ? "Created." : "Failed.") << "\n";
    return h ? 0 : 1;
  } else if (cmd == "mount" && argc >= 4) {
    auto h = vm.Mount(argv[2], argv[3]);
    cout << (h ? "Mounted." : "Failed.") << "\n";
    return h ? 0 : 2;
  } else if (cmd == "migrate-nonces" && argc >= 3) {
    // Demonstrate NonceLog usage in skeleton
    qv::core::NonceGenerator ng(1, 0);
    auto n = ng.Next();
    (void)n;
    cout << "Migrated (demo stub)." << "\n";
    return 0;
  } else {
    cout << "Unknown/invalid command." << "\n";
    return 64;
  }
}
