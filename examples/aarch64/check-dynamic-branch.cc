// Copyright 2020, VIXL authors
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//   * Redistributions of source code must retain the above copyright notice,
//     this list of conditions and the following disclaimer.
//   * Redistributions in binary form must reproduce the above copyright notice,
//     this list of conditions and the following disclaimer in the documentation
//     and/or other materials provided with the distribution.
//   * Neither the name of ARM Limited nor the names of its contributors may be
//     used to endorse or promote products derived from this software without
//     specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <cstdint>
#include <fstream>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/stat.h>

#include "code-buffer-vixl.h"

#include "aarch64/decoder-aarch64.h"
#include "aarch64/disasm-aarch64.h"
#include "aarch64/instructions-aarch64.h"

// This example is interactive, and isn't tested systematically.
#ifndef TEST_EXAMPLES

using namespace vixl;
using namespace vixl::aarch64;

class FindDangerousBranchDisassembler : public Disassembler {
 public:
  bool dangerous = false;

  void DisassembleBuffer(const Instruction* start,
                         const Instruction* end,
                         const ISAMap* map) {
    Decoder decoder;
    decoder.AppendVisitor(this);
    decoder.Decode(start, end, map);
  }


  void VisitUnconditionalBranchToRegister(
      const Instruction* instruction) override {
    switch (instruction->Mask(UnconditionalBranchToRegisterMask)) {
      case BR:
        dangerous = true;
        break;
      case BLR:
        dangerous = true;
        break;
      case RET: {
        // ignore returns for now.
        break;
      }
      case BRAAZ:
        dangerous = true;
        break;
      case BRABZ:
        dangerous = true;
        break;
      case BLRAAZ:
        dangerous = true;
        break;
      case BLRABZ:
        dangerous = true;
        break;
      case RETAA:
        // ignore return for now
        break;
      case RETAB:
        // ignore return for now
        break;
      case BRAA:
        dangerous = true;
        break;
      case BRAB:
        dangerous = true;
        break;
      case BLRAA:
        dangerous = true;
        break;
      case BLRAB:
        dangerous = true;
        break;
    }
  }
};

Instr ParseInstr(char const* arg) {
  // TODO: Error handling for out-of-range inputs.
  return (Instr)strtoul(arg, NULL, 16);
}

int64_t ParseInt64(char const* arg) {
  // TODO: Error handling for out-of-range inputs.
  return (int64_t)strtoll(arg, NULL, 0);
}

int main(int argc, char* argv[]) {
  for (int i = 1; i < argc; i++) {
    char const* arg = argv[i];
    if ((strcmp(arg, "--help") == 0) || (strcmp(arg, "-h") == 0)) {
      return 0;
    }
  }

  int64_t start_address = 0;
  ISA isa = ISA::A64;
  std::string fileName;

  bool expect_start_at = false;
  for (int i = 1; i < argc; i++) {
    char* arg = argv[i];
    if (strcmp(arg, "--start-at") == 0) {
      char* arg = argv[++i];
      start_address = ParseInt64(arg);
    } else if (strcmp(arg, "--a64") == 0) {
      isa = ISA::A64;
    } else if (strcmp(arg, "--c64") == 0) {
      isa = ISA::C64;
    } else {
      // Get a file by doing a
      // ` ~/cheri/output/morello-sdk/bin/llvm-objcopy -O binary
      // --only-section=.text`
      fileName = std::string(arg);
    }
  }

  std::ifstream fileStream;
  struct stat st;

  stat(fileName.c_str(), &st);
  CodeBuffer buffer(st.st_size + 4);

  fileStream.open(fileName, std::ifstream::in | std::ifstream::binary);

  uint32_t instruction;
  do {
    fileStream.read((char*)&instruction, sizeof(uint32_t));
    buffer.Emit((Instr)instruction);
  } while (fileStream.tellg() != st.st_size);

  buffer.SetClean();

  if (expect_start_at) {
    printf("No address given. Use: --start-at <address>\n");
    return 1;
  }

  if (buffer.GetSizeInBytes() == 0) {
    printf("Nothing to disassemble.\n");
    return 0;
  }

  // Disassemble the buffer.
  const Instruction* start = buffer.GetStartAddress<Instruction*>();
  const Instruction* end = buffer.GetEndAddress<Instruction*>();
  vixl::aarch64::PrintDisassembler disasm(stdout);
  FindDangerousBranchDisassembler dangerousBranch;

  disasm.PrintSignedAddresses(true);
  disasm.MapCodeAddress(start_address, start);
  ISAMap map(isa);
  disasm.DisassembleBuffer(start, end, &map);
  dangerousBranch.DisassembleBuffer(start, end, &map);
  std::cout << "Dangerous found:" << dangerousBranch.dangerous << std::endl;

  return 0;
}

#endif  // TEST_EXAMPLES
