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
#include "elfio/elf_types.hpp"
#include "elfio/elfio.hpp"

#include "aarch64/decoder-aarch64.h"
#include "aarch64/disasm-aarch64.h"
#include "aarch64/instructions-aarch64.h"

// This example is interactive, and isn't tested systematically.
#ifndef TEST_EXAMPLES

using namespace vixl;
using namespace vixl::aarch64;

// This actually doesn't work.
class FindDangerousBranchDisassembler : public Disassembler {
 public:
  uint64_t dangerous = 0;

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
        dangerous += 1;
        break;
      case BLR:
        dangerous += 1;
        break;
      case RET: {
        // ignore returns for now.
        break;
      }
      case BRAAZ:
        dangerous += 1;
        break;
      case BRABZ:
        dangerous += 1;
        break;
      case BLRAAZ:
        dangerous += 1;
        break;
      case BLRABZ:
        dangerous += 1;
        break;
      case RETAA:
        // ignore return for now
        break;
      case RETAB:
        // ignore return for now
        break;
      case BRAA:
        dangerous += 1;
        break;
      case BRAB:
        dangerous += 1;
        break;
      case BLRAA:
        dangerous += 1;
        break;
      case BLRAB:
        dangerous += 1;
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

void printFunction(ISA isa, int64_t start_address, Instruction* instructions, uint64_t size) {
  const Instruction* start = instructions;
  const Instruction* end = instructions + size;
  vixl::aarch64::PrintDisassembler disasm(stdout);
  FindDangerousBranchDisassembler dangerousBranch;

  disasm.PrintSignedAddresses(true);
  disasm.MapCodeAddress(start_address, start);
  ISAMap map(isa);
  disasm.DisassembleBuffer(start, end, &map);
  dangerousBranch.DisassembleBuffer(start, end, &map);
  std::cout << "Dangerous found: " << dangerousBranch.dangerous << std::endl;
}

int main(int argc, char* argv[]) {
  for (int i = 1; i < argc; i++) {
    char const* arg = argv[i];
    if ((strcmp(arg, "--help") == 0) || (strcmp(arg, "-h") == 0)) {
      return 0;
    }
  }


  ISA isa = ISA::A64;
  std::string fileName;
  for (int i = 1; i < argc; i++) {
    char* arg = argv[i];
    if (strcmp(arg, "--a64") == 0) {
      isa = ISA::A64;
    } else if (strcmp(arg, "--c64") == 0) {
      isa = ISA::C64;
    } else {
      fileName = std::string(arg);
    }
  }

  ELFIO::elfio reader;
  if (!reader.load(fileName)) {
    std::cout << "Invalid elf file: " << fileName << "\n";
    return -1;
  } else {
    ELFIO::Elf_Half sec_num = reader.sections.size();
    for (int i = 0; i < sec_num; ++i) {
      ELFIO::section* psec = reader.sections[i];
      // std::cout << "  [" << i << "] " << psec->get_name() << "\t"
                // << psec->get_size() << " 0x" << std::hex << psec->get_address() << std::endl;
  
      
      if (psec->get_type() != SHT_SYMTAB) {
        continue;
      }
      

      const ELFIO::symbol_section_accessor symbols(reader, psec);
      for (unsigned int j = 0; j < symbols.get_symbols_num(); ++j) {
        std::string name;
        ELFIO::Elf64_Addr value;
        ELFIO::Elf_Xword size;
        unsigned char bind;
        unsigned char type;
        ELFIO::Elf_Half section_index;
        unsigned char other;

        // Read symbol properties
        symbols
            .get_symbol(j, name, value, size, bind, type, section_index, other);
        if (type == 2 && size > 0) {
          ELFIO::section* symbol_section = reader.sections[section_index];

          uint64_t offset = value - symbol_section->get_address();
          std::cout << j << " " << name << " " << (unsigned int)type << " "
                    << std::hex << offset << std::dec << std::endl;
          printFunction(isa, value, (Instruction*)(symbol_section->get_data() + offset - 1), size/4);
        }
      }
    }
  }
  return 0;
}

#endif  // TEST_EXAMPLES
