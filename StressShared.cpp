// StressShared - DLL shared section naive fuzzer.
// http://code.google.com/p/dll-shared-sections
// http://gynvael.coldwind.pl/
//
// Version: 2012-05-19
//
// LICENSE
//   Copyright 2012 Gynvael Coldwind
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <stdint.h>
#include <time.h>
#include <string>
#include <vector>

// ------------------------------------------------------------------
// Functions & globals.
// ------------------------------------------------------------------

#define VERSION "2012-05-19"

static void Usage();
static void Stress(HMODULE h);
static void FindSharedSections(std::vector<IMAGE_SECTION_HEADER*> *v,
                               HMODULE h);
static void StressSection(IMAGE_SECTION_HEADER *sec, HMODULE h);

static bool Option_Hard = false;

// ------------------------------------------------------------------
// main
// ------------------------------------------------------------------
int main(int argc, char **argv) {

  // Banner.
  puts("StressShared (v. " VERSION ") by gynvael.coldwind//vx");
  
  // Args?
  if((argc != 2 && argc != 3) || 
     strcmp(argv[1], "-h") == 0 ||
     strcmp(argv[1], "--help") == 0 ||
     strcmp(argv[1], "/?") == 0) {
    Usage();
    return 1;
  }

  if(argc == 3) {
    if(strcmp(argv[2], "--hard") == 0) {
      Option_Hard = true;
    } else {
      Usage();
      return 2;
    }
  }

  // Load module.
  HMODULE h = LoadLibrary(argv[1]);
  if(h == NULL) {
    fprintf(stderr, "error: failed to load DLL\n");
    return 2;
  }

  // Let's start the stress.
  Stress(h);

  // The execution should normally never reach this.
  FreeLibrary(h);

  // Done.
  return 0;
}


// ------------------------------------------------------------------
// Usage: Show how to use this tool.
// ------------------------------------------------------------------
void Usage() {
  puts("usage: StressShared <path_to_dll> [--hard]\n"
       "e.g. : StressShared \"C:\\Program Files\\Sth\\asdf.dll\"\n"
       "\n"
       "StressShared loads a DLL with a shared section(s) and rapidly\n"
       "changes it's content to random values.\n"
       "\n"
       "Options:\n"
       "  --hard   Hammer it hard (don't sleep).");
}

// ------------------------------------------------------------------
// Stress: Find sections and stress them.
// ------------------------------------------------------------------
void Stress(HMODULE h) {

  // Find shared sections.
  std::vector<IMAGE_SECTION_HEADER*> shared_sections;
  FindSharedSections(&shared_sections, h);

  if(shared_sections.size() == 0) {
    fprintf(stderr, "error: no shared sections found\n");
    return;
  }

  // Let's stress them.
  printf("Starting the stress/fuzz test (press CTRL+C to break).\n");
  size_t count = shared_sections.size();
  for(;;) {

    for(size_t i = 0; i < count; i++)
      StressSection(shared_sections[i], h);

    // Let the OS rest.
    if(!Option_Hard) Sleep(1);
  }

  // Should never reach this point.
}

// ------------------------------------------------------------------
// StressSection: Overwrites the section with random data.
// ------------------------------------------------------------------
void StressSection(IMAGE_SECTION_HEADER *sec, HMODULE h) {

  // Calc the VA & size.
  BYTE *va = (BYTE*)h + sec->VirtualAddress;
  DWORD size = sec->Misc.VirtualSize;

  for(DWORD i = 0; i < size; i++) {
    va[i] = (BYTE)rand();
  }

  // Done.
}


// ------------------------------------------------------------------
// FindSharedSections: Overwrites the section with random data.
// ------------------------------------------------------------------
void FindSharedSections(std::vector<IMAGE_SECTION_HEADER*> *v, HMODULE h) {
  // Assume: v is empty.

  // Pointers.
  BYTE *data = (BYTE*)h;
  IMAGE_DOS_HEADER *pdos_header = (IMAGE_DOS_HEADER*)data;
  IMAGE_NT_HEADERS32 *pnt_header = (IMAGE_NT_HEADERS32*)(
      data + pdos_header->e_lfanew);
  IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(pnt_header);

  // Scan.
  printf("Found shared sections:\n");
  for(WORD i = 0; i < pnt_header->FileHeader.NumberOfSections; i++) {

    // Check match (must be both writable and shared).
    if(!((sections[i].Characteristics & IMAGE_SCN_MEM_WRITE) &&
         (sections[i].Characteristics & IMAGE_SCN_MEM_SHARED)))
      continue;

    // Print info about this section.
    char section_name_asciiz[12] = {0};
    memcpy(section_name_asciiz, sections[i].Name, sizeof(sections[i].Name));
    printf("       [%-8s] rva=%.8x vsz=%.8x ch=%.8x\n",
        section_name_asciiz, (unsigned int)sections[i].VirtualAddress, 
        (unsigned int)sections[i].Misc.VirtualSize,
        (unsigned int) sections[i].Characteristics);

    // Add to vector.
    v->push_back(&sections[i]);
  }

  // Done.  
}

