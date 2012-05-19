// FindShared - DLL shared sections finder.
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

// ------------------------------------------------------------------
// Functions & globals.
// ------------------------------------------------------------------

#define VERSION "2012-05-19"

static void Usage();
static int Scan(std::string path);
static bool CheckPEFile(const char *path);
static bool CheckPEFile_Worker(const char *path, unsigned char *data);
static inline char ToLower(char c);

static bool Option_CheckAllFiles; // Check all files, not only EXE/etc.
static unsigned int Global_FileCountTotal;
static unsigned int Global_FileCountPE;

// ------------------------------------------------------------------
// main
// ------------------------------------------------------------------
int main(int argc, char **argv) {

  // Banner.
  puts("FindShared (v. " VERSION ") by gynvael.coldwind//vx");

  // Args?
  if((argc != 2 && argc != 3) || 
     strcmp(argv[1], "-h") == 0 ||
     strcmp(argv[1], "--help") == 0 ||
     strcmp(argv[1], "/?") == 0) {
    Usage();
    return 1;
  }

  if(argc == 3) {
    if(strcmp(argv[2], "--all") == 0) {
      Option_CheckAllFiles = true;
    } else {
      // Unknown option.
      Usage();
      return 2;
    }
  }

  // Scan.
  time_t t_start = time(NULL);
  int ret = Scan(argv[1]);
  time_t t_end   = time(NULL);

  printf("Done (in %u secs. scanned %u files; %u were valid PE files).\n",
         (unsigned int)(t_end - t_start), Global_FileCountTotal, 
         Global_FileCountPE);

  // Done.
  return ret;
}


// ------------------------------------------------------------------
// Usage: Show how to use this tool.
// ------------------------------------------------------------------
void Usage() {
  puts("usage: FindShared <top_level_path> [options]\n"
       "e.g. : FindShared C: \n"
       "     : FindShared \"C:\\Program Files\\\" --all\n"
       "\n"
       "FindShared will recursively scan the given directory tree looking\n"
       "for files with EXE, DLL, SCR, CPL and OCX extensions with a shared\n"
       "read/write section (both PE and PE32+).\n"
       "\n"
       "Options:\n"
       "  --all    Scan all files, not only common PE extensions.\n"
       "           Warning: this will slow down the scan.");
}

// ------------------------------------------------------------------
// Scan: Scans recursivelly for PE files with shared sections.
// ------------------------------------------------------------------
int Scan(std::string path) {

  // Find all entries in this directory.
  WIN32_FIND_DATA find_data;

  std::string spath = path + "\\*.*";

  HANDLE search = FindFirstFile(spath.c_str(), &find_data);
  if(search == INVALID_HANDLE_VALUE)
    return 1;

  do {

    // Skip links and unavailable files.
    if((find_data.dwFileAttributes & FILE_ATTRIBUTE_OFFLINE) ||
       (find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
      continue;

    // Directory?
    if((find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {

      // Skip both . and .. special directories.
      if(strcmp(find_data.cFileName, ".") == 0 ||
         strcmp(find_data.cFileName, "..") == 0)
        continue;

      // Recursively enter Scan.
      Scan(path + "\\" + find_data.cFileName);
      continue;
    }

    // Normal file.
    bool perform_scan = false;

    if(Option_CheckAllFiles) {
      perform_scan = true;
    } else {
      // Need to check extension.
      int len = strlen(find_data.cFileName);
      if(len >= 4) {
        char last_four_chars[8] = {
          ToLower(find_data.cFileName[len - 4]),
          ToLower(find_data.cFileName[len - 3]),
          ToLower(find_data.cFileName[len - 2]),
          ToLower(find_data.cFileName[len - 1])
        };

        if(strcmp(last_four_chars, ".exe") == 0 ||
           strcmp(last_four_chars, ".dll") == 0 ||
           strcmp(last_four_chars, ".cpl") == 0 ||
           strcmp(last_four_chars, ".scr") == 0 ||
           strcmp(last_four_chars, ".ocx") == 0) {
          perform_scan = true;
        };
      }
    }

    // Scan?
    if(perform_scan) {
      std::string fpath = path + "\\" + find_data.cFileName;
      CheckPEFile(fpath.c_str());
    }

  } while(FindNextFile(search, &find_data));

  // Done.
  FindClose(search);
  return 0;
}

// ------------------------------------------------------------------
// CheckPEFile: Checks if given PE file has shared r/w sections.
// ------------------------------------------------------------------
bool CheckPEFile(const char *path) {
  IMAGE_DOS_HEADER dos_header;
  IMAGE_NT_HEADERS nt_headers; // Use this only up to OptionalHeader.Magic
                               // since later it gets PE/PE32+ depentent.

  // Open file.
  FILE *f = fopen(path, "rb");
  if(!f) {
    // Report this.
    fprintf(stderr, "error: could not open file \"%s\"\n", path);
    return false;
  }

  // Read the DOS header.
  if(!fread(&dos_header, sizeof(dos_header), 1, f)) {
    fclose(f);
    return false;
  }

  // Increment counter.
  ++Global_FileCountTotal;

  // Check magic.
  if(dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
    fclose(f);
    return false;
  }

  // Seek.
  if(fseek(f, dos_header.e_lfanew, SEEK_SET) == -1) {
    fclose(f);
    return false;
  }

  // Load part of headers (enough to decide on file format).
  memset(&nt_headers, 0, sizeof(nt_headers));
  if(!fread(&nt_headers, sizeof(DWORD) +             // PE Sig.
                         sizeof(IMAGE_FILE_HEADER) + // File header
                         sizeof(WORD), 1, f)) {      // Opt.Magic
    fclose(f);
    return false;
  }

  // Check signatures and decide on format.
  if(nt_headers.Signature != IMAGE_NT_SIGNATURE ||
     (nt_headers.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
      nt_headers.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)) {
    fclose(f);
    return false;
  }

  // Since the File Header is already loaded, check if there are
  // any sections.
  if(nt_headers.FileHeader.NumberOfSections == 0) {
    fclose(f);
    return false;
  }

  // Read the whole file.
  // I assume that these files are not changed on the fly, but it's
  // up to the user to make sure of that.
  unsigned char *data = NULL;
  size_t size = 0;

  fseek(f, 0, SEEK_END);
  size = ftell(f);
  fseek(f, 0, SEEK_SET);

  // Check sanity of file size before load.
  uint64_t min_size = dos_header.e_lfanew;
  min_size += sizeof(DWORD);             // PE Signature.
  min_size += sizeof(IMAGE_FILE_HEADER); // File header.
  min_size += nt_headers.FileHeader.SizeOfOptionalHeader; // Optional header.
  min_size += ((uint64_t)sizeof(IMAGE_SECTION_HEADER)) *
              nt_headers.FileHeader.NumberOfSections; // Section headers.

  if(size < min_size) {
    fclose(f);
    return false;
  }  

  // Note: There is a time-of-check vs time-of-use race cond. bug here,
  // but I don't care about it. It's just a tool that is supposed to be
  // run in a static environment.
  data = (unsigned char*)malloc(size);
  if(!data) {
    // Report this.
    fprintf(stderr, "error: could not allocate memory to check \"%s\"\n",
            path);
    fclose(f);
    return false;
  }

  if(!fread(data, size, 1, f)) {
    // Report this.
    fprintf(stderr, "error: read error on file \"%s\"\n",  path);
    fclose(f);
    free(data);  
    return false;
  }

  // Safe to close now.
  fclose(f);

  // Call proper handler. Signatures are already checked.
  bool bret = CheckPEFile_Worker(path, data);

  // Done.
  free(data);
  return bret;
}

// ------------------------------------------------------------------
// CheckPEFile_Worker: Do the work.
// ------------------------------------------------------------------
bool CheckPEFile_Worker(const char *path, unsigned char *data) {
  // Note: Size checks have been done earlier.

  // Increment counter.
  ++Global_FileCountPE;

  // Pointers.
  IMAGE_DOS_HEADER *pdos_header = (IMAGE_DOS_HEADER*)data;
  IMAGE_NT_HEADERS32 *pnt_header = (IMAGE_NT_HEADERS32*)(
      data + pdos_header->e_lfanew);
  IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(pnt_header);

  // (data + pdos_header->e_lfanew + sizeof(DWORD) +
  //   pnt_header->FileHeader.SizeOfOptionalHeader);

  unsigned int matching_sections_found = 0;

  // Scan.
  for(WORD i = 0; i < pnt_header->FileHeader.NumberOfSections; i++) {

    // Check match (must be both writable and shared).
    if(!((sections[i].Characteristics & IMAGE_SCN_MEM_WRITE) &&
         (sections[i].Characteristics & IMAGE_SCN_MEM_SHARED)))
      continue;

    // If this is a first matching_sections_found, print out exe info.
    if(matching_sections_found == 0) puts(path);

    ++matching_sections_found;
    
    // Print info about this section.
    char section_name_asciiz[12] = {0};
    memcpy(section_name_asciiz, sections[i].Name, sizeof(sections[i].Name));
    printf("       [%-8s] rva=%.8x vsz=%.8x ch=%.8x\n",
        section_name_asciiz, (unsigned int)sections[i].VirtualAddress, 
        (unsigned int)sections[i].Misc.VirtualSize,
        (unsigned int) sections[i].Characteristics);
  }

  // Done.
  return (matching_sections_found > 0);
}


// ------------------------------------------------------------------
// ToLower: Returns char lowercase.
// ------------------------------------------------------------------
inline char ToLower(char c) {
  return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
}

