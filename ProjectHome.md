# Tools #
This pack contains the following tools:

  1. **FindShared** - find PE files with shared sections
  1. **StressShared** - naive fuzzer for shared sections

Detailed description follows.

## FindShared ##
FindShared is a tool that traverses the directory tree looking for PE files with shared+writable sections. By default it looks only at files with .exe, .dll, .scr, .cpl and .ocx extensions, but it can also be set to scan all files (this is more time consuming though).

## StressShared ##
This is a simple naive fuzzer that loads a given DLL module and rapidly overwrites the shared section data with random bytes.

It overwrites only the first N bytes of the section, where N is equal to the IMAGE\_SECTION\_HEADER.VirtualSize field value from the given section's header since - as observed, compilers tend to set it to a value indicating the actual size taken by the variables in the section and not to a page-aligned value.