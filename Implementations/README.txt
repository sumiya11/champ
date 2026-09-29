CHAMP Implementations
=====================

CHAMP stands for Cayley HAshing with Matrix Products.

Algorithm Instances
-------------------
  CHAMP-512   512-bit digest
  CHAMP-1024  1024-bit digest

Directory Layout
----------------
  Reference_Implementation/
    CHAMP-512/    Portable ISO C99 reference
    CHAMP-1024/   Portable ISO C99 reference

  Optimized_Implementation/
    CHAMP-512/    Optimized implementation
    CHAMP-1024/   Optimized implementation

  Additional_Implementation/  Currently empty

  README                      Top-level overview of implementation contents

Files per Instance
------------------
  CryptHash_AlgorithmInstance.h   Hash interface
  CryptHash_AlgorithmInstance.c   Hash implementation
  KAT_CryptHash.c                 Unmodified
  drng.c / drng.h                 Unmodified
  Makefile                        Automated build
  README.txt                      Per-instance notes and build instructions

Per-Instance Build Notes
------------------------
For instance-specific notes and run instructions, see that folder's README.txt
and Makefile.

Each instance build produces a KAT program that writes four test files to the
output/ sub-directory:
  KAT_2_12_CHAMP-{512,1024}.txt
  KAT_2_23_CHAMP-{512,1024}.txt
  KAT_2_33_CHAMP-{512,1024}.txt
  KAT_Loop_CHAMP-{512,1024}.txt

The files in Test_Vectors/ were produced by running this process on a standard
x86-64 Linux machine with GCC 13.
