*********************************Instructions**********************************

The following files SHALL NOT be modified:

drng.c                              Source file of Deterministic Random Number 
                                    Generator

drng.h                              Header file of Deterministic Random Number 
                                    Generator

KAT_CryptHash.c                     Source file for generating test vector files
                                    of cryptographic hash algorithm

The following files NEED to be modified:

CryptHash_AlgorithmInstance.c       Source file of cryptographic hash algorithm 
                                    instance (demo)

CryptHash_AlgorithmInstance.h       Header file of cryptographic hash algorithm 
                                    instance (programming interface)

**************************************Use**************************************

1.  Modify the provided file "CryptHash_AlgorithmInstance.h":
    a.  Set the macro "OUTPUT_BLANK_TEST_VECTORS" as 0 to set generating mode.
    b.  Set the macro "ALGORITHM_INSTANCE" as the submitted algorithm instance 
        name.
    c.  Set the macro "DIGEST_BIT_LENGTH" as the message digest length of your 
        algorithm instance.

2.  Modify the provided file "CryptHash_AlgorithmInstance.c" to implement the 
    functions of the submitted algorithm.

3.  Compile and execute to generate test vector files.

*************************************Notes*************************************

1.  The submitted algorithm shall use the provided programming interface in 
    "CryptHash_AlgorithmInstance.h".
2.  This program assumes a little-endian byte order for multi-byte values. 
    Behavior is undefined on systems with a different byte order.
3.  This program requires compilation with compilers supporting the 
    ISO/IEC 9899:1999 (C99) standard or later.
4.  This program requires at least 1GB of memory to store messages of a length
    of 2^33 bits. Please ensure that the system has sufficient available memory.
5.  For non-byte-aligned data operations (e.g., DRNG outputs and CryptHash 
    inputs), the most significant bit (MSB) first convention applies to 
    partial-byte read/write operations.
    Example: the 11-bit non-byte-aligned output "10101100001"(bin) is stored 
    in memory as "AC 20"(hex):
                     MSB     ------->     LSB         
        Address+0  :  1  0  1  0  1  1  0  0  (0xAC)
        Address+1  :  0  0  1  0  0  0  0  0  (0x20, with only 3 valid bits)

*************************************Build*************************************

1.  Build the KAT generator by running:
        make
2.  Run the generated KAT program (for example, "./KAT" on Unix-like systems
    or "KAT.exe" on Windows).
3.  The KAT program writes its test vector files to the output/ sub-directory.