<h1 align="center">
    Shelltropy
</h1>

<h2 align="center">
    The more predictable you are, the less you get detected
</h2>

**A technique of hiding malicious shellcode based on low-entropy via Shannon encoding.**

Entropy is the measure of the randomness in a set of data (here: shellcode). The higher the entropy, the more random the data is. Shannon Entropy is an algorithm that will produce a result between 0 and 8, where 8 means there is no pattern in the data, thereby it's very random and 0 means data follows a pattern.

Check out my article for more information of my research: https://kleiton0x00.github.io/posts/The-more-predictable-you-are-the-less-you-are-able-to-get-detected/

## How the PoC works

![poc_logic_flow](https://github.com/kleiton0x00/Shelltropy/blob/main/Images/encoding_logic_flow.jpg?raw=true)

The concept is to divide the array into chunks and insert a low-entropy pattern of bytes between each chunk. When the sample is run, we must reconstruct the original payload in memory, bypassing the static detection of the high entropy code at this stage.
It's also worth noting that the low-entropy code to be inserted can follow a variety of patterns, and the amount of insertions can vary, thus it can be used to circumvent static signature detection. The second step is to combine the high entropy chunks of bytes with the low entropy chunks. 
Because, after all, we need to restore the obfuscated code to what it was initially in order to proceed to the de-obfuscation step, the third task will restore the original array of bytes by deleting the low entropy patterns. 

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
