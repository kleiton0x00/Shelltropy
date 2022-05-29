# Shelltropy
A new (hopefully) technique of hiding malicious shellcode via Shannon encoding.

Entropy is the measure of the randomness in a set of data (here: shellcode). The higher the entropy, the more random the data is. Shannon Entropy is an algorithm that will produce a result between 0 and 8, where 8 means there is no pattern in the data, thereby it's very random and 0 means data follows a pattern.

## The problem with high entropy shellcode
The entropy of malicious code grows as it is packed or obfuscated.
Indeed, studies have shown that entropy may be utilized to successfully distinguish between non-malicious and malicious code based on its entropy.
Malicious samples have an entropy of over 7.2, whereas normal software has an entropy of 4.8 to 7.2.
In 30% of malicious samples, the entropy will be close to 8, whereas only 1% of harmless code will have this value.
More than half of malicious samples will have an entropy of more than 7.2, but only one out of every ten normal programs will have this level of entropy.
To summarize, not all malicious samples (though the most majority will) have high entropy, and not all valid programs will have low entropy (but the majority will). The fact that packing is a genuine strategy for reducing the size of executables and protecting resources, and many programs take advantage of it, explains why legal samples can have high entropy.

Despite the fact that entropy alone is insufficient to distinguish malicious code from benign code, malware analysis tools have employed high entropy as one of the major aspects in their malicious score systems to flag samples. 

## Avoiding high entropy algorithms
During my research, I noticed that the default Cobalt Strike shellcode has an entropy of 7.4, that is high! There are many possibilities to obfuscate the code, by using an algorithm that does not increase entropy (like XORing and Base64 encoding). This last one I think is the more convenient, which does not mean that is perfect. XORing as well as Base64 encoding can be easily decrypted to unmask the real purpose of the code. Also signatures can be created directly, both against the XORed as well as the Base64 encoded data. Finally, Some anti-malware solutions can even decode these simple schemes during the emulation phase of the analysis.

## The solution
If randomness is the issue, why not try to mask the harmful obfuscated code by introducing patterns that diminish unpredictability and hence global entropy? This manner, you are not restricted to using basic techniques to obfuscate code and remain undetected by anti-malware solutions; also, the obfuscated code may be any size. 

## How the PoC works

![poc_logic_flow](https://github.com/kleiton0x00/Shelltropy/blob/main/Images/encoding_logic_flow.jpg?raw=true)

The concept is to divide the array into chunks and insert a low-entropy pattern of bytes between each chunk. When the sample is run, we must reconstruct the original payload in memory, bypassing the static detection of the high entropy code at this stage.
It's also worth noting that the low-entropy code to be inserted can follow a variety of patterns, and the amount of insertions can vary, thus it can be used to circumvent static signature detection. The second step is to combine the high entropy chunks of bytes with the low entropy chunks. 
Because, after all, we need to restore the obfuscated code to what it was initially in order to proceed to the de-obfuscation step, the third job will restore the original array of bytes by deleting the low entropy patterns. 

## Results

**Note:** The following results are only tested with CS Shellcode.

~ Raw default Cobalt Strike shellcode  
(High-entropy) Normal: **7.062950**   
(Low-entropy) Encoded: **4.527140**  

~ XORed Cobalt Strike shellcode  
(High-entropy) Normal: **4.583139**    
(Low-entropy) Encoded: **3.278284**

## Summary
It is straightforward to reduce the entropy of obfuscated malware code; it may be used to elude detection and, on top of that, it may provide some extra protection against signature formation. The code described here can be modified to build solutions that assist avoid the use of entropy as a malware detection method.
Using alternative mathematical equations and different sized low entropy chunks of code to create better low entropy byte patterns may improve the method's reliability. 
