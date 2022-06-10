file = open("payload.bin", 'rb')
contents = file.read()
file.close()

shellcode = []
for b in range(len(contents)):
    test = contents[b]
    shellcode.append("{:02x}".format(test))

output = "BYTE payload[] = {"

count = 0
for x in shellcode:
    if count < len(shellcode)-1:
        output += "0x{},".format(x)
    else:
        output += "0x{}".format(x)
    count += 1

output += "};"

print(output)
