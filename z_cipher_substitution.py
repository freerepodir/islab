def forward(n):
    return ord(n)-65

def reverse(n):
    return chr(n+65)

# p = "HELLO"
# k = 4
p = input("Enter the string.")
k = int(input("Enter the key."))

f = ''
for i in p:
    p = forward(i)
    a = reverse((p+k)%26)
    f+=a

print("The encrypted string :",f)

r = ''
for i in f:
    c = forward(i)
    a = reverse((c-k)%26)
    r+=a

print("The decrypted string :",r)
