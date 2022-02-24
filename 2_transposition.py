
def sender(key, string):
    k = len(key)
    s = len(string)
    
    r = s%k
    if r!=0:
        for _ in range(k-r):
            string+='~'
            
    dic = {}
    for i in range(k):
        dic.update({key[i]:string[i::len(key)]})
    lis = sorted(dic.items())
    
    sender = ''
    for i in lis:
        sender += ''.join(i[1])
        
    return sender
    

def receiver(key, sender):
    k = len(key)
    ls = len(sender)
    
    lis = [i for i in sorted(key)]
    rows = ls//k
    
    dic = {}
    for i in range(k):
        temp = i*rows
        dic.update({lis[i]:sender[temp:temp+rows]})
    
    
    receiver = ''
    for i in range(rows):
        for j in range(k):
            receiver+=dic[key[j]][i]
            
    receiver = receiver.replace("~","")
    
    return receiver


# key = "CIPHER"
# string = "Information Security"

key = input("Enter the key.")
string = input("Enter the text to be encrypted.")

print("Sending string......")
sender = sender(key, string)
print("The sender sends :",sender)

print("Receving string.....")
receiver = receiver(key, sender)
print("The receiver receives :",receiver)


