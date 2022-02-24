q = 7
alpha = 5

while True:
    print("Please enter the private key of User A, i.e. xa.")
    xa = int(input())
    if xa>=q:
        print("Error : The entered value of xa, {} is greater than q, {}.".format(xa,q))
    else:
        ya = (alpha**xa)%q
        print("Private Key of A, xa == {}.".format(xa))
        print("Public  Key of A, ya == {}.".format(ya))
        break

while True:
    print("Please enter the private key of User B, i.e. xb.")
    xb = int(input())
    if xb>=q:
        print("Error : The entered value of xb, {} is greater than q, {}.".format(xb,q))
    else:
        yb = (alpha**xb)%q
        print("Private Key of A, xb == {}.".format(xb))
        print("Public  Key of A, yb == {}.".format(yb))
        break   
    
k1 = (yb**xa)%q
k2 = (ya**xb)%q
if k1==k2:
    print("k1 == {}, k2 == {}, hence the secret key is the same.".format(k1,k2))

