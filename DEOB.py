from SeEq import RangerDivDeob
from OpaquePre import OpDeob
while True:
    print("***************DEOB*****************")
    print("1.Opaque Predicates")
    print("2.Ranger divider")
    print("4.Exit")
    choice=input('Your choice:')
    if choice=='1': #OP

        OpDeob()
        print("OK")
    elif choice=='2':

        RangerDivDeob()
        print("OKE")
    elif choice=='4':
        print("bye")
        break
    else:
        print("Option unavailable")





