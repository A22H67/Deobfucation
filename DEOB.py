from miasm.core.locationdb import LocationDB
from miasm.analysis.machine import Machine
from miasm.analysis.binary import Container
from future.utils import viewitems
from miasm.arch.x86.regs import *
from miasm.expression.expression import ExprInt,ExprMem,ExprId,LocKey
from OpaPre import *
loc_db=LocationDB()
filename=input('Name of file:')
fdes=open(filename,'rb')
cont=Container.from_stream(fdes,loc_db)
machine=Machine(cont.arch)

print('Loc_db:')
print(loc_db)
str_addr=input('Address of target function:')
target_address=int(str_addr,16)

mdis=machine.dis_engine(cont.bin_stream,loc_db=loc_db,follow_call=False)

asmcfg=mdis.dis_multiblock(target_address)
while True:
    print("***************DEOB*****************")
    print("1.Opaque Predicates")
    print("2.Ranger divider")
    print("4.Exit")
    choice=input('Your choice:')
    if choice=='1': #OP
        ir_arch=machine.ira(mdis.loc_db)
        ircfg=ir_arch.new_ircfg_from_asmcfg(asmcfg)
        symbols_init={}
        for i,r in enumerate(all_regs_ids):
            symbols_init[r]=all_regs_ids_init[i]
        symbols_init[ExprMem(ExprId('ESP_init',32),32)]=ExprInt(0xdeadbeef,32)
        final_states=[]
        explore(ir=ir_arch,start_addr=target_address,start_sym=symbols_init,ircfg=ircfg,lbl_stop=0xdeadbeef,final_states=final_states)
        executed_lockey=[]
        unexecuted_lockey=[]
        for final_state in final_states:
            if final_state.result:
                for node in final_state.path_history:
                    if isinstance(node,int):
                        loc_k=ircfg.get_loc_key(node)
                    elif isinstance(node,ExprInt):
                        loc_k = ircfg.get_loc_key(node)
                    elif isinstance(node,LocKey):
                        loc_k = ircfg.get_loc_key(node)
                    if loc_k not in executed_lockey:
                        executed_lockey.append(loc_k)
        for loc_k,irblock in viewitems(ircfg.blocks):
            if loc_k not in executed_lockey:
                unexecuted_lockey.append(loc_k)
        print("Executed loc:")
        print(executed_lockey)
        print("================")
        print("Unexecuted loc:")
        print(unexecuted_lockey)
        print("================")
        to_idc(unexecuted_lockey,asmcfg,filename,target_address)




    if choice=='2':
        print("2")

    elif choice=='4':
        print("bye")
        break
    else:
        print("Option unavailable")





