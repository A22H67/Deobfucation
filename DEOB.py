from miasm.core.locationdb import LocationDB
from miasm.analysis.machine import Machine
from miasm.analysis.binary import Container
from future.utils import viewitems
from miasm.arch.x86.regs import *
from miasm.expression.expression import ExprInt,ExprMem,ExprId,LocKey

from miasm.ir.ir import IRCFG

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
        from OpaPre import *

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
        to_idc(unexecuted_lockey,asmcfg,filename,target_address)
        print("OK")

    if choice=='2':
        from SeEq import *

        ir_arch0=machine.ira(mdis.loc_db)
        ir_arch1=machine.ira(mdis.loc_db)
        target_blocks=[]
        for cn,block in enumerate(asmcfg.blocks):
            target_blocks.append(block)
        results={}
        for src_blk in target_blocks:
            src_loc=src_blk._loc_key
            if len(src_blk.lines)==1 and src_blk.lines[0].dstflow():
                continue
            for dst_blk in target_blocks:
                dst_loc=dst_blk._loc_key
                if len(dst_blk.lines)==1 and dst_blk.lines[0].dstflow():
                    continue
                if src_loc==dst_loc:
                    continue
                if (src_loc,dst_loc) in results.keys() or (dst_loc,src_loc) in results.keys():
                    continue
                r_syntax=syntax_compare(src_blk,dst_blk)
                if r_syntax:
                    r_semantic=True
                else:
                    r_semantic=semantic_compare(src_blk,dst_blk,ir_arch0,ir_arch1)

                results[(src_loc,dst_loc)]=[(r_syntax,r_semantic)]
        to_idc(target_blocks, results, asmcfg, filename, target_address)
        print("OKE")

    elif choice=='4':
        print("bye")
        break
    else:
        print("Option unavailable")





