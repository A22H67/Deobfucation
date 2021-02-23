from miasm.core.locationdb import LocationDB
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.ir.symbexec import SymbolicExecutionEngine
import z3
from miasm.ir.translators.translator import Translator
from miasm.expression.expression import ExprCond, ExprId, ExprInt, ExprMem,LocKey
from miasm.expression.simplifications import expr_simp
from miasm.arch.x86.regs import *
from future.utils import viewitems
def to_idc(lockeys,asmcfg,filename,target_addr):
    header='''
    #include <idc.idc>
    static main(){
    '''
    footer='''
    }
    '''
    body=''
    f=open('OP-%s-%s.idc' %(filename,hex(target_addr)),'w')
    for loc in lockeys:
        asmblk=asmcfg.loc_key_to_block(loc)
        if asmblk:
            for l in asmblk.lines:
                body+= 'SetColor(0x%08x, CIC_ITEM, 0xc7c7ff);\n'%(l.offset)
    f.write(header+body+footer)
    f.close()

def check_path_feasibility(conds):
    solver=z3.Solver()
    for constraints,rval in conds:
        z3_cond=Translator.to_language("z3").from_expr(constraints)
        solver.add(z3_cond==rval.arg)
    rs=solver.check()
    if rs==z3.sat:
        return True
    else:
        return False
class FinalState:
    def __init__(self,result,sym,path_conds,path_history):
        self.result=result
        self.sb=sym
        self.path_conds=path_conds
        self.path_history=path_history
def explore(ir,start_addr,start_sym,ircfg,cond_limit=30,uncond_limit=100,lbl_stop=None,final_states=[]):

    def code_walk(addr,symbols,conds,depth,final_states,path):
        if depth>=cond_limit:
            warnings.warn("Depth is over the cond_limit:%d"%(depth))
            return
        sb=SymbolicExecutionEngine(ir,symbols)
        for _ in range(uncond_limit):
            if isinstance(addr,ExprInt):
                if addr==lbl_stop:
                    final_states.append(FinalState(True,sb,conds,path))
                    return
            path.append(addr)
            pc=sb.run_block_at(ircfg,addr)
            if isinstance(pc,ExprCond):
                # condition true false
                cond_true={pc.cond: ExprInt(1,32)}
                cond_false={pc.cond: ExprInt(0,32)}
                # the destination addr of true or false path
                addr_true=expr_simp(sb.eval_expr(pc.replace_expr(cond_true)))
                addr_false=expr_simp(sb.eval_expr(pc.replace_expr(cond_false)))

                conds_true=list(conds)+list(cond_true.items())
                conds_false=list(conds)+list(cond_false.items())

                if check_path_feasibility(conds_true):
                    code_walk(addr_true,sb.symbols.copy(),conds_true,depth+1,final_states,list(path))
                else:
                    final_states.append(FinalState(False,sb,conds_true,path))
                if check_path_feasibility(conds_false):
                    code_walk(addr_false,sb.symbols.copy(),conds_false,depth+1,final_states,list(path))
                else:
                    final_states.append(FinalState(False,sb,conds_false,path))
                return
            else:
                addr=expr_simp(sb.eval_expr(pc))

        final_states.append(FinalState(True,sb,conds,path))
        return
    return code_walk(start_addr,start_sym,[],0,final_states,[])


def OpDeob():
    loc_db=LocationDB()
    filename=input('Name of file: ')
    fdes=open(filename,'rb')
    cont=Container.from_stream(fdes,loc_db)
    machine=Machine(cont.arch)

    print("Loc_DB:")
    print(loc_db)
    str_addr=input('Address of target function: ')
    target_addr=int(str_addr,16)
    mdis=machine.dis_engine(cont.bin_stream,loc_db=loc_db) #disengine
    mdis.follow_call=False #follow calls
    #mdis.dontdis_retcall=True
    asmcfg=mdis.dis_multiblock(target_addr)  #dis asm
    open("before-simp.dot","w").write(asmcfg.dot())
    ir_arch=machine.ira(mdis.loc_db) #ir_arch

    ircfg=ir_arch.new_ircfg_from_asmcfg(asmcfg)

    symbols_init={}
    for i,r in enumerate(all_regs_ids):
        symbols_init[r]=all_regs_ids[i]

    final_states=[]
    explore(ir=ir_arch,start_addr=target_addr,start_sym=symbols_init,ircfg=ircfg,lbl_stop=0xdeadbeef,final_states=final_states)

    executed_loc=[]
    unexecuted_loc=[]

    for final_states in final_states:
        if final_states.result:
            for node in final_states.path_history:
                if isinstance(node,int):
                    loc_K=ircfg.get_loc_key(node)
                elif isinstance(node,ExprInt):
                    loc_K=ircfg.get_loc_key(node)
                elif isinstance(node,LocKey):
                    loc_K=node.loc_key

                if loc_K not in executed_loc:
                    executed_loc.append(loc_K)

    for loc_K,irblock in viewitems(ircfg.blocks):
        if loc_K not in executed_loc:
            unexecuted_loc.append(loc_K)
    print("Executed loc:")
    print(executed_loc)
    print("================")
    print("Unexecuted loc:")
    print(unexecuted_loc)
    print("==================")

    to_idc(unexecuted_loc, asmcfg, filename, target_addr)

