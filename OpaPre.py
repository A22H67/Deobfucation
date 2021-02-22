
from miasm.ir.symbexec import SymbolicExecutionEngine
import z3
from miasm.ir.translators.translator import Translator
from miasm.expression.expression import ExprCond, ExprInt
from miasm.expression.simplifications import expr_simp
import warnings

def to_idc(lockeys,asmcfg,filename,target_addr):
    header='''
    #include <idc.idc>
    static main(){
    '''
    footer='''
    }
    '''
    body=''
    f=open('op-%s-%s.idc' %(filename,hex(target_addr)),'w')
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
