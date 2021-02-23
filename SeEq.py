from miasm.ir.ir import IRCFG,IntermediateRepresentation
from miasm.arch.x86.regs import *
from miasm.ir.symbexec import SymbolicExecutionEngine
from future.utils import viewitems
import z3
from miasm.ir.translators.translator import Translator
import random
import networkx as nx
from miasm.expression.expression import LocKey
from miasm.analysis.machine import Machine
from miasm.analysis.binary import Container
from miasm.core.locationdb import LocationDB
def syntax_compare(blk0,blk1):
    if len(blk0.lines) != len(blk1.lines):
        return False
    for l0,l1 in zip(blk0.lines,blk1.lines):
        if str(l0)[0] =='J':
            instr0=str(l0).split(' ')[0]
            instr1=str(l1).split(' ')[0]
            if instr0 != instr1:
                return False
        else:
            if str(l0)!=str(l1):
                return False
    return True
def execute_symbolic_execution(src_irb,dst_irb,ir_arch0,ir_arch1,flag_cmp):
    src_symbols={}
    dst_symbols={}
    for i,r in enumerate(all_regs_ids):
        src_symbols[r]=all_regs_ids_init[i]
        dst_symbols[r]=all_regs_ids_init[i]

    src_sb=SymbolicExecutionEngine(ir_arch0,src_symbols)
    for assignblk in src_irb:
        skip_update=False
        for dst,src in viewitems(assignblk):
            if str(dst) in ['EIP','IRDst']:
                skip_update=True
            if not skip_update:
                src_sb.eval_updt_assignblk(assignblk)

    dst_sb=SymbolicExecutionEngine(ir_arch1,dst_symbols)
    for assignblk in dst_irb:
        skip_update=False
        for dst,src in viewitems(assignblk):
            if str(dst) in ['EIP','IRDst']:
                skip_update=True
            if not skip_update:
                dst_sb.eval_updt_assignblk(assignblk)
    #equi checking
    src_sb.del_mem_above_stack(ir_arch0.sp)
    dst_sb.del_mem_above_stack(ir_arch1.sp)

    all_memory_ids=[k for k,v in dst_sb.symbols.memory()]+[k for k,v in src_sb.symbols.memory()]

    for k in all_regs_ids + all_memory_ids:
        if str(k)=='EIP':
            continue
        if not flag_cmp and k in [zf,nf,pf,of,cf,af,df,tf]:
            continue
        v0=src_sb.symbols[k]
        v1=dst_sb.symbols[k]
        if v0==v1:
            continue
        solver=z3.Solver()
        try:
            z3_r=Translator.to_language('z3').from_expr(v0)
        except NotImplementedError:
            return False
        try:
            z3_l=Translator.to_language('z3').from_expr(v1)
        except NotImplementedError:
            return False
        solver.add(z3.Not(z3_r==z3_l))
        r=solver.check()
        if r==z3.unsat:
            continue
        else:
            return False
    return True

def semantic_compare(blk0,blk1,ir_arch0,ir_arch1,flag_cmp=False):
    src_ircfg=IRCFG(None,ir_arch0.loc_db)

    try:

        ir_arch0.add_asmblock_to_ircfg(blk0,src_ircfg)

    except NotImplementedError:
        return False
    dst_ircfg=IRCFG(None,ir_arch1.loc_db)
    try:
        ir_arch1.add_asmblock_to_ircfg(blk1,dst_ircfg)
    except NotImplementedError:
        return False
    if len(src_ircfg.blocks) != len(dst_ircfg.blocks):
        return False
    for src_lbl,dst_lbl in zip(src_ircfg.blocks,dst_ircfg.blocks):
        src_irb=src_ircfg.blocks.get(src_lbl,None)
        dst_irb=dst_ircfg.blocks.get(dst_lbl,None)
        r=execute_symbolic_execution(src_irb,dst_irb,ir_arch0,ir_arch1,flag_cmp)
        if r is False:
            return False
    return True
def gen_random_color():
    ret=[]
    a=[x for x in range(256)]
    b=[x for x in range(256)]
    c=[x for x in range(256)]
    random.shuffle(a)
    random.shuffle(b)
    random.shuffle(c)
    for a2,a1,a0 in zip(a,b,c):
        color=a2<<16 | a1<<8 | a0
        ret.append(color)
    return ret

def to_idc(target_block,results,asmcfg,filename,target_addr):
    G=nx.Graph()
    G.add_nodes_from(target_block)
    for k,v in viewitems(results):
        if v[0][0] or v[0][1]:
            G.add_edge(k[0],k[1])
    random_colors=gen_random_color()
    body=''
    for n,conn_nodes in enumerate(nx.connected_components(G)):
        if len(conn_nodes)==1:
            continue
        for node in conn_nodes:
            if isinstance(node,LocKey):
                asmblk=asmcfg.loc_key_to_block(node)
                if asmblk:
                    for l in asmblk.lines:
                        body += 'SetColor(0x%08x, CIC_ITEM, 0x%x);\n' % (l.offset, random_colors[n])
                else:
                    for l in node.lines:
                        body += 'SetColor(0x%08x, CIC_ITEM, 0x%x);\n' % (l.offset, random_colors[n])
    header='''
    #include <idc.idc>
    static main(){
    '''
    footer='''
    }
    '''
    f=open('EQ-%s-%s.idc' %(filename,hex(target_addr)),'w')
    f.write(header+body+footer)
    f.close()

def RangerDivDeob():
    loc_db = LocationDB()
    filename = input('Name of file:')
    fdes = open(filename, 'rb')
    cont = Container.from_stream(fdes, loc_db)
    machine = Machine(cont.arch)

    print('Loc_db:')
    print(loc_db)
    str_addr = input('Address of target function:')
    target_address = int(str_addr, 16)

    mdis = machine.dis_engine(cont.bin_stream, loc_db=loc_db, follow_call=False)

    asmcfg = mdis.dis_multiblock(target_address)

    ir_arch0 = machine.ira(mdis.loc_db)
    ir_arch1 = machine.ira(mdis.loc_db)
    target_blocks = []
    for cn, block in enumerate(asmcfg.blocks):
        target_blocks.append(block)
    results = {}
    for src_blk in target_blocks:
        src_loc = src_blk._loc_key
        if len(src_blk.lines) == 1 and src_blk.lines[0].dstflow():
            continue
        for dst_blk in target_blocks:
            dst_loc = dst_blk._loc_key
            if len(dst_blk.lines) == 1 and dst_blk.lines[0].dstflow():
                continue
            if src_loc == dst_loc:
                continue
            if (src_loc, dst_loc) in results.keys() or (dst_loc, src_loc) in results.keys():
                continue
            r_syntax = syntax_compare(src_blk, dst_blk)
            if r_syntax:
                r_semantic = True
            else:
                r_semantic = semantic_compare(src_blk, dst_blk, ir_arch0, ir_arch1)

            results[(src_loc, dst_loc)] = [(r_syntax, r_semantic)]
    to_idc(target_blocks, results, asmcfg, filename, target_address)


    



