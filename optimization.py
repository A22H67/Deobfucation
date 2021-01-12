from miasm.core.locationdb import LocationDB
from miasm.analysis.machine import Machine
from miasm.analysis.binary import Container
from miasm.analysis.cst_propag import propagate_cst_expr
from miasm.analysis.data_flow import DeadRemoval,merge_blocks,remove_empty_assignblks

from future.utils import viewitems
fileName=input('Input file name:')
fdes=open(fileName,'rb')
#fdes=open('test-add-sub','rb')

loc_db=LocationDB()
cont=Container.from_stream(fdes,loc_db)
machine=Machine(cont.arch)
mdis=machine.dis_engine(cont.bin_stream,loc_db=loc_db)
mdis.follow_call=True #follow calls
mdis.dontdis_retcall=True
#disasembly
address=loc_db.get_name_offset("main") #address
asmcfg=mdis.dis_multiblock(offset=address)
open("test-add-before.dot","w").write(asmcfg.dot())
#end
functionName=input('input function name:')
print("Function name:"+functionName)
address=loc_db.get_name_offset(functionName) #get function_name

asmcfg=mdis.dis_multiblock(offset=address)

ir_arch=machine.ira(mdis.loc_db)
ircfg=ir_arch.new_ircfg_from_asmcfg(asmcfg)

entry_points=set([mdis.loc_db.get_offset_location(address)])
init_infos=ir_arch.arch.regs.regs_init


cst_propag_link=propagate_cst_expr(ir_arch,ircfg,address,init_infos) #--> address
deadrm=DeadRemoval(ir_arch)
modified=True
while modified:
    modified=False
    modified |=deadrm(ircfg)
    modified |=remove_empty_assignblks(ircfg)

print("After:")
for lbl,irb in viewitems(ircfg.blocks):
    print(irb)





