import struct,sys
def parse(path):
    d=open(path,'rb').read()
    count=struct.unpack_from('>I',d,0x20)[0]
    p=0x24; out=[]
    for n in range(count):
        eid=struct.unpack_from('>I',d,p)[0]; p+=4
        strs=[]
        for k in range(3):
            l=struct.unpack_from('<I',d,p)[0]; p+=4
            strs.append(d[p:p+l].decode('latin1')); p+=l
        off,size,zsize=struct.unpack_from('>QII',d,p); entry_off=p; p+=16
        tail=d[p:p+10]; p+=10
        out.append(dict(id=eid,type=strs[0],name=strs[1],path=strs[2],off=off,size=size,zsize=zsize,entry_off=entry_off,container=struct.unpack_from('>H',tail,8)[0],tail=tail))
    return d,out
if __name__=='__main__':
    d,es=parse(sys.argv[1])
    print(len(es),'entries; end',hex(sum(1 for _ in [])))
    for e in es:
        if sys.argv[2].lower() in (e['name']+e['path']).lower(): print(e['id'],e['type'],e['name'],e['path'],hex(e['off']),e['size'],e['zsize'],e['container'],e['tail'].hex())
