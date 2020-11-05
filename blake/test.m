clear all;

obj = Blake_256;

[ obj, hash ] = obj.Hash( 0, 8 );
'00H - 8 bits'
hash

[ obj, hash ] = obj.Hash( 0, 576 );
'00...00H - 576 bits'
hash

[ obj, hash ] = obj.Hash( 0, 1020 );
'00...0H - 1020 bits'
hash