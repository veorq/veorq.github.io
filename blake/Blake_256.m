classdef Blake_256
  % Blake_256
  % File:        Blake_256.m
  % Description: Defines a class which implements the BLAKE-256 
  %                cryptographic hash function.
  % Notes:       
  %
  % Change History
  % Date        | Contributor          | Description
  % ------------+----------------------+-----------------------------------
  % 16/03/2011  | Zeke Steer           | Authored
  %             | Loughborough Uni, UK | 
  % ------------+----------------------+-----------------------------------    
  properties ( Constant )
    nRounds_32 = 14;                   % number of rounds
    
    % array of permutations of {0,...,15}, sigma 
    o = [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15;
          14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3;
          11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4;
           7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8;
           9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13;
           2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9;
          12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11;
          13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10;
           6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5;
          10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0
        ];
    
    % array of constants, c
    c = { '243F6A88', '85A308D3', '13198A2E', '03707344', ...
          'A4093822', '299F31D0', '082EFA98', 'EC4E6C89', ...
          '452821E6', '38D01377', 'BE5466CF', '34E90C6C', ...
          'C0AC29B7', 'C97C50DD', '3F84D5B5', 'B5470917'  ...
        };
    
    % array of initial values, iv
    iv = { '6A09E667', 'BB67AE85', '3C6EF372', 'A54FF53A', ...
           '510E527F', '9B05688C', '1F83D9AB', '5BE0CD19'  ...
         };
  end
  
  properties ( GetAccess = private )
    c_32, iv_256                       % fi objects
    f                                  % fimath object
    state                              % hash structure
  end
  
  methods ( Static = true )    
    function [ out ] = ToUInt_32( in )
      % ToUint_32
      % Converts a 32-element array of Boolean values into a 32-bit 
      %   unsigned integer.
      % Inputs:  in
      %            32-element array of Boolean values
      % Outputs: out
      %            32-bit unsigned integer

      out = 0;

      % loop through array
      for i = 1:32      
        % sum decimal value of each bit
        if in( i ) == 1
          out = out + 2^( i - 1 );
        end
      end
    end 
  end
  
  methods ( Access = private )
    function [ v ] = G( obj, v, i, r )
      % G
      % Transforms a 4-element array of 32-bit values in accordance with 
      %   the BLAKE specification, pp. 9 - 10.
      % Inputs:  obj
      %            Blake_256 object  
      %          v
      %            Input vector
      %          i
      %            Index
      %          r
      %            Round
      % Outputs: v
      %            Output vector

      % generate indices into state.m_32 and c
      j = obj.o( mod( r - 1, 10 ) + 1, 2 * i - 1 ) + 1;
      k = obj.o( mod( r - 1, 10 ) + 1, 2 * i ) + 1;
  
      % perform 1st sequence of transformations
      v( 1 ) = v( 1 ) + v( 2 ) + ...
               bitxor( obj.state.m_32( j ), obj.c_32( k ) );                   
      v( 4 ) = bitror( bitxor( v( 4 ), v( 1 ) ), 16 );
      v( 3 ) = v( 3 ) + v( 4 );
      v( 2 ) = bitror( bitxor( v( 2 ), v( 3 ) ), 12 );

      % perform 2nd sequence of transformations
      v( 1 ) = v( 1 ) + v( 2 ) + ...
               bitxor( obj.state.m_32( k ), obj.c_32( j ) );
      v( 4 ) = bitror( bitxor( v( 4 ), v( 1 ) ), 8 );
      v( 3 ) = v( 3 ) + v( 4 );
      v( 2 ) = bitror( bitxor( v( 2 ), v( 3 ) ), 7 );
    end 
    function [ obj ] = Compress( obj )
      % Compress
      % Compresses a 512-bit message block in accordance with the BLAKE
      %   specification, pp. 9 - 12.
      % Inputs:  obj
      %            Blake_256 object  
      % Outputs: obj
      %            Blake_256 object
    
      % populate 4x4 matrix, v with initial chain values
      v = [ obj.state.h_32( 1 ), obj.state.h_32( 2 ),     ...
            obj.state.h_32( 3 ), obj.state.h_32( 4 );     ...
            obj.state.h_32( 5 ), obj.state.h_32( 6 ),     ...
            obj.state.h_32( 7 ), obj.state.h_32( 8 );     ...
            bitxor( obj.state.s_32( 1 ), obj.c_32( 1 ) ), ...
            bitxor( obj.state.s_32( 2 ), obj.c_32( 2 ) ), ...
            bitxor( obj.state.s_32( 3 ), obj.c_32( 3 ) ), ...
            bitxor( obj.state.s_32( 4 ), obj.c_32( 4 ) ); ...
            bitxor( obj.state.t_32( 1 ), obj.c_32( 5 ) ), ...
            bitxor( obj.state.t_32( 1 ), obj.c_32( 6 ) ), ...
            bitxor( obj.state.t_32( 2 ), obj.c_32( 7 ) ), ...
            bitxor( obj.state.t_32( 2 ), obj.c_32( 8 ) )  ...
          ];
    
      % do rounds
      for r = 1 : obj.nRounds_32
        % do column steps
        v( [  1,  2,  3,  4 ] ) = obj.G( v( [  1,  2,  3,  4 ] ), ...
                                         1, r );
        v( [  5,  6,  7,  8 ] ) = obj.G( v( [  5,  6,  7,  8 ] ), ... 
                                         2, r ); 
        v( [  9, 10, 11, 12 ] ) = obj.G( v( [  9, 10, 11, 12 ] ), ...
                                         3, r ); 
        v( [ 13, 14, 15, 16 ] ) = obj.G( v( [ 13, 14, 15, 16 ] ), ...
                                         4, r );                                  
        
        % do diagonal steps
        v( [  1,  6, 11, 16 ] ) = obj.G( v( [  1,  6, 11, 16 ] ), ...
                                         5, r ); 
        v( [  5, 10, 15,  4 ] ) = obj.G( v( [  5, 10, 15,  4 ] ), ...
                                         6, r ); 
        v( [  9, 14,  3,  8 ] ) = obj.G( v( [  9, 14,  3,  8 ] ), ...
                                         7, r ); 
        v( [ 13,  2,  7, 12 ] ) = obj.G( v( [ 13,  2,  7, 12 ] ), ...
                                         8, r );     
      end

      % generate next chain values
      obj.state.h_32( 1 ) = bitxor( obj.state.h_32( 1 ), ...
                            bitxor( obj.state.s_32( 1 ), ...
                            bitxor( v( 1, 1 ), v( 3, 1 ) ) ) );
      obj.state.h_32( 2 ) = bitxor( obj.state.h_32( 2 ), ...
                            bitxor( obj.state.s_32( 2 ), ...
                            bitxor( v( 1, 2 ), v( 3, 2 ) ) ) );
      obj.state.h_32( 3 ) = bitxor( obj.state.h_32( 3 ), ...
                            bitxor( obj.state.s_32( 3 ), ...
                            bitxor( v( 1, 3 ), v( 3, 3 ) ) ) );
      obj.state.h_32( 4 ) = bitxor( obj.state.h_32( 4 ), ...
                            bitxor( obj.state.s_32( 4 ), ...
                            bitxor( v( 1, 4 ), v( 3, 4 ) ) ) );
      obj.state.h_32( 5 ) = bitxor( obj.state.h_32( 5 ), ...
                            bitxor( obj.state.s_32( 1 ), ...
                            bitxor( v( 2, 1 ), v( 4, 1 ) ) ) );
      obj.state.h_32( 6 ) = bitxor( obj.state.h_32( 6 ), ...
                            bitxor( obj.state.s_32( 2 ), ...
                            bitxor( v( 2, 2 ), v( 4, 2 ) ) ) );
      obj.state.h_32( 7 ) = bitxor( obj.state.h_32( 7 ), ...
                            bitxor( obj.state.s_32( 3 ), ...
                            bitxor( v( 2, 3 ), v( 4, 3 ) ) ) );
      obj.state.h_32( 8 ) = bitxor( obj.state.h_32( 8 ), ...
                            bitxor( obj.state.s_32( 4 ), ...
                            bitxor( v( 2, 4 ), v( 4, 4 ) ) ) );
    end
  end
  
  methods
    function [ obj ] = Blake_256( )
      % Blake_256
      % Blake_256 constructor.
      % Inputs:  -
      % Outputs: obj
      %            Blake_256 object
      
      % set fimath properties
      obj.f = fimath( 'CastBeforeSum',        1,         ...
                      'MaxProductWordLength', 128,       ...
                      'MaxSumWordLength',     128,       ...
                      'OverflowMode',         'wrap',    ...
                      'ProductBias',          0,         ...
                      'ProductMode',          'KeepLSB', ...
                      'ProductWordLength',    32,        ...
                      'RoundMode',            'ceil',    ...
                      'SumBias',              0,         ...
                      'SumMode',              'KeepLSB', ...
                      'SumWordLength',        32         ...
                    ); 

      % convert c in hex to fi representation
      obj.c_32 = fi( [ ], 0, 32, 0, obj.f );
      obj.c_32.hex = char( obj.c );
      
      % convert iv in hex to fi representation
      obj.iv_256 = fi( [ ], 0, 32, 0, obj.f );
      obj.iv_256.hex = char( obj.iv );
      
      % initialise hash structure
      obj.state = struct( 'h_32', fi( [ ], 0, 32, 0, obj.f ),           ...
                          's_32', fi( zeros( 1, 4 ), 0, 32, 0, obj.f ), ...  
                          't_32', fi( [ ], 0, 32, 0, obj.f ),           ...
                          'm_32', fi( [ ], 0, 32, 0, obj.f )            ...
                        );     
    end  
    function [ obj ] = Salt( obj, salt )
      % Salt
      % Sets a salt.
      % Inputs:  obj
      %            Blake_256 object
      %          salt
      %            128-bit salt
      % Outputs: obj
      %            Blake_256 object
        
      % convert salt to 128-bit fi representation   
      salt = fi( salt, 0, 128, 0, obj.f );
    
      % generate 4-element array of 32-bit values
      for i = 1 : 4
        obj.state.s_32( i ) = Blake_256.ToUInt_32( ...
                                salt.bitget( i * 32 - 31 : i * 32 ) ); 
      end
    end
    function [ obj, hash ] = Hash( obj, data, length )
      % Hash
      % Generates a 256-bit cryptographic hash value for an arbitrary 
      %   block of data.
      % Inputs:  obj
      %            Blake_256 object
      %          data
      %            Arbitrary block of data
      %          length
      %            Data length in bits
      
      % re-initialise hash structure
      obj.state.h_32 = obj.iv_256;
      obj.state.t_32 = fi( zeros( 1, 2 ), 0, 32, 0, obj.f );
      obj.state.m_32 = fi( zeros( 1, 16), 0, 32, 0, obj.f );
        
      % convert data to fi representation        
      data = fi( data, 0, length, 0, obj.f );
      
      % calculate pad bits so message length is multiple of 512 bits
      pad = 512 - mod( length + 66, 512 );

      % pad message
      data = data.bitconcat( fi( 1, 0, 1, 0, obj.f ),      ...
                             fi( 0, 0, pad, 0, obj.f ),    ...
                             fi( 1, 0, 1, 0, obj.f ),      ...
                             fi( length, 0, 64, 0, obj.f ) ... 
                           );

      % generate initial data index   
      i = length + pad + 66 + 1;
      
      % loop through 512-bit message blocks
      while length >= 512
        % increment counter LS 32 bits by 512
        obj.state.t_32( 1 ) = obj.state.t_32( 1 ) + ...
                              fi( 512, 0, 32, 0, obj.f );

        % increment counter MS 32 bits on overflow 
        if obj.state.t_32( 1 ) == 0
          obj.state.t_32( 2 ) = obj.state.t_32( 2 ) + ...
                                fi( 1, 0, 32, 0, obj.f );
        end

        % split 512-bit message block into 16 32-bit values
        for j = 1 : 16
          obj.state.m_32( j ) = Blake_256.ToUInt_32( data.bitget( ...
                                  i - j * 32 : i - ( j - 1 ) * 32 - 1 ) );
        end
    
        % compress message block
        obj = obj.Compress( );
   
        % decrement length and data index 
        length = length - 512;
        i = i - 512;    
      end
      
      % increment counter LS 32 bits by remaining data bits
      obj.state.t_32( 1 ) = obj.state.t_32( 1 ) + ...
                            fi( length, 0, 32, 0, obj.f );               

      % split 512-bit message block into 16 32-bit values
      for j = 1 : 16
        obj.state.m_32( j ) = Blake_256.ToUInt_32( data.bitget( ...
                                i - j * 32 : i - ( j - 1 ) * 32 - 1 ) );
      end

      % compress message block
      obj = obj.Compress( );
      
      % decrement data index
      i = i - 512;
  
      % check for special case, 0 data bits in last message block
      if length > 446
        % 0 data bits so counter = 0
        obj.state.t_32(1) = 0;
        obj.state.t_32(2) = 0;
        
        % split 512-bit message block into 16 32-bit values
        for j = 1 : 16
          obj.state.m_32( j ) = Blake_256.ToUInt_32( data.bitget( ...
                                  i - j * 32 : i - ( j - 1 ) * 32 - 1 ) );
        end
 
        % compress message block
        obj = obj.Compress( );

      end
      
      % convert hash value to hex and return
      hash = obj.state.h_32.hex;
    end
  end 
end 
