using System;

public class udonCrypto
{
	private const int SHA256_leng  = 256; // bit
	private const int SHA256_chunk = 512; // bit
	private const int SHA256_work  = 64;

	private static UInt32 rotate( UInt32 x, int y )
	{
		UInt64 xx = (UInt64)x;
		xx = (xx << 32) + xx;
		xx = xx >> y;
		return (UInt32)xx;
	}

	public static byte[] SHA256( byte[] msg )
	{
		UInt32[] initial_h = new UInt32[SHA256_leng / 32] {
			0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
		};

		UInt32[] k = new UInt32[SHA256_work] {
			0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
			0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
			0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
			0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
		};

		int chunk_n = ((msg.Length + 1 /* mark */ + 8 /* leng */) + (SHA256_chunk / 8) - 1) / (SHA256_chunk / 8);
		byte[] m = new byte[ chunk_n * (SHA256_chunk / 8) ];

		for( int i = 0; i < msg.Length; i++ ) {
			m[i] = msg[i];
		}
		m[msg.Length] = 0x80;
		for( int i = msg.Length + 1; i < m.Length; i++ ) {
			m[i] = 0;
		}
		UInt64 msgLength = (UInt64)( msg.Length * 8 );
		m[m.Length - 8] = (byte)( msgLength >> 56 );
		m[m.Length - 7] = (byte)( msgLength >> 48 );
		m[m.Length - 6] = (byte)( msgLength >> 40 );
		m[m.Length - 5] = (byte)( msgLength >> 32 );
		m[m.Length - 4] = (byte)( msgLength >> 24 );
		m[m.Length - 3] = (byte)( msgLength >> 16 );
		m[m.Length - 2] = (byte)( msgLength >>  8 );
		m[m.Length - 1] = (byte)( msgLength >>  0 );

		UInt32[] h = (UInt32[]) initial_h.Clone();
		for( int c = 0; c < chunk_n; c++ ) {
			UInt32[] w = new UInt32[ SHA256_work ];
			for( int i = 0; i < SHA256_chunk / 32; i++ ) {
				int p = c * (SHA256_chunk / 8) + i * 4;
				w[i] = (UInt32)( (m[p + 0] << 24) + (m[p + 1] << 16) + (m[p + 2] << 8) + (m[p + 3]) );
			}
			for( int i = SHA256_chunk / 32; i < SHA256_work; i++ ) {
				UInt32 s0 = rotate( w[i-15], 7 ) ^ rotate( w[i-15], 18 ) ^ ( w[i-15] >> 3 );
				UInt32 s1 = rotate( w[i-2], 17 ) ^ rotate( w[i-2], 19 ) ^ ( w[i-2] >> 10 );
				w[i] = w[i-16] + s0 + w[i-7] + s1;
			}

			UInt32[] e = (UInt32[]) h.Clone();
			for( int i = 0; i < SHA256_work; i++ ) {
				UInt32 s1 = rotate( e[4], 6 ) ^ rotate( e[4], 11 ) ^ rotate( e[4], 25 );
				UInt32 ch = (e[4] & e[5]) ^ ((~e[4]) & e[6]);
				UInt32 t1 = e[7] + s1 + ch + k[i] + w[i];
				UInt32 s0 = rotate( e[0], 2 ) ^ rotate( e[0], 13 ) ^ rotate( e[0], 22 );
				UInt32 mj = (e[0] & e[1]) ^ (e[0] & e[2]) ^ (e[1] & e[2]);
				UInt32 t2 = s0 + mj;

				e[7] = e[6]; e[6] = e[5]; e[5] = e[4]; e[4] = e[3] + t1;
				e[3] = e[2]; e[2] = e[1]; e[1] = e[0]; e[0] = t1 + t2;
			}
			for( int i = 0; i < h.Length; i++ ) {
				h[i] = h[i] + e[i];
			}
		}

		byte[] hash = new byte[SHA256_leng / 8];
		for( int i = 0; i < SHA256_leng / 32; i++ ) {
			hash[ i * 4 + 0 ] = (byte)( h[i] >> 24 );
			hash[ i * 4 + 1 ] = (byte)( h[i] >> 16 );
			hash[ i * 4 + 2 ] = (byte)( h[i] >>  8 );
			hash[ i * 4 + 3 ] = (byte)( h[i]       );
		}

		return hash;
	}

	public static void Main()
	{
		byte[] msg = System.Text.Encoding.ASCII.GetBytes( "test" );

		byte[] hash = SHA256( msg );

		Console.WriteLine( System.BitConverter.ToString( hash ).Replace( "-", "" ) );
	}
}
