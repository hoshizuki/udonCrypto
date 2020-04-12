using System;

public class udonCrypto
{
	private const int SHA256_leng  = 256; // bit
	private const int SHA256_chunk = 512; // bit
	private const int SHA256_work  = 64;

	private static UInt32 rotate( UInt32 x, int y )
	{
		return (x >> y) + (x << (32 - y));
	}

	public static byte[] SHA256( byte[] msg )
	{
		UInt32[] initial_h = new UInt32[SHA256_leng / 32];
		initial_h[0] = 0x6a09e667;
		initial_h[1] = 0xbb67ae85;
		initial_h[2] = 0x3c6ef372;
		initial_h[3] = 0xa54ff53a;
		initial_h[4] = 0x510e527f;
		initial_h[5] = 0x9b05688c;
		initial_h[6] = 0x1f83d9ab;
		initial_h[7] = 0x5be0cd19;

		UInt32[] k = new UInt32[SHA256_work];
		k[ 0] = 0x428a2f98; k[ 1] = 0x71374491; k[ 2] = 0xb5c0fbcf; k[ 3] = 0xe9b5dba5; k[ 4] = 0x3956c25b; k[ 5] = 0x59f111f1; k[ 6] = 0x923f82a4; k[ 7] = 0xab1c5ed5;
		k[ 8] = 0xd807aa98; k[ 9] = 0x12835b01; k[10] = 0x243185be; k[11] = 0x550c7dc3; k[12] = 0x72be5d74; k[13] = 0x80deb1fe; k[14] = 0x9bdc06a7; k[15] = 0xc19bf174;
		k[16] = 0xe49b69c1; k[17] = 0xefbe4786; k[18] = 0x0fc19dc6; k[19] = 0x240ca1cc; k[20] = 0x2de92c6f; k[21] = 0x4a7484aa; k[22] = 0x5cb0a9dc; k[23] = 0x76f988da;
		k[24] = 0x983e5152; k[25] = 0xa831c66d; k[26] = 0xb00327c8; k[27] = 0xbf597fc7; k[28] = 0xc6e00bf3; k[29] = 0xd5a79147; k[30] = 0x06ca6351; k[31] = 0x14292967;
		k[32] = 0x27b70a85; k[33] = 0x2e1b2138; k[34] = 0x4d2c6dfc; k[35] = 0x53380d13; k[36] = 0x650a7354; k[37] = 0x766a0abb; k[38] = 0x81c2c92e; k[39] = 0x92722c85;
		k[40] = 0xa2bfe8a1; k[41] = 0xa81a664b; k[42] = 0xc24b8b70; k[43] = 0xc76c51a3; k[44] = 0xd192e819; k[45] = 0xd6990624; k[46] = 0xf40e3585; k[47] = 0x106aa070;
		k[48] = 0x19a4c116; k[49] = 0x1e376c08; k[50] = 0x2748774c; k[51] = 0x34b0bcb5; k[52] = 0x391c0cb3; k[53] = 0x4ed8aa4a; k[54] = 0x5b9cca4f; k[55] = 0x682e6ff3;
		k[56] = 0x748f82ee; k[57] = 0x78a5636f; k[58] = 0x84c87814; k[59] = 0x8cc70208; k[60] = 0x90befffa; k[61] = 0xa4506ceb; k[62] = 0xbef9a3f7; k[63] = 0xc67178f2;

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
				UInt32 ch = (e[4] & e[5]) ^ ((0xffffffff - e[4]) & e[6]);
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
			hash[ i * 4 + 0 ] = (byte)( (h[i] >> 24) & 0xff );
			hash[ i * 4 + 1 ] = (byte)( (h[i] >> 16) & 0xff );
			hash[ i * 4 + 2 ] = (byte)( (h[i] >>  8) & 0xff );
			hash[ i * 4 + 3 ] = (byte)( (h[i]      ) & 0xff );
		}

		return hash;
	}

	public static void Main()
	{
		byte[] msg = System.Text.Encoding.ASCII.GetBytes( "abc" );

		byte[] hash = SHA256( msg );

		Console.WriteLine( System.BitConverter.ToString( hash ).Replace( "-", "" ) );
	}
}
