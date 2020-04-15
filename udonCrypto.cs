using System;

public class udonCrypto
{
	private const int SHA256_leng  = 256; // bit
	private const int SHA256_chunk = 512; // bit
	private const int SHA256_work  = 64;

	public byte[] StringToByte( string s ) {
		byte[] r = new byte[ s.Length ];
		for( int i = 0; i < s.Length; i++ ) {
			r[i] = Convert.ToByte( s[i] );
		}
		return r;
	}

	public string ByteToHex( byte[] b ) {
		string r = "";
		for( int i = 0; i < b.Length; i++ ) {
			r += b[i].ToString( "X2" );
		}
		return r;
	}

	private UInt32 rotate( UInt32 x, int y )
	{
		return (x >> y) + (x << (32 - y));
	}

	public byte[] SHA256( byte[] msg )
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
		UInt64 msgLength = (UInt64)( msg.Length ) * 8;
		m[m.Length - 8] = (byte)( (msgLength >> 56) & 0xff );
		m[m.Length - 7] = (byte)( (msgLength >> 48) & 0xff );
		m[m.Length - 6] = (byte)( (msgLength >> 40) & 0xff );
		m[m.Length - 5] = (byte)( (msgLength >> 32) & 0xff );
		m[m.Length - 4] = (byte)( (msgLength >> 24) & 0xff );
		m[m.Length - 3] = (byte)( (msgLength >> 16) & 0xff );
		m[m.Length - 2] = (byte)( (msgLength >>  8) & 0xff );
		m[m.Length - 1] = (byte)( (msgLength >>  0) & 0xff );

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

	private UInt32[] BigIntAdd( UInt32[] lhs, UInt32[] rhs, out UInt32 c )
	{
		// lhs.Length == rhs.Length
		UInt32[] r = new UInt32[ lhs.Length ];
		c = 0;
		for( int i = 0; i < lhs.Length; i++ ) {
			UInt64 t = c;
			t = t + lhs[i];
			t = t + rhs[i];
			r[i] = (UInt32)( t & 0xffffffff );
			c = (UInt32)( t >> 32 );
		}
		return r;
	}

	private UInt32[] BigIntSub( UInt32[] lhs, UInt32[] rhs, out UInt32 b )
	{
		// lhs.Length == rhs.Length
		UInt32[] r = new UInt32[ lhs.Length ];
		b = 0;
		for( int i = 0; i < lhs.Length; i++ ) {
			Int64 t = lhs[i];
			t = t - rhs[i];
			t = t - b;
			if( t < 0 ) {
				r[i] = (UInt32)( t + 0x100000000 );
				b = 1;
			} else {
				r[i] = (UInt32)( t );
				b = 0;
			}
		}
		return r;
	}

	private UInt32[] BigIntMult64( UInt32[] lhs, UInt32[] rhs )
	{
		// lhs.Length == rhs.Length == 2
		UInt32[] r = new UInt32[ 4 ];

		UInt64 t0 = lhs[0];
		t0 = t0 * rhs[0];
		UInt64 t2 = lhs[1];
		t2 = t2 * rhs[1];

		UInt32[] z = new UInt32[ 4 ];
		z[0] = (UInt32)( t0 & 0xffffffff );
		z[1] = (UInt32)( t0 >> 32 );
		z[2] = (UInt32)( t2 & 0xffffffff );
		z[3] = (UInt32)( t2 >> 32 );

		UInt64 t11 = lhs[1], t12 = rhs[1];
		t11 = t11 * rhs[0];
		t12 = t12 * lhs[0];
		UInt32[] z1 = new UInt32[ 4 ];
		UInt32[] z2 = new UInt32[ 4 ];
		z1[0] = 0;
		z1[1] = (UInt32)( t11 & 0xffffffff );
		z1[2] = (UInt32)( t11 >> 32 );
		z1[3] = 0;
		z2[0] = 0;
		z2[1] = (UInt32)( t12 & 0xffffffff );
		z2[2] = (UInt32)( t12 >> 32 );
		z2[3] = 0;

		UInt32 c1, c2;
		return BigIntAdd( z, BigIntAdd( z1, z2, out c1 ), out c2 );
		// c1 == 0, c2 == 0
	}

	private UInt32[] BigIntMult128( UInt32[] lhs, UInt32[] rhs )
	{
		// lhs.Length == rhs.Length == 8
		int Leng = lhs.Length;

		UInt32[] lhs0 = new UInt32[ Leng / 2 ];
		UInt32[] lhs1 = new UInt32[ Leng / 2 ];
		UInt32[] rhs0 = new UInt32[ Leng / 2 ];
		UInt32[] rhs1 = new UInt32[ Leng / 2 ];
		Array.Copy( lhs,        0, lhs0, 0, Leng / 2 );
		Array.Copy( lhs, Leng / 2, lhs1, 0, Leng / 2 );
		Array.Copy( rhs,        0, rhs0, 0, Leng / 2 );
		Array.Copy( rhs, Leng / 2, rhs1, 0, Leng / 2 );

		UInt32[] z = new UInt32[ Leng * 2 ];
		UInt32[] z0 = BigIntMult64( lhs0, rhs0 );
		UInt32[] z2 = BigIntMult64( lhs1, rhs1 );
		Array.Copy( z0, 0, z,    0, Leng );
		Array.Copy( z2, 0, z, Leng, Leng );

		UInt32[] t0 = new UInt32[ Leng * 2 ];
		UInt32[] t1 = new UInt32[ Leng * 2 ];
		UInt32[] t2 = new UInt32[ Leng * 2 ];
		Array.Clear( t0, 0, Leng * 2 );
		Array.Clear( t1, 0, Leng * 2 );
		Array.Clear( t2, 0, Leng * 2 );
		Array.Copy( z0, 0, t0, Leng / 2, Leng );
		Array.Copy( z2, 0, t2, Leng / 2, Leng );

		UInt32 bl, br, t;
		UInt32[] lhsd = BigIntSub( lhs1, lhs0, out bl );
		UInt32[] rhsd = BigIntSub( rhs1, rhs0, out br );
		if( bl != 0 ) {
			lhsd = BigIntSub( lhs0, lhs1, out t );
		}
		if( br != 0 ) {
			rhsd = BigIntSub( rhs0, rhs1, out t );
		}
		// t == 0
		Array.Copy( BigIntMult64( lhsd, rhsd ), 0, t1, Leng / 2, Leng );

		UInt32[] z1 = BigIntAdd( t0, t2, out t );
		// t == 0
		if( br != bl ) {
			z1 = BigIntAdd( z1, t1, out t );
		} else {
			z1 = BigIntSub( z1, t1, out t );
		}
		// t == 0

		return BigIntAdd( z, z1, out t );
		// t == 0
	}

	private UInt32[] BigIntMult256( UInt32[] lhs, UInt32[] rhs )
	{
		// lhs.Length == rhs.Length == 8
		int Leng = lhs.Length;

		UInt32[] lhs0 = new UInt32[ Leng / 2 ];
		UInt32[] lhs1 = new UInt32[ Leng / 2 ];
		UInt32[] rhs0 = new UInt32[ Leng / 2 ];
		UInt32[] rhs1 = new UInt32[ Leng / 2 ];
		Array.Copy( lhs,        0, lhs0, 0, Leng / 2 );
		Array.Copy( lhs, Leng / 2, lhs1, 0, Leng / 2 );
		Array.Copy( rhs,        0, rhs0, 0, Leng / 2 );
		Array.Copy( rhs, Leng / 2, rhs1, 0, Leng / 2 );

		UInt32[] z = new UInt32[ Leng * 2 ];
		UInt32[] z0 = BigIntMult128( lhs0, rhs0 );
		UInt32[] z2 = BigIntMult128( lhs1, rhs1 );
		Array.Copy( z0, 0, z,    0, Leng );
		Array.Copy( z2, 0, z, Leng, Leng );

		UInt32[] t0 = new UInt32[ Leng * 2 ];
		UInt32[] t1 = new UInt32[ Leng * 2 ];
		UInt32[] t2 = new UInt32[ Leng * 2 ];
		Array.Clear( t0, 0, Leng * 2 );
		Array.Clear( t1, 0, Leng * 2 );
		Array.Clear( t2, 0, Leng * 2 );
		Array.Copy( z0, 0, t0, Leng / 2, Leng );
		Array.Copy( z2, 0, t2, Leng / 2, Leng );

		UInt32 bl, br, t;
		UInt32[] lhsd = BigIntSub( lhs1, lhs0, out bl );
		UInt32[] rhsd = BigIntSub( rhs1, rhs0, out br );
		if( bl != 0 ) {
			lhsd = BigIntSub( lhs0, lhs1, out t );
		}
		if( br != 0 ) {
			rhsd = BigIntSub( rhs0, rhs1, out t );
		}
		// t == 0
		Array.Copy( BigIntMult128( lhsd, rhsd ), 0, t1, Leng / 2, Leng );

		UInt32[] z1 = BigIntAdd( t0, t2, out t );
		// t == 0
		if( br != bl ) {
			z1 = BigIntAdd( z1, t1, out t );
		} else {
			z1 = BigIntSub( z1, t1, out t );
		}
		// t == 0

		return BigIntAdd( z, z1, out t );
		// t == 0
	}

	private UInt64[] BigIntDiv( UInt64[] lhs, UInt64[] rhs, out UInt64[] mod )
	{
		mod = null;
		return null;
	}

	public static void Main()
	{
		udonCrypto c = new udonCrypto();

		byte[] msg = c.StringToByte( "abc" );

		byte[] hash = c.SHA256( msg );

		Console.WriteLine( c.ByteToHex( hash ) );
	}
}
