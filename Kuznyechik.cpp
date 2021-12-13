#include <stdexcept>

#include <vector>
using std::vector;

#include <map>
using std::map;

#include <iostream>
#include <cstring>
using std::cerr;
using std::endl;

#include "Kuznyechik.hpp"
#include "byteblocks.hpp"

/* The encryption round consists of following stages:
* 1. XOR of round key and data block.
* 2. Nonlinear transformation: replace one byte with another according to the table.
* 3. Linear transformation: 
	each byte from the block is multiplied by one of the coefficients in the GF(256);
	bytes are added together (mod2);
	block is shifted towards the 0 byte;
	the result of adding is written to the 16th byte.
*/
// Designations: S - nonlinear transform, L - linear transform

bool Kuznyechik::is_init = false;

// table for S transform
// S: 0->252, 1->238, ...
const vector<BYTE> S_transform_table = {
	252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77,
	233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193,
	249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79,
	5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31,
	235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204, 
	181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135,
	21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
	50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87,
	223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3,
	224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74,
	167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65,
	173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59,
	7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137,
	225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97,
	32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82,
	89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182
};
const map<BYTE, BYTE> direct_permutation, inverse_permutation;

// linear transformation uses GF(256): p(x)=x^8+x^7+x^6+x+1=451
// coefficients for L transform
const vector<WORD> L_transform_coeff = {
	148, 32, 133, 16, 194, 192, 1, 251, 1, 192,
	194, 16, 133, 32, 148, 1
};
const WORD L_transform_mod = 451;


/********* FUNCTIONS FOR S-TRANSFORMATION ***********/

void init_permutations()
{
	map<BYTE, BYTE> *direct_p, *inverse_p;
	direct_p = const_cast< map<BYTE, BYTE> * >(&direct_permutation);
	inverse_p = const_cast< map<BYTE, BYTE> * >(&inverse_permutation);
	
	for(int i = 0; i < S_transform_table.size(); i++)
	{
		(*direct_p)[i] = S_transform_table[i];
		(*inverse_p)[S_transform_table[i]] = i;
	}
}

void direct_S_transform_128(BYTE * target)
{
	BYTE * end_p = target + BLOCK_LEN;
	while(target != end_p)
	{
		*target = direct_permutation.at(*target);
		target++;
	}
}
void inverse_S_transform_128(BYTE * target)
{
	BYTE * end_p = target + BLOCK_LEN;
	while(target != end_p)
	{
		*target = inverse_permutation.at(*target);
		target++;
	}
}

/********* FUNCTIONS FOR L-TRANSFORMATION ***********/

WORD multiply(WORD a, WORD b)
{
	WORD res = 0;
	// multiply a by b
	for(WORD hotone = 0x1; hotone != 0x100; hotone <<= 1, a <<= 1)
		if(b & hotone)
			res ^= a;
			
	// find the value in our GF(256)
	WORD mod = L_transform_mod << 7;
	for(WORD hotone = 0x8000; hotone != 0x80; hotone >>= 1, mod >>= 1)
		if(res & hotone)
			res ^= mod;
	return res;
}

BYTE L_transform_128(const BYTE * target)
{
	WORD res = 0;
	for(int i = 0; i < BLOCK_LEN; i++)
		res ^= multiply(target[i], L_transform_coeff[i]);

	return res;
}

void direct_L_transform_128(BYTE * target) 
{
	// multiply block by coeffs and get new 16th byte
	BYTE buf = L_transform_128(target);
	// shift block
	for(int i = BLOCK_LEN - 1; i > 0; i--)
		target[i] = target[i-1];

	// fill an empty 16th byte
	*target = buf;
}

void inverse_L_transform_128(BYTE * target) 
{
	BYTE buf = *target;
	for(int i = 0; i < BLOCK_LEN - 1; i++)
		target[i] = target[i+1];
	target[15] = buf;
	target[15] = L_transform_128(target);
}

/********* PREPARING FOR KUZNYECHIK ***********/

/* Generation of round keys:
* 1. The master key is split in half - 1st pair of round keys.
* 2. 8 iterations of Feistel Cipher - 2nd pair of round keys.
* 3. Repeat 2 for next pairs (3rd, 4th, 5th). 
* Total 32 iterations. Iteration constants are obtained using the L-transformation of the iteration number.
*/
const vector<ByteBlock> iteration_constants;

void init_iteration_constants() 
{
	vector<ByteBlock> * p = const_cast< vector<ByteBlock> * >(&iteration_constants);
	ByteBlock v128;
	for(BYTE i = 1; i <= 32; i++)
	{
		v128 = ByteBlock(BLOCK_LEN, 0);
		v128[BLOCK_LEN - 1] = i;
		
		for(int j = 0; j < BLOCK_LEN; j++)
			direct_L_transform_128(v128.getBytePtr());
	
		p->push_back(std::move(v128));
	}
}

void xor128(BYTE * res, const BYTE * a, const BYTE * b) 
{
	const BYTE * end_p = res + BLOCK_LEN;
	while(res != end_p) {
		*(res++) = *(a++) ^ *(b++);
	}
}

// Feistel: right->left, left->L(S(left^Ci))^right
void FeistelCipher128(BYTE * left, BYTE * right, int Ci)
{
	BYTE buf[BLOCK_LEN];
	memcpy(buf, left, BLOCK_LEN);
	
	xor128(left, left, iteration_constants[Ci].getBytePtr());
	direct_S_transform_128(left);
	for(int j = 0; j < BLOCK_LEN; j++)
		direct_L_transform_128(left);
			
	xor128(left, right, left);
	
	memcpy(right, buf, BLOCK_LEN);
}

void generateKeys128(BYTE * k1, BYTE * k2, BYTE * k3, BYTE * k4, int round)
{
	if(k1 != k3)
		memcpy(k3, k1, BLOCK_LEN);
	if(k2 != k4)
		memcpy(k4, k2, BLOCK_LEN);
	for(int i = 0; i < 8; i++)
		FeistelCipher128(k3, k4, round * 8 + i);
}

void encrypt128(BYTE * target, const vector<ByteBlock> & keys)
{
	xor128(target, target, keys[0].getBytePtr());
	for(int i = 1; i < 10; i++)
	{
		direct_S_transform_128(target);
		for(int j = 0; j < BLOCK_LEN; j++)
			direct_L_transform_128(target);
		xor128(target, target, keys[i].getBytePtr());
	}
}

void decrypt128(BYTE * target, const vector<ByteBlock> & keys)
{
	xor128(target, target, keys[9].getBytePtr());
	for(int i = 8; i >= 0; i--)
	{
		for(int j = 0; j < BLOCK_LEN; j++)
			inverse_L_transform_128(target);
        	inverse_S_transform_128(target);
        	xor128(target, target, keys[i].getBytePtr());
	}
}

/********* MAIN PART OF KUZNYECHIK ***********/

Kuznyechik::Kuznyechik(const ByteBlock & key) :
    keys(10)
{
    if(key.getSize() != 32)
        throw std::invalid_argument("Kuznyechik: The key must be 32 bytes length");
    if(!is_init)
    {
        init_permutations();
        init_iteration_constants();
        is_init = true;
    }
    // get 1st pair of round keys
    keys[0].reset(key.getBytePtr(), BLOCK_LEN);
    keys[1].reset(key.getBytePtr() + BLOCK_LEN, BLOCK_LEN);
    
    // generate other round keys
    for(int i = 0; i < 4; i++)
    {
        keys[2 * i + 2] = ByteBlock(BLOCK_LEN);
        keys[2 * i + 3] = ByteBlock(BLOCK_LEN);
        generateKeys128(
			keys[2 * i].getBytePtr(),
			keys[2 * i + 1].getBytePtr(),
			keys[2 * i + 2].getBytePtr(),
			keys[2 * i + 3].getBytePtr(),
			i );
    }
}

Kuznyechik::Kuznyechik(const Kuznyechik & xKuznyechik)
{
	is_init = xKuznyechik.is_init;
	for(auto & iter_key : xKuznyechik.keys)
		keys.push_back(iter_key.getCopy());
}
Kuznyechik::~Kuznyechik() {}

void Kuznyechik::encrypt(const ByteBlock & src, ByteBlock & dst) const
{
    if(src.getSize() != BLOCK_LEN)
        throw std::invalid_argument("Kuznyechik: The block must be 16 bytes length");
    if(dst != src)
    	dst = src.getCopy();
    encrypt128(dst.getBytePtr(), keys);
}

void Kuznyechik::decrypt(const ByteBlock & src, ByteBlock & dst) const
{
    if(src.getSize() != BLOCK_LEN)
        throw std::invalid_argument("Kuznyechik: The block must be 16 bytes length");
    if(dst != src)
    	dst = src.getCopy();
    decrypt128(dst.getBytePtr(), keys);
}
