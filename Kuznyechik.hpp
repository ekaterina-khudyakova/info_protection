#ifndef __KUZNYECHIK__
#define __KUZNYECHIK__

#include <vector>

#define BLOCK_LEN	16

class Kuznyechik {
	std::vector<ByteBlock> keys;
	static bool is_init;
public:
	static const int block_length {BLOCK_LEN};

	Kuznyechik(const ByteBlock & key);
	Kuznyechik(const Kuznyechik & rhs);
	~Kuznyechik();
	
	void encrypt(const ByteBlock & src, ByteBlock & dst) const;
	void decrypt(const ByteBlock & src, ByteBlock & dst) const;
};

#endif
