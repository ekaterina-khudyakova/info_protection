#include<stdint.h>
#include <string>
using std::string;

#include <cstring>

#ifndef __BYTEBLOCKS__
#define __BYTEBLOCKS__

typedef uint8_t BYTE;
typedef uint16_t WORD;

class ByteBlock {
	BYTE * pBlocks;
	size_t number_of_bytes;
public:
    // Construct ByteBlock of size_ blocks each of them = init_value
    ByteBlock(size_t size_ = 0, BYTE init_value = 0);

    // Construct ByteBlock with size_ first bytes of src_ (the value is copied, src_ stays untouchable)
    ByteBlock(BYTE * src_, size_t size_);

    // Move src to ByteBlock, src turn to null
    ByteBlock(ByteBlock && src);

    ~ByteBlock();

    void operator = (ByteBlock && a)
    {
	if(this == &a)
	    return;
    	if(pBlocks) 
    	{
    	    memset(pBlocks, 0, number_of_bytes);
    	    delete [] pBlocks;
    	}
    	pBlocks = a.pBlocks;
    	number_of_bytes = a.number_of_bytes;
    	a.pBlocks = nullptr;
    	a.number_of_bytes = 0;
    }
    
    BYTE & operator [] (size_t index) { return *(pBlocks + index); }
    BYTE operator [] (size_t index) const { return *(pBlocks + index); }
    
    bool operator == (const ByteBlock & a) const { return pBlocks == a.pBlocks; }
    bool operator != (const ByteBlock & a) const { return !(*this == a); }
    
    // get slice of current ByteBlock
    ByteBlock operator () (size_t start, size_t length) const
    {
        ByteBlock tmp;
    	tmp.reset(pBlocks + start, length);
    	return tmp;
    }

    BYTE * getBytePtr() { return pBlocks; }
    const BYTE * getBytePtr() const { return pBlocks; }
    size_t getSize() const { return number_of_bytes; }
    ByteBlock getCopy() const { return ByteBlock(pBlocks, number_of_bytes); }
    
    // replace body of the current block with pBlocks_
    void reset(const BYTE * pBlocks_, size_t size_);

    friend void swap(ByteBlock & a, ByteBlock & b);
};

#endif
