#include <stdexcept>

#include <sstream>
using std::stringstream;

#include <string>
using std::string;
using std::getline;

#include <iostream>
using std::cerr;
using std::endl;

#include <vector>
using std::vector;

#include <cstring>

#include "byteblocks.hpp"

/// Constructors

ByteBlock::ByteBlock(size_t size_, BYTE init_value) :
    number_of_bytes(size_)
{
    if(!size_)
    	pBlocks = nullptr;
    else 
    {
        pBlocks = new BYTE [size_];
        memset(pBlocks, init_value, size_);
    }
}

ByteBlock::ByteBlock(BYTE * src_, size_t size_) :
    number_of_bytes(size_)
{
    pBlocks = new BYTE [size_];
    memcpy(pBlocks, src_, size_);
}

ByteBlock::ByteBlock(ByteBlock && src) :
    pBlocks(src.pBlocks), number_of_bytes(src.number_of_bytes)
{
    src.pBlocks = nullptr;
    src.number_of_bytes = 0;
}

ByteBlock::~ByteBlock()
{
    if(pBlocks) 
    {
        memset(pBlocks, 0, number_of_bytes);
        delete [] pBlocks;
    }
}

void ByteBlock::reset(const BYTE * pBlocks_, size_t size_)
{
    if(pBlocks) 
    {
        memset(pBlocks, 0, number_of_bytes);
        delete [] pBlocks;
    }
    if(size_ && pBlocks_) 
    {
        pBlocks = new BYTE [size_];
        memcpy(pBlocks, pBlocks_, size_);
        number_of_bytes = size_;
    } else  
    {
        pBlocks = nullptr;
        number_of_bytes = 0;
    }
}

void swap(ByteBlock & a, ByteBlock & b) 
{
    BYTE * tmp = a.pBlocks;
    size_t tmp_size = a.number_of_bytes;
    a.pBlocks = b.pBlocks;
    a.number_of_bytes = b.number_of_bytes;
    b.pBlocks = tmp;
    b.number_of_bytes = tmp_size;
}
