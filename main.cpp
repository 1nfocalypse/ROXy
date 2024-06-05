#include <iostream>
#include <cstdint>
#include <string>
#include <vector>

/*
 * XOR scheme - CLEAR XOR KEY1 -> CIPHER
 * CIPHER XOR CLEAR2 -> KEY2
 * PUBLISH CIPHER, KEY2
 *
 * Asymmetric Scheme -> see NSA book
 *
 *
 *
 */

// forward declarations
std::string strXOR(std::string str1, std::string str2) noexcept; // allows for bitwise XOR of diff strings
uint32_t customHash(uint32_t num); // 32-bit hash, collisions possible but shouldn't be important
std::string iterativeHash(std::string key); // allows for n-length padding from PRNG
// mersenne twister? Blum blum shub? should prolly do BBS
std::string constructSet(int s, int k); // constructs translucent set for asymmetric system
uint32_t blumblushub(uint32_t p1, uint32_t p2, uint32_t seed, uint32_t iterations); // CRNG
// maybe a global MT?



int main() {
    std::cout << "Hello, World!" << std::endl;
    return 0;
}


// ok lets build a construction of a translucent set

std::string constructSet(uint32_t s, uint32_t k) {
    uint32_t t = s + k;
    std::vector<std::string> x;
    
}

uint32_t blumblumshub(uint32_t p1, uint32_t p2, uint32_t seed, uint32_t iterations) {

}