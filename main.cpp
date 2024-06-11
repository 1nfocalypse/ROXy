#include <iostream>
#include <string>
#include <random>
#include <fstream>
#include <queue>
#include <bitset>
#include <algorithm>

/*
 *     ____  ____ _  __     
 *    / __ \/ __ | |/ __  __
 *   / /_/ / / / |   / / / /
 *  / _, _/ /_/ /   / /_/ / 
 * /_/ |_|\____/_/|_\__, /  
 *                 /____/   
 ************************************************************************************************************************
 * ROXy is a toy encryption scheme meant to showcase Plausibly Deniable Encryption (PDE) via a symmetric and asymmetric
 * algorithm. For symmetric encryption, it utilizes a simple XOR cipher in order to encrypt text via a run-length key,
 * then uses the same cipher to derive a key that would result in a decoy plaintext. The asymmetric algorithm relies 
 * on the concept of translucent sets, and is best described in the paper linked in the README by Canetti et. al. 
 * With some modification, this concept can be made to be secure, however, this implementation is meant to simply serve
 * as a toy and Proof of Concept. For additional information regarding the mathematics, theory, and function of the
 * cryptosystems, please view the README. Thank you, and thanks for checking out ROXy!
 * 
 * Project Music Recommendation: Himiko Kikuchi - Flying Beagle (Jazz) https://www.youtube.com/watch?v=HHOn8u-c2wk
 * ROXy -> XOR reversed, y added to mimic the name of a character
 ************************************************************************************************************************
 */


/* TO DO
 * [ ] Finish construct translucent set (ASYMM SCHEME)
 * [ ] Implement encrypt/decrypt (ASYMM SCHEME)
 * [ ] TEST
 */


// forward declarations
void encrypt(); // launches encryption handler
void decrypt(); // launches decryption handler
void symmEncrypt(); // encrypts with symmetric encryption via XOR
void asymmEncrypt(); // encrypts with asymmetric encryption via translucent sets
void symmDecrypt(); // decrypts with symmetric encryption via XOR
void asymmDecrypt(); // decrypts with asymmetric encryption via translucent sets
uint32_t customHash(uint32_t num); // used for efficient 32-bit uint seed generation
std::string iterativeHash(std::string key, uint32_t tarlen); // pads a seed to tarlen bytes
std::string strXOR(std::string x, std::string y); // bitwise XOR of two n-len bitstrings
std::string strToBin(std::string str); // convert a string to binary representation
std::string binToStr(std::string str); // convert a bitstring to characters
std::string constructTranslucentSet(uint32_t s, uint32_t k); // constructs translucent set for asymmetric system
std::vector<uint32_t> blumblumshub(uint32_t p1, uint32_t p2, uint32_t seed, uint32_t iterations); // CRNG
bool isPrime(uint32_t num); // primality test for BBS verification

// ctor
// PRE: Program starts
// POST: Program halts
// WARNINGS:
// STATUS: Completed, untested
int main() {
    while (1) {
        std::string menChoiceProxy;
        std::cout << "    ____  ____ _  __     " << std::endl;
        std::cout << "   / __ \\/ __ | |/ __  __" << std::endl;
        std::cout << "  / /_/ / / / |   / / / /" << std::endl;
        std::cout << " / _, _/ /_/ /   / /_/ / " << std::endl;
        std::cout << "/_/ |_|\\____/_/|_\\__, /  " << std::endl;
        std::cout << "                /____/   " << std::endl;
        std::cout << "********************************************************" << std::endl;
        std::cout << "This is a toy implementation, and thus not secure." << std::endl;
        std::cout << "For more information, please consult the README." << std::endl;
        std::cout << "Created by 1nfocalypse: https://github.com/1nfocalypse\n\n" << std::endl;
        std::cout << "Please choose a menu option below." << std::endl;
        std::cout << "********************************************************" << std::endl;
        std::cout << "1. Encrypt" << std::endl;
        std::cout << "2. Decrypt" << std::endl;
        std::cout << "3. Quit" << std::endl;
        std::cout << "********************************************************" << std::endl;
        std::getline(std::cin, menChoiceProxy);
        int menChoice = menChoiceProxy[0] - '0';
        while (menChoice < 1 || menChoice > 3) {
            std::cout << "Invalid choice. Please select a valid option." << std::endl;
            std::cout << "********************************************************" << std::endl;
            std::cout << "1. Encrypt" << std::endl;
            std::cout << "2. Decrypt" << std::endl;
            std::cout << "3. Quit" << std::endl;
            std::cout << "********************************************************" << std::endl;
            std::getline(std::cin, menChoiceProxy);
            menChoice = menChoiceProxy[0] - '0';
        }
        switch (menChoice) {
        case 1:
            encrypt();
            break;
        case 2:
            decrypt();
            break;
        case 3:
            std::cout << "Quitting..." << std::endl;
            return 0;
        default:
            std::cout << "Unexpected Error: Uncaught menu input. Exiting..." << std::endl;
            return 1;
        }
    }
	return 0;
}

// encrypt()
// PRE:
// POST:
// WARNINGS:
// STATUS: Completed, untested
void encrypt() {
    std::string menChoiceProxy;
    std::cout << "++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << std::endl;
    std::cout << "1. Encrypt with Symmetric System" << std::endl;
    std::cout << "2. Encrypt with Asymmetric System" << std::endl;
    std::cout << "++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << std::endl;
    std::getline(std::cin, menChoiceProxy);
    int menChoice = menChoiceProxy[0] - '0';
    while (menChoice < 1 || menChoice > 2) {
        std::cout << "Invalid choice. Please select a valid option." << std::endl;
        std::cout << "++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << std::endl;
        std::cout << "1. Encrypt with Symmetric System" << std::endl;
        std::cout << "2. Encrypt with Asymmetric System" << std::endl;
        std::cout << "++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << std::endl;
        std::getline(std::cin, menChoiceProxy);
        menChoice = menChoiceProxy[0] - '0';
    }
    switch (menChoice) {
    case 1:
        symmEncrypt();
        break;
    case 2:
        asymmEncrypt();
        break;
    default:
        std::cout << "Unexpected Error: Uncaught encryption menu input. Exiting..." << std::endl;
        exit(1);
    }
}

// decrypt()
// PRE:
// POST:
// WARNINGS:
// STATUS: Completed, untested
void decrypt() {
    std::string menChoiceProxy;
    std::cout << "--------------------------------------------------------" << std::endl;
    std::cout << "1. Decrypt with Symmetric System" << std::endl;
    std::cout << "2. Decrypt with Asymmetric System" << std::endl;
    std::cout << "--------------------------------------------------------" << std::endl;
    std::getline(std::cin, menChoiceProxy);
    int menChoice = menChoiceProxy[0] - '0';
    while (menChoice < 1 || menChoice > 2) {
        std::cout << "Invalid choice. Please select a valid option." << std::endl;
        std::cout << "--------------------------------------------------------" << std::endl;
        std::cout << "1. Decrypt with Symmetric System" << std::endl;
        std::cout << "2. Decrypt with Asymmetric System" << std::endl;
        std::cout << "--------------------------------------------------------" << std::endl;
        std::getline(std::cin, menChoiceProxy);
        menChoice = menChoiceProxy[0] - '0';
    }
    switch (menChoice) {
    case 1:
        symmDecrypt();
        break;
    case 2:
        asymmDecrypt();
        break;
    default:
        std::cout << "Unexpected Error: Uncaught decryption menu input. Exiting..." << std::endl;
        exit(1);
    }
}

// symmEncrypt()
// PRE:
// POST:
// WARNINGS:
// STATUS: need to convert back to char before write
void symmEncrypt() {
    std::string path, keyPath, decoyPath;
    std::string key, decoyKey;
    std::string decoy, line;
    std::string outfileName, keyOutName;
    std::ifstream rawFile, rawKey, rawDecoy;
    std::ofstream cryptoOut, keyOut;
    std::cout << "Please enter the path to the file you would like encrypted." << std::endl;
    std::cout << "++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << std::endl;
    std::getline(std::cin, path);
    std::cout << "Please enter the name of the output file:" << std::endl;
    std::cout << "++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << std::endl;
    std::getline(std::cin, outfileName);
    keyOutName = outfileName + "-keys.rox";
    outfileName += ".rox";
    std::cout << "Please enter the path to the file containing your true key." << std::endl;
    std::cout << "++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << std::endl;
    std::getline(std::cin, keyPath);
    rawFile.open(path.c_str());
    if (rawFile.good()) {
        auto out = std::string();
        auto buf = std::string(100, '\0');
        while (rawFile.read(&buf[0], 100)) {
            out.append(buf, 0, rawFile.gcount());
        }
        out.append(buf, 0, rawFile.gcount());
        line = out;
        rawFile.close();
    }
    else {
        std::cout << "Failed to open encryption target. Returning to menu." << std::endl;
        rawFile.close();
        return;
    }
    std::cout << "Successfully read encryption target." << std::endl;
    rawKey.open(keyPath.c_str());
    if (rawKey.good()) {
        auto out = std::string();
        auto buf = std::string(100, '\0');
        while (rawKey.read(&buf[0], 100)) {
            out.append(buf, 0, rawKey.gcount());
        }
        out.append(buf, 0, rawKey.gcount());
        key = out;
        rawKey.close();
    }
    else {
        std::cout << "Failed to open key file. Returning to menu." << std::endl;
        rawKey.close();
        return;
    }
    std::cout << "Successfully read key." << std::endl;
    // decide which is longer, key or plaintext
    if (key.length() > line.length()) {
        key = key.substr(0, line.length());
    }
    else if (key.length() != line.length()) {
        key = iterativeHash(key, line.length());
    }
    key = strToBin(key);
    line = strToBin(line);
    std::string ciphertext = strXOR(key, line);
    // now we have the initial real data, the key, and the ciphertext
    // next step is fake data XOR ciphertext = K2
    std::cout << "Successfully encrypted target with given key." << std::endl;
    std::cout << "Please enter the path to the decoy cleartext." << std::endl;
    std::cout << "Note: Decoy cannot exceed length of original cleartext!" << std::endl;
    std::cout << "++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << std::endl;
    std::getline(std::cin, decoyPath);
    rawDecoy.open(decoyPath.c_str());
    if (rawDecoy.good()) {
        auto out = std::string();
        auto buf = std::string(100, '\0');
        while (rawDecoy.read(&buf[0], 100)) {
            out.append(buf, 0, rawDecoy.gcount());
        }
        out.append(buf, 0, rawDecoy.gcount());
        decoy = out;
        rawDecoy.close();
    }
    else {
        std::cout << "Failed to open decoy target. Returning to menu." << std::endl;
        rawDecoy.close();
        return;
    }
    // perform XOR operation to yield decoy key
    if (decoy.length() > ciphertext.length()) {
        std::cout << "Decoy too long! Returning to menu." << std::endl;
        return;
    }
    else if (decoy.length() < ciphertext.length()) {
        std::cout << "Proceeding with undersized decoy." << std::endl;
        std::cout << "Note: Decoy will be padded out with spaces to meet length requirements." << std::endl;
        while (decoy.length() < ciphertext.length()) {
            decoy += " ";
        }
    }
    decoy = strToBin(decoy);
    decoyKey = strXOR(decoy, ciphertext);
    std::cout << "Successfully derived decoy key." << std::endl;
    std::cout << "++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << std::endl;
    std::cout << "Successfully encrypted data." << std::endl;
    std::cout << "Writing data to files..." << std::endl;
    std::cout << "++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << std::endl;
    ciphertext = binToStr(ciphertext);
    key = binToStr(key);
    decoyKey = binToStr(decoyKey);
    cryptoOut.open(outfileName);
    cryptoOut << ciphertext;
    cryptoOut.close();
    keyOut.open(keyOutName);
    keyOut << key;
    keyOut << "\n";
    keyOut << decoyKey;
    keyOut.close();
    std::cout << "Successfully wrote data." << std::endl;
    std::cout << "Ciphertext written to: " << outfileName << std::endl;
    std::cout << "Keys written to: " << keyOutName << std::endl;
    std::cout << "First key is legitimate, second is for the decoy." << std::endl;
    std::cout << "Retain original keyfile. Otherwise, data loss may occur." << std::endl;
    std::cout << "++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << std::endl;
}

// symmDecrypt()
// PRE:
// POST:
// WARNINGS:
// STATUS:
void symmDecrypt() {
    std::string path;
    std::string line;
    std::string outfileName, keyfileName;
    std::string menChoiceProxy;
    std::string key, ciphertext, cleartext;
    std::ifstream keyRaw, cipherRaw;
    std::ofstream outRaw;
    std::cout << "Please enter the path to the file you would like decrypted." << std::endl;
    std::cout << "--------------------------------------------------------" << std::endl;
    std::getline(std::cin, path);
    if (path.find(".rox") == std::string::npos) {
        std::cout << "Valid target for decryption not found." << std::endl;
    }
    std::cout << "Please enter the name of the output file with extension:" << std::endl;
    std::cout << "--------------------------------------------------------" << std::endl;
    std::getline(std::cin, outfileName);
    std::cout << "Please enter the path to your key file." << std::endl;
    std::cout << "--------------------------------------------------------" << std::endl;
    std::getline(std::cin, keyfileName);
    std::cout << "Please select an option below:" << std::endl;
    std::cout << "--------------------------------------------------------" << std::endl;
    std::cout << "1. Decrypt with Real Key" << std::endl;
    std::cout << "2. Decrypt with Decoy Key" << std::endl;
    std::cout << "--------------------------------------------------------" << std::endl;
    std::getline(std::cin, menChoiceProxy);
    int menChoice = menChoiceProxy[0] - '0';
    while (menChoice < 1 || menChoice > 2) {
        std::cout << "Invalid choice. Please select a valid option." << std::endl;
        std::cout << "--------------------------------------------------------" << std::endl;
        std::cout << "1. Decrypt with Real Key" << std::endl;
        std::cout << "2. Decrypt with Decoy Key" << std::endl;
        std::cout << "--------------------------------------------------------" << std::endl;
        std::getline(std::cin, menChoiceProxy);
        menChoice = menChoiceProxy[0] - '0';
    }
    keyRaw.open(keyfileName);
    if (!keyRaw.is_open()) {
        std::cout << "Error: Unable to read keys." << std::endl;
        keyRaw.close();
        return;
    }
    std::string key;
    // First key is legitimate, second is for the decoy.
    if (menChoice == 1) {
        // read in real key
        std::getline(keyRaw, key);
    }
    else {
        // unwrapped 2x loop to pull fake key
        std::getline(keyRaw, key);
        std::getline(keyRaw, key);
    }
    // close keyRaw
    keyRaw.close();
    cipherRaw.open(path);
    // read cipher
    std::getline(cipherRaw, ciphertext);
    cipherRaw.close();
    key = strToBin(key);
    ciphertext = strToBin(ciphertext);
    cleartext = strXOR(key, ciphertext);
    cleartext = binToStr(cleartext);
    // write to output file
    std::cout << "Writing cleartext to " << outfileName << "..." << std::endl;
    outRaw.open(outfileName);
    outRaw << cleartext;
    outRaw.close();
    std::cout << "Data written." << std::endl;
    std::cout << "--------------------------------------------------------" << std::endl;
}

// asymmEncrypt()
// PRE:
// POST:
// WARNINGS:
// STATUS:
void asymmEncrypt() {

}

// asymmDecrypt()
// PRE:
// POST:
// WARNINGS:
// STATUS:
void asymmDecrypt() {

}

// customHash(int32_t num)
// PRE: linear equation of string sum is passed
// POST: 32 bits of hashed data yielded
// WARNINGS: collisions may occur - collision resistance not tested
// STATUS: Completed, tested.
// Attribution: sourced from https://www.cs.ubc.ca/~rbridson/docs/schechter-sca08-turbulence.pdf
uint32_t customHash(uint32_t num) {
    num = num ^ 2747636419;
    num = (num * 2654435769) % UINT32_MAX;
    num = num ^ (num >> 16);
    num = (num * 2654435769) % UINT32_MAX;
    num = num ^ (num >> 16);
    num = (num * 2654435769) % UINT32_MAX;
    return num;
}

// iterativeHash(std::string key, uint32_t tarlen)
// PRE: key pas sed as a string
// POST: key padded to n bytes with deterministic pseudorandomness
// WARNINGS: collisions may occur - collision resistance not tested
// STATUS: Completed, tested.
std::string iterativeHash(std::string key, uint32_t tarlen) {
    if (key.length() == tarlen) {
        return key;
    }
    uint32_t baseNum(0);
    // this should fix the ordering issue
    for (size_t i = 0; i < key.length(); ++i) {
        baseNum += static_cast<uint32_t>(key[i]) * i;
    }
    // hash basenum
    uint32_t base = customHash(baseNum);
    std::mt19937 gen(base); // seed the generator
    std::uniform_int_distribution<> distr(32, 255);
    char randomAppend = static_cast<char>(distr(gen));
    key += randomAppend;
    return iterativeHash(key, tarlen);
}

// strXOR(std::string r, std::string k)
// PRE: r, k are 4 char strings representing binary numbers
// POST: result of r XOR k is returned.
// WARNING: Different length inputs may yield bad results
// STATUS: Completed, tested
std::string strXOR(std::string r, std::string k) {
    std::string retStr = "";
    for (size_t i = 0; i < r.length(); i++) {
        if (r[i] == '1' || k[i] == '1') {
            if (r[i] == '1' && k[i] == '1') {
                retStr.append("0");
            }
            else {
                retStr.append("1");
            }
        }
        else {
            retStr.append("0");
        }
    }
    return retStr;
}

// strToBin(std::string str)
// PRE: A string is passed containing valid characters
// POST: A bitstring of those characters is returned
// WARNING: Invalid data types may be corrupted via this process.
// STATUS: Completed, untested
std::string strToBin(std::string str) {
    std::string binStr = "";
    for (uint32_t i = 0; i < str.length(); ++i) {
        binStr.append(std::bitset<8>(str[i]).to_string());
    }
    return binStr;
}

// binToStr(std::string str)
// PRE: A string of bits is passed
// POST: A char converted string is returned
// WARNING: Invalid data types may be corrupted via this process.
// STATUS: Completed, untested
std::string binToStr(std::string str) {
    std::string retStr;
    while (str.length() > 8) {
        int num = std::stoi(str.substr(0, 8), 0, 2);
        char myChar = static_cast<char>(num);
        retStr += myChar;
        str = str.substr(9, str.length());
    }
    return retStr;
}

// constructTranslucentSet(uint32_t s, uint32_t k)
// PRE: Two unsigned integers passed denoting size
// POST: A set is constructed per Canetti et. al. construction 2
// WARNING: 
// STATUS: Incomplete, untested
std::string constructTranslucentSet(uint32_t s, uint32_t k) {
    uint32_t t = s * k;

    return "";
}

// blumblumshub(uint32_t p1, uint32_t p2, uint32_t seed, uint32_t iterations)
// PRE: primes p1, p2, 32 bit uint seed, and number of iterations passed
// POST: A CRNG number c is returned: c in [0, UINT32_MAX]
// WARNING: Not actually secure; numbers too small.
// STATUS: Complete, untested
std::vector<uint32_t> blumblumshub(uint32_t p1, uint32_t p2, uint32_t seed, uint32_t iterations) {
    std::vector<uint32_t> empty;
    if ((p1 % 4) != 3) {
        std::cout << "Error: BBS p1 does not meet residuosity standards." << std::endl;
        return empty;
    }
    if ((p2 % 4) != 3) {
        std::cout << "Error: BBS p2 does not meet residuosity standards." << std::endl;
        return empty;
    }
    // check primality p1 / 2, p2 / 2
    if (!isPrime(p1 / 2)) {
        std::cout << "Error: BBS p1 does not meet safety standards (has large GCD)." << std::endl;
        return empty;
    }
    if (!isPrime(p2 / 2)) {
        std::cout << "Error: BBS p2 does not meet safety standards (has large GCD)." << std::endl;
        return empty;
    }
    uint32_t n = p1 * p2;
    std::vector<uint32_t> numbers;
    for (uint32_t i = 0; i < iterations; ++i) {
        seed = (seed * seed) % n;
        if (std::find(numbers.begin(), numbers.end(), seed) != numbers.end()) {
            std::cout << "Error: BBS looping at " << i << " steps." << std::endl;
            return numbers;
        }
        numbers.push_back(seed);
    }
    return numbers;
}

// isPrime(uint32_t num)
// PRE: number num passed
// POST: Boolean value returned if prime or not
// WARNING: overflow may occur
// STATUS: Complete, untested
bool isPrime(uint32_t num) {
    if (num == 2 || num == 3) {
        return true;
    }
    if (num <= 1 || num % 2 == 0 || num % 3 == 0) {
        return false;
    }
    for (uint32_t i = 5; (i * i) <= num; i += 6) {
        if ((num % i) == 0 || (num % (i + 2)) == 0) {
            return false;
        }
    }
    return true;
}