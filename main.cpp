#include <iostream>
#include <string>
#include <random>
#include <fstream>
#include <queue>
#include <bitset>
#include <algorithm>
#include <cstdlib>
#include <time.h>
#include <cmath>

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


// forward declarations
void encrypt(); // launches encryption handler
void decrypt(); // launches decryption handler
void symmEncrypt(); // encrypts with symmetric encryption via XOR
void asymmEncrypt(); // encrypts with asymmetric encryption via translucent sets
void symmDecrypt(); // decrypts with symmetric encryption via XOR
void asymmDecrypt(); // decrypts with asymmetric encryption via translucent sets
uint32_t customHash(uint32_t num); // used for efficient 32-bit uint seed generation
uint32_t invertRSA(uint32_t prev, uint32_t p, uint32_t q); // inverts the current value of x0 via trapdoor permutation
uint32_t rsa(uint32_t p, uint32_t q, uint32_t seed); // RSA for round encoding
std::string iterativeHash(std::string key, uint32_t tarlen); // pads a seed to tarlen bytes
std::string strXOR(std::string x, std::string y); // bitwise XOR of two n-len bitstrings
std::string strToBin(std::string str); // convert a string to binary representation
std::string binToStr(std::string str); // convert a bitstring to characters
std::string constructTranslucentElement(); // constructs element of translucent set for asymmetric system
std::string randomAsymmElement(); // returns a pseudorandom non-translucent 64 bit number as a bitstring
std::vector<uint32_t> blumblumshub(uint32_t p1, uint32_t p2, uint32_t seed, uint32_t iterations); // CPRNG
bool isPrime(uint32_t num); // primality tester
bool hcpredicate(uint32_t number); // hardcore predicate for RSA enciphering, defined as a sum over GF2 of all elements.
bool isTranslucentElement(std::string bitstr, uint32_t p, uint32_t q); // determines if a 64 bit bitstring is an element of St, returning 1 if it is, and 0 otherwise.


// main()
// PRE: Program starts
// POST: Program halts
// WARNINGS: None
// STATUS: Completed, tested
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
// PRE: Encrypt menu choice selected
// POST: User displayed appropriate asymmetric or symmetric enciphering options
// WARNINGS: None
// STATUS: Completed, tested
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
// PRE: Decrypt menu choice selected
// POST: User displayed appropriate asymmetric or symmetric deciphering options
// WARNINGS: None
// STATUS: Completed, tested
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
// PRE: User selects to symmetrically encrypt
// POST: Keys and ciphertext outputted
// WARNINGS: Failures to read or open targets may alter behavior.
// STATUS: completed, tested
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
    if (key.length() > line.length()) {
        key = key.substr(0, line.length());
    }
    else if (key.length() != line.length()) {
        key = iterativeHash(key, line.length());
    }
    std::string asciiKey = key;
    key = strToBin(key);
    line = strToBin(line);
    std::string ciphertext = strXOR(key, line);
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
    if (decoy.length() > asciiKey.length()) {
        std::cout << "Decoy too long! Returning to menu." << std::endl;
        return;
    }
    else if (decoy.length() < asciiKey.length()) {
        std::cout << "Proceeding with undersized decoy." << std::endl;
        std::cout << "Note: Decoy will be padded out with spaces to meet length requirements." << std::endl;
        while (decoy.length() < asciiKey.length()) {
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
// PRE: Symmetric decryption option selected
// POST: Selected ciphertext decrypted with selected option's key
// WARNINGS: Failures to read or open targets may alter behavior.
// STATUS: completed, tested
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
    if (menChoice == 1) {
        std::getline(keyRaw, key);
    }
    else {
        std::getline(keyRaw, key);
        std::getline(keyRaw, key);
    }
    keyRaw.close();
    cipherRaw.open(path);
    if (cipherRaw.good()) {
        auto out = std::string();
        auto buf = std::string(100, '\0');
        while (cipherRaw.read(&buf[0], 100)) {
            out.append(buf, 0, cipherRaw.gcount());
        }
        out.append(buf, 0, cipherRaw.gcount());
        ciphertext = out;
        cipherRaw.close();
    }
    else {
        std::cout << "Failed to open cipher target. Returning to menu." << std::endl;
        cipherRaw.close();
        return;
    }
    key = strToBin(key);
    ciphertext = strToBin(ciphertext);
    cleartext = strXOR(key, ciphertext);
    cleartext = binToStr(cleartext);
    std::cout << "Writing cleartext to " << outfileName << "..." << std::endl;
    outRaw.open(outfileName);
    outRaw << cleartext;
    outRaw.close();
    std::cout << "Data written." << std::endl;
    std::cout << "--------------------------------------------------------" << std::endl;
}

// asymmEncrypt()
// PRE: User selected to asymmetrically encrypt
// POST: Ciphertext outputted
// WARNINGS: None
// STATUS: completed, tested
void asymmEncrypt() {
    std::string path;
    std::string outfileName;
    std::string line;
    std::ifstream rawFile;
    std::ofstream cryptoOut;
    std::cout << "Please enter the path to the file you would like encrypted." << std::endl;
    std::cout << "++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << std::endl;
    std::getline(std::cin, path);
    std::cout << "Please enter the name of the output file:" << std::endl;
    std::cout << "++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << std::endl;
    std::getline(std::cin, outfileName);
    outfileName += ".roxy";
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
        std::cout << "Unable to open encryption target. Returning to menu..." << std::endl;
        rawFile.close();
        return;
    }
    std::string bitstr;
    for (uint32_t i = 0; i < line.length(); ++i) {
        bitstr += std::bitset<8>(line[i]).to_string();
    }
    std::string ciphertext;
    for (uint32_t i = 0; i < bitstr.length(); ++i) {
        if (bitstr[i] == '1') {
            ciphertext += constructTranslucentElement();
        }
        else {
            ciphertext += randomAsymmElement();
        }
    }
    ciphertext = binToStr(ciphertext);
    cryptoOut.open(outfileName.c_str());
    cryptoOut << ciphertext;
    cryptoOut.close();
    std::cout << "Successfully wrote data." << std::endl;
    std::cout << "Ciphertext written to: " << outfileName << std::endl;
    std::cout << "Retain original ciphertext outfile. Otherwise, data loss may occur." << std::endl;
    std::cout << "++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << std::endl;
}

// asymmDecrypt()
// PRE: User selected to decrypt asymmetrically encrypted data
// POST: Cleartext restored
// WARNINGS: 1/2^32 chance of a bitflip occuring - retransmission may be required
// STATUS: Completed, tested
void asymmDecrypt() {
    uint32_t p = 6827, q = 4079;
    std::string path;
    std::string outfileName;
    std::string line;
    std::ifstream rawFile;
    std::ofstream clearOut;
    std::cout << "Please enter the path to the file you would like decrypted." << std::endl;
    std::cout << "--------------------------------------------------------" << std::endl;
    std::getline(std::cin, path);
    std::cout << "Please enter the name of the output file:" << std::endl;
    std::cout << "--------------------------------------------------------" << std::endl;
    std::getline(std::cin, outfileName);
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
    line = strToBin(line);
    std::string bitBuffer, out;
    for (uint32_t i = 0; i < (line.length() / 64); ++i) {
        bitBuffer = line.substr(i * 64, 64);
        if (isTranslucentElement(bitBuffer, p, q)) {
            out += '1';
        }
        else {
            out += '0';
        }
    }
    std::string outText = binToStr(out);
    std::cout << "Writing cleartext to " << outfileName << "..." << std::endl;
    clearOut.open(outfileName);
    clearOut << outText;
    clearOut.close();
    std::cout << "Data written." << std::endl;
    std::cout << "--------------------------------------------------------" << std::endl;
}

// customHash(int32_t num)
// PRE: 32 bit integer is passed
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
// STATUS: Completed, tested
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
// STATUS: Completed, tested
std::string binToStr(std::string str) {
    std::string retStr;
    while (str.length() >= 8) {
        std::string testing = str.substr(0, 8);
        int num = std::stoi(str.substr(0, 8), 0, 2);
        char myChar = static_cast<char>(num);
        retStr += myChar;
        str = str.substr(8, str.length()-8);
    }
    return retStr;
}

// rsa(uint32_t p, uint32_t q, uint32_t seed)
// PRE: User is encrypting asymmetrically
// POST: valid RSA ciphertext returned
// WARNINGS: Large quantities of p,q,seed may result in overflow
// STATUS: Completed, tested
uint32_t rsa(uint32_t p, uint32_t q, uint32_t seed) {
    uint32_t n = p * q;
    uint32_t phi = (p - 1) * (q - 1);
    uint32_t e = 17;
    
    uint64_t ciphertext = 1;
    for (uint32_t i = 0; i < e; ++i) {
        ciphertext = (ciphertext * seed) % n;
    }

    return ciphertext;
}

// constructTranslucentElement()
// PRE: 1 is selected for encoding
// POST: A set element is constructed per Canetti et. al. construction 2
// WARNING: Time-based seeding produces vulnerabilities, should be quelled with BBS
// Small p,q are easily breakable
// STATUS: completed, tested
std::string constructTranslucentElement() {
    uint32_t t = 64;
    uint32_t s = 32, k = 32; // P(0 dec as 1) = 1 / 2^32 apprx .000000000232, 2 bits/10 billion, approx 1 bitflip per 625 MB is E
    uint32_t p = 6827, q = 4079;
    // done to illustrate RSA functionality - in reality, public key is only predicate, e, n
    // In practicum, users should use p,q of cryptographic size (256/512 bits), along with a different seeding algorithm
    uint32_t seed = customHash(time(0));
    // original x0
    seed = blumblumshub(p, q, seed, 17)[time(0) % 17];
    uint32_t randNum = seed;
    std::vector<bool> predicates;
    std::vector<bool> ciphertext;

    for (uint32_t i = 0; i < k; ++i) {
        if (i != 0) {
            randNum = rsa(p,q,randNum);
        }
        predicates.push_back(hcpredicate(randNum));
    }
    std::string x0 = std::bitset<32>(randNum).to_string();
    std::string predicateStr;
    for (uint32_t i = 0; i < k; ++i) {
        if (predicates[i] == true) {
            predicateStr += "1";
        }
        else {
            predicateStr += "0";
        }
    }
    std::string bitstring = x0 + predicateStr;
    return bitstring;
}

// randomAsymmElement()
// PRE: 0 is selected for encoding
// POST: A random 64 bit bitstring is returned
// WARNING: Time-based seeding produces vulnerabilities, should be quelled with BBS
// Small p,q are easily breakable
// STATUS: completed, tested
std::string randomAsymmElement() {
    uint32_t seed = time(0);
    uint32_t left, right;
    std::string retstr;
    left = customHash(seed);
    right = customHash(left);
    left = blumblumshub(83, 5639, left, 17)[left % 17];
    std::string strseed, strleft, strright, newl, newr;
    strleft = std::bitset<32>(left).to_string();
    strright = std::bitset<32>(right).to_string();
    strseed = std::bitset<32>(seed).to_string();
    newl = strXOR(strright, strXOR(strleft, strseed));
    newr = strleft;
    strleft = newl;
    strright = newr;
    retstr = strleft + strright;
    return retstr;
}

// bool hcpredicate(uint32_t number) {
// PRE: a translucent set is selected for encoding/testing for decoding
// POST: A parity bit is returned based on a bitstring length sum over GF2
// WARNING: None
// STATUS: completed, tested
bool hcpredicate(uint32_t number) {
    std::string num = std::bitset<32>(number).to_string();
    int parity = 0;
    for (size_t i = 0; i < num.length(); ++i) {
        if (num[i] == '1') {
            parity = (parity + 1) % 2;
        }
    }
    return static_cast<bool>(parity);
}

// blumblumshub(uint32_t p1, uint32_t p2, uint32_t seed, uint32_t iterations)
// PRE: primes p1, p2, 32 bit uint seed, and number of iterations passed
// POST: A CRNG number c is returned: c in [0, UINT32_MAX]
// WARNING: Not actually secure; numbers too small.
// STATUS: Complete, tested
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
// STATUS: Complete, tested
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

// isTranslucentElement(uint32_t bitstr, uint32_t p, uint32_t q)
// PRE: bitstrings + trapdoor primes p,q passed
// POST: Boolean value returned if an element or not
// WARNING: functions only as well as invertRSA, which may overflow depending on p,q
// STATUS: Complete, tested
bool isTranslucentElement(std::string bitstr, uint32_t p, uint32_t q) {
    std::string predicatesStr = bitstr.substr(32, 32);
    std::string x0 = bitstr.substr(0, 32);
    std::reverse(predicatesStr.begin(), predicatesStr.end());
    bool predicates[32];
    for (uint32_t i = 0; i < 32; ++i) {
        if (predicatesStr[i] == '1') {
            predicates[i] = true;
        }
        else {
            predicates[i] = false;
        }
    }
    long long int signedTmp = std::stoll(x0, 0, 2);
    uint32_t unsInt = static_cast<uint32_t>(signedTmp);
    for (uint32_t i = 0; i < 32; ++i) {
        if (hcpredicate(unsInt) == predicates[i]) {
            unsInt = invertRSA(unsInt, p, q);
            if (unsInt == 0) {
                std::cout << "Error: Unable to invert x0." << std::endl;
            }
        }
        else {
            return false;
        }
    }
    return true;
}

// invertRSA(uint32_t prev, uint32_t p, uint32_t q)
// PRE: x0 as an integer + trapdoor primes p,q passed
// POST: deciphered value returned given args
// WARNING: may overflow depending on p, q, seed
// STATUS: Complete, tested
uint32_t invertRSA(uint32_t prev, uint32_t p, uint32_t q) {
    uint32_t n = p * q;
    uint32_t phi = (p - 1) * (q - 1);
    uint32_t e = 17;
    long long int prevrow[7];
    long long int currow[7];
    prevrow[0] = phi;
    prevrow[1] = e;
    prevrow[2] = phi / e;
    prevrow[3] = phi - (prevrow[2] * prevrow[1]);
    prevrow[4] = 0;
    prevrow[5] = 1;
    prevrow[6] = prevrow[4] - (prevrow[5] * prevrow[2]);

    while (prevrow[3] != 0) {
        currow[0] = prevrow[1];
        currow[1] = prevrow[3];
        currow[2] = currow[0] / currow[1];
        currow[3] = currow[0] % (currow[1] * currow[2]);
        currow[4] = prevrow[5];
        currow[5] = prevrow[6];
        currow[6] = currow[4] - (currow[5] * currow[2]);
        for (uint32_t i = 0; i < 7; ++i) {
            prevrow[i] = currow[i];
        }
    }
    if (prevrow[5] < 0) {
        prevrow[5] = phi + prevrow[5];
    }
    uint32_t d = static_cast<uint32_t>(prevrow[5]);
    unsigned long long int inversion = 1;
    for (uint32_t i = 0; i < d; ++i) {
        inversion = (inversion * prev) % n;
        if (inversion == 0) {
            std::cout << "ERROR: INVERSION FOUND TO BE 0 AT ITERATION " << i << std::endl;
        }
    }
    return static_cast<uint32_t>(inversion);;
}  
