#include <iostream>
#include <string>


int main() {
    while (1) {
        std::string menChoiceProxy;
        std::cout << "    _   __     _ __  __             _  ______  ____ " << std::endl;
        std::cout << "   / | / ___  (_/ /_/ /_  ___  ____| |/ / __ \\/ __ \\" << std::endl;
        std::cout << "  /  |/ / _ \\/ / __/ __ \\/ _ \\/ ___|   / / / / /_/ /" << std::endl;
        std::cout << " / /|  /  __/ / /_/ / / /  __/ /  /   / /_/ / _, _/ " << std::endl;
        std::cout << "/_/ |_/\\___/_/\\__/_/ /_/\\___/_/  /_/|_\\____/_/ |_|  " << std::endl;
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
            mySim.run();
            break;
        case 2:
            mySim.configure();
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