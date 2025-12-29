#include <windows.h>
#include <vector>
#include <random>
#include <iostream>
#include <string>
#include <iomanip>
#include <algorithm>
#include "ANTINJ.h"

int main() {
    StartManualMapDetection();
    
    std::cout << "STARTED...\n";
    
    while (true) {
        Sleep(1000);
    }
    
    return 0;
}
