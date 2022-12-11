#include <detector.h>

using namespace fn;

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        std::cerr << "Usage: ./fanotify <mount>" << std::endl;
        return -1;
    }

    try
    {
        EncryptorDetector detector(argv[1]);
        detector.Launch();
    }
    catch (const std::exception& e)
    {
        std::cerr << "Caught exception from EncryptorDetector: " << e.what() << std::endl;
        return -1;
    }
    
    return 0;
}
