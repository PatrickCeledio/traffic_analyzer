traffic_analyzer by Patrick Celedio
Written in C++
Dev Environment: Ubuntu 22.04.1 LTS on Microsoft Hyper-V
Machine: Alienware m17 R3


How to run traffic_analyzer: 

Run commands on their own terminals
    - First time run: 
        sudo g++ trafficCapture.cpp frameio.cpp util.cpp -o out && sudo ./out

    - Second time run: 
        sudo rm ./out && sudo g++ trafficCapture.cpp frameio.cpp util.cpp -o out && sudo ./out


