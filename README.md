# FTP Steganography Malware

Application written in Python for sending files hidden in FTP traffic between two machines. FTP server is "infected" wih malware.py script which insert chunks of desirable file into FTP traffic. Attacker's machine is accepting incoming traffic with FTP client together with listener.py script which analyse incoming packets, finding those with hidden chunks and put them together into ready-to-read file.

In pip_requirements.txt there is list of python packages for both scripts to working properly.