Purpose
=======
Allow for different data recording mode in order to track individual visits, 
rather than remembering all MAC addresses forever. This is done to allow for
better traffic metrics (who comes in range at what times, and when they leave).

Usage
=====
Add flag to enable forgetful mode with an adjustable timout. 
Airodump-ng will collect and report data in the same fashion as before, however
when it receives a packet, if `current_time - time_last_seen > timeout` then 
it will create a new entry rather than simply updating the old one.
This creates duplicate entries for MAC addresses that are seen multiple times.
