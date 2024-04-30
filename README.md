# TANGOCAN

This is the repository for our Computer Information Security course project. Our Project is CAN bus analysis and Vulnerability detection in Vehicle Network

# Attacker
This contains attacker simulation.
We can change the attacker attack in config/convert_jobs.json.
Attacks:
1. CONST
2. ADD-INCR
3. ADD-DECR
4. NEG_OFFSET
5. POS_OFFSET
6. REPLAY

We have modification and injection attacks.
Use, dataset-generator.py in attacker/src to generate the malicious CAN log data in output/S-1-1/
We can do Double or CONST message injection and modification and get a compromised CAn messages in  this format [text](attacker/output/S-1-1/S-1-1-malicious-DOUBLE-msg-mod-0x110-NEG_OFFSET-0.4-0.6-0x410-NEG_OFFSET-0.4-0.6.log) [Example for NEG_OFFSET, CHANGE attack in config/convert_jobs.json to simulate other attack scenario.]

# Defense
For defense part we use the benign and malicious CAN logs generated in attacker/output with pipeline/Main.py. Script description is given in https://github.com/brent-stone/CAN_Reverse_Engineering.

python3 Pipeline/Main.py --can-utils --filename  ../attacker/output/S-1-1/S-1-1-malicious-DOUBLE-msg-mod-0x110-NEG_OFFSET-0.4-0.6-0x410-NEG_OFFSET-0.4-0.6.log 

We get Tang time series signature of the benign and attack scenario in defense/figure.