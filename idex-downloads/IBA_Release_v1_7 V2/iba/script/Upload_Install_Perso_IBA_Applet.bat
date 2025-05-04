@echo Delete all applets
idex-test.exe --port PCSC-C --applet_config delete_all_applets --en_applet_auth=readkeys

@echo Upload applets
idex-test.exe --port PCSC-C --applet_config upload_applet ../../se-sdk/applets/iba/iba/applet/com.idex.iba.service.cap --en_applet_auth=readkeys 
idex-test.exe --port PCSC-C --applet_config upload_applet ../../se-sdk/applets/iba/iba/applet/com.idex.iba.cap --en_applet_auth=readkeys 
idex-test.exe --port PCSC-C --applet_config upload_applet ../../se-sdk/applets/iba/ibaclient/applet/com.idex.client.cap --en_applet_auth=readkeys 

@echo Install applets
idex-test.exe --port PCSC-C --applet_config install iba_p iba --en_applet_auth=readkeys 
idex-test.exe --port PCSC-C --applet_config install ibac_p ibac --en_applet_auth=readkeys 


@echo "Store Data : DGI 9000 / Enroll PIN (1234)"
idex-test.exe --port PCSC-C --iba_set_perso 0x9000 24 12 34 FF FF FF FF FF --en_applet_select=iba --en_applet_auth=readkeys

@echo "Store Data : DGI 9008 / Enroll PIN PTL (3)"
idex-test.exe --port PCSC-C --iba_set_perso 0x9008 03 --en_applet_select=iba --en_applet_auth=readkeys

@echo "Store Data : DGI 9009 / Enroll PIN PTR"
idex-test.exe --port PCSC-C --iba_set_perso 0x9009 00 --en_applet_select=iba --en_applet_auth=readkeys

@echo "Store Data : DGI 9011 / Enable Sleeve Enroll"
idex-test.exe --port PCSC-C --iba_set_perso 0x9011 C0 --en_applet_select=iba --en_applet_auth=readkeys

@echo "Store Data : DGI 9013 / Enable APDU Enroll"
idex-test.exe --port PCSC-C --iba_set_perso 0x9013 80 --en_applet_select=iba --en_applet_auth=readkeys

@echo "Store Data : DGI 9015 / Set Unlimited Enrollment Attempts"
idex-test.exe --port PCSC-C --iba_set_perso 0x9015 FF --en_applet_select=iba --en_applet_auth=readkeys

@echo "Store Data : DGI 9106 / APDU and Shareable interface enabled"
idex-test.exe --port PCSC-C --iba_set_perso 0x9106 03 last_store_data --en_applet_select=iba --en_applet_auth=readkeys

@echo List all applets
idex-test.exe --port PCSC-C --applet_config list --en_applet_auth=readkeys
