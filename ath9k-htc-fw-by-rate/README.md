Built from https://github.com/qca/open-ath9k-htc-firmware.git, modifying the second ar5416_11ng_table 
(around line 220) in target_firmware/wlan/ar5416_phy.c, to move the desired rate to the top of the 
list. empirically, injection uses whatever is in the first position in the table.

	vi target_firmware/wlan/ar5416_phy.c 
	make -C target_firmware
	cp target_firmware/htc_9271.fw ${DESTDIR}/htc_9271-${RATE}Mbps.fw 
