--Install tcpdump and run

if tonumber(arg[1]) then
	nCaptureDuration = arg[1] 
end

function ExecuteShellCommand(systemcmd)
	local strOutput
	local file = io.popen(systemcmd .. ' 2>&1', 'r')
	if file ~= nil or file ~= '' then
		strOutput = file:read('*all')
	end
	file:close()
	return strOutput
end

strIsTCPDumpInstalled = ExecuteShellCommand("if which tcpdump >/dev/null; then echo -n true; else echo -n false; fi")
strIsCore = ExecuteShellCommand("if uname -a | grep -q aarch64; then echo -n true; else echo -n false; fi")
if strIsTCPDumpInstalled == "false" then
	if strIsCore == "true" then
		ExecuteShellCommand("wget -O /packages/libpcap1_1.9.1-r0.6_arm64.deb http://update2.control4.com/release/3.3.0.628678-res/pool/imx8mq-core/aarch64/libpcap1_1.9.1-r0.6_arm64.deb; dpkg -i /packages/libpcap1_1.9.1-r0.6_arm64.deb; wget -O /packages/tcpdump_4.9.3-r0.8_arm64.deb http://update2.control4.com/release/3.3.0.628678-res/pool/imx8mq-core/aarch64/tcpdump_4.9.3-r0.8_arm64.deb; dpkg -i /packages/tcpdump_4.9.3-r0.8_arm64.deb")
	else
		ExecuteShellCommand("cd /packages; wget http://influxed.net/c4/mtutest/tcpdump_4.3.0_i586v3.deb; dpkg -i tcpdump_4.3.0_i586v3.deb")
	end
end

--Get Network Interface
strNetworkInterface = ExecuteShellCommand("if sysman net iface eth0 | grep -q up=1; then echo -n eth0; else echo -n wlan0; fi")
if strNetworkInterface == nil or strNetworkInterface == "" then
	print("Unable to determine network interface.")
	os.exit()
end
hostname = ExecuteShellCommand([[echo "`hostname`" | tr -d '\n']])
print("Start time: " .. os.date())
print("Saving to /mnt/internal/" .. hostname .. "_network_capture.pcap")
	print("Running tcpdump. Press ctrl+c to stop or exit terminal to run as background task.")
	pcall(ExecuteShellCommand([[nohup tcpdump -i ]] .. strNetworkInterface .. [[ -s 65535 -B 4096 -W 20 -C 10 -p -n -w /mnt/internal/`hostname`_network_capture.pcap proto 0x32 or proto 0x02 or proto 0x76 or multicast or broadcast]]))