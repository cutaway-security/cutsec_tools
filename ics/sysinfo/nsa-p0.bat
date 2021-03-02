
::###############################
::# nsa-p0.bat - a batch script for following the NSA IAD Position Zero
::#             manual information gathering process.
::###############################

::###############################
::# License: 
::# Copyright (c) 2021, Cutaway Security, Inc. <don@cutawaysecurity.com>
::#  
::# nsa-p0.bat is free software: you can redistribute it and/or modify
::# it under the terms of the GNU General Public License as published by
::# the Free Software Foundation, either version 3 of the License, or
::# (at your option) any later version.
::# 
::# nsa-p0.bat is distributed in the hope that it will be useful,
::# but WITHOUT ANY WARRANTY; without even the implied warranty of
::# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
::# GNU General Public License for more details.
::# You should have received a copy of the GNU General Public License
::# along with this program.  If not, see <http://www.gnu.org/licenses/>.
::# Point Of Contact:    Don C. Weber <don@cutawaysecurity.com>
::###############################

::###############################
::# NSA IAD Position Zero Script.
::###############################

::### Create storage directory for files in users Temp directory at %temp% ###
set "nsa_p0_dest=nsa-p0-%date:~10,4%%date:~4,2%%date:~7,2%%time::=-%"
if not exist %temp%\%nsa_p0_dest% mkdir %temp%\%nsa_p0_dest%
echo "NSA Position 0 Files will be written to" %temp%\%nsa_p0_dest%
::###############################


::### Create individual output files for future comparision ###
set "sysinfo_file=%temp%\%nsa_p0_dest%\%ComputerName%-sysinfo.txt"
set "netstart_file=%temp%\%nsa_p0_dest%\%ComputerName%-netstart_file.txt"
set "tasklist_file=%temp%\%nsa_p0_dest%\%ComputerName%-tasklist_file.txt"
set "dlllist_file=%temp%\%nsa_p0_dest%\%ComputerName%-dlllist_file.txt"
set "svclist_file=%temp%\%nsa_p0_dest%\%ComputerName%-svclist_file.txt"
set "netstat_ano_file=%temp%\%nsa_p0_dest%\%ComputerName%-netstat_ano_file.txt"
set "netstat_anob_file=%temp%\%nsa_p0_dest%\%ComputerName%-netstat_anob_file.txt"
set "netstat_nr_file=%temp%\%nsa_p0_dest%\%ComputerName%-netstat_nr_file.txt"
set "netuser_file=%temp%\%nsa_p0_dest%\%ComputerName%-netuser_file.txt"
set "netsession_file=%temp%\%nsa_p0_dest%\%ComputerName%-netsession_file.txt"
set "wmic_user_list_full_file=%temp%\%nsa_p0_dest%\%ComputerName%-wmic_user_list_full_file.txt"
set "wmic_startup_list_full_file=%temp%\%nsa_p0_dest%\%ComputerName%-wmic_startup_list_full_file.txt"
set "wmic_process_paths_file=%temp%\%nsa_p0_dest%\%ComputerName%-wmic_process_paths_file.txt"
set "wmic_netlogin_file=%temp%\%nsa_p0_dest%\%ComputerName%-wmic_netlogin_file.txt"
set "wmic_netproto_file=%temp%\%nsa_p0_dest%\%ComputerName%-wmic_netproto_file.txt"
set "wmic_service_descr_file=%temp%\%nsa_p0_dest%\%ComputerName%-wmic_service_descr_file.txt"
set "wmic_service_info_file=%temp%\%nsa_p0_dest%\%ComputerName%-wmic_service_info_file.txt"
set "wmic_qfe_file=%temp%\%nsa_p0_dest%\%ComputerName%-wmic_qfe_file.txt"
::###############################

::### NSA IAD Position Zero Commands ###
systeminfo >> %sysinfo_file%
net start >> %netstart_file%
tasklist >> %tasklist_file%
tasklist /m /fo list >> %dlllist_file%
tasklist /svc >> %svclist_file%
netstat -ano >> %netstat_ano_file%
netstat -anob >> %netstat_anob_file%
netstat -nr >> %netstat_nr_file%
net user >> %netuser_file%
net session >> %netsession_file%
wmic useraccount list full >> %wmic_user_list_full_file%
wmic startup list full >> %wmic_startup_list_full_file%
wmic process get description, processid, executablepath, pagefileusage >> %wmic_process_paths_file%
wmic netlogin get lastlogon, numberoflogons, name >> %wmic_netlogin_file%
wmic netprotocol get description, name, supportsbroadcasting, supportsmulticasting >> %wmic_netproto_file%
wmic service get caption, description >> %wmic_service_descr_file%
wmic service get caption, startmode, started, pathname, startname, state >> %wmic_service_info_file%
wmic qfe >> %wmic_qfe_file%
::###############################