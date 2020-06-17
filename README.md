# volatility-bam
Volatility plugin to parse Bam registry data

# Why is bam useful?

Bam is a service in Windows 10 that appeared after the Fall Creators update – version 1709. It provides the full path of the executable file that was run on the system and last execution date/time. 

# Usage
```
vol.py --plugins="/yourpathto/volatility-bam/" --profile=Win10x64_18362 -f mem.img bam
```
```
Volatility Foundation Volatility Framework 2.6.1
SID                                           Username               Executable                                                                         LastExecutionTime
S-1-5-21-779300877-3336791673-4128505751-1001 testuser               Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy                            2020-05-04 06:18:33.026546
S-1-5-21-779300877-3336791673-4128505751-1001 testuser               Microsoft.Windows.Cortana_cw5n1h2txyewy                                            2020-05-04 06:18:33.026546
S-1-5-21-779300877-3336791673-4128505751-1001 testuser               Microsoft.MicrosoftEdge_8wekyb3d8bbwe                                              2020-05-04 06:18:33.026546
S-1-5-21-779300877-3336791673-4128505751-1001 testuser               Microsoft.WindowsStore_8wekyb3d8bbwe                                               2020-05-04 06:18:33.011586
S-1-5-21-779300877-3336791673-4128505751-1001 testuser               microsoft.windowscommunicationsapps_8wekyb3d8bbwe                                  2020-05-04 06:18:33.011586
S-1-5-21-779300877-3336791673-4128505751-1001 testuser               Microsoft.WindowsCalculator_8wekyb3d8bbwe                                          2020-05-04 06:18:33.026546
S-1-5-21-779300877-3336791673-4128505751-1001 testuser               \Device\HarddiskVolume4\Windows\System32\cmd.exe                                   2020-05-04 06:18:03.710760
S-1-5-21-779300877-3336791673-4128505751-1001 testuser               \Device\HarddiskVolume4\Program Files (x86)\Parallels\Parallels Tools\prl_cc.exe   2020-05-04 06:18:32.948436
S-1-5-21-779300877-3336791673-4128505751-1000 ellie                  Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy                            2020-06-08 01:16:23.067932
S-1-5-21-779300877-3336791673-4128505751-1000 ellie                  \Device\HarddiskVolume4\Windows\explorer.exe                                       2020-06-08 01:16:19.130656
S-1-5-21-779300877-3336791673-4128505751-1000 ellie                  Microsoft.Windows.Cortana_cw5n1h2txyewy                                            2020-06-08 05:21:23.304496
S-1-5-21-779300877-3336791673-4128505751-1000 ellie                  \Device\HarddiskVolume4\Windows\System32\ApplicationFrameHost.exe                  2020-06-08 01:16:48.442950
S-1-5-21-779300877-3336791673-4128505751-1000 ellie                  Microsoft.MicrosoftEdge_8wekyb3d8bbwe                                              2020-06-08 06:50:40.167150
S-1-5-21-779300877-3336791673-4128505751-1000 ellie                  Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy                                2020-05-04 06:16:38.248198
S-1-5-21-779300877-3336791673-4128505751-1000 ellie                  \Device\HarddiskVolume4\Program Files (x86)\Parallels\Parallels Tools\prl_cc.exe   2020-06-08 01:17:17.834876
S-1-5-21-779300877-3336791673-4128505751-1000 ellie                  InputApp_cw5n1h2txyewy                                                             2020-06-08 01:17:19.522374
S-1-5-21-779300877-3336791673-4128505751-1000 ellie                  Microsoft.WindowsStore_8wekyb3d8bbwe                                               2020-06-08 04:10:30.179506
S-1-5-21-779300877-3336791673-4128505751-1000 ellie                  microsoft.windowscommunicationsapps_8wekyb3d8bbwe                                  2020-06-08 06:36:40.850376
S-1-5-21-779300877-3336791673-4128505751-1000 ellie                  Microsoft.WindowsCalculator_8wekyb3d8bbwe                                          2020-06-08 01:13:15.694054
S-1-5-21-779300877-3336791673-4128505751-1000 ellie                  \Device\HarddiskVolume4\Windows\System32\WindowsPowerShell\v1.0\powershell.exe     2020-06-08 03:15:08.896212
S-1-5-21-779300877-3336791673-4128505751-1000 ellie                  \Device\HarddiskVolume4\Windows\System32\mmc.exe                                   2020-06-08 01:13:14.553532
S-1-5-21-779300877-3336791673-4128505751-1000 ellie                  windows.immersivecontrolpanel_cw5n1h2txyewy                                        2020-05-04 06:27:55.203692
S-1-5-21-779300877-3336791673-4128505751-1000 ellie                  \Device\HarddiskVolume4\Program Files (x86)\Parallels\Parallels Tools\PTIAgent.exe 2020-06-08 02:08:12.110908
S-1-5-21-779300877-3336791673-4128505751-1000 ellie                  \Device\HarddiskVolume4\Windows\System32\Taskmgr.exe                               2020-06-08 01:16:43.614756
S-1-5-21-779300877-3336791673-4128505751-1000 ellie                  Microsoft.XboxGamingOverlay_8wekyb3d8bbwe                                          2020-06-08 02:18:38.816028
S-1-5-21-779300877-3336791673-4128505751-1000 ellie                  \Device\HarddiskVolume4\Program Files\Internet Explorer\iexplore.exe               2020-06-08 01:21:32.847888
S-1-5-90-0-1                                  Desktop Window Manager \Device\HarddiskVolume4\Windows\System32\dwm.exe                                   2020-06-08 01:16:19.083484
S-1-5-18                                      systemprofile          \Device\HarddiskVolume4\Windows\System32\consent.exe                               2020-06-08 03:15:08.431172
```
