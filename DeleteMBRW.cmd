@ECHO OFF
@REM ------------------------------------------------------------------------------------------
@REM Delete MBRW Logger
@REM
@REM
@REM Author: Andrew Probert, Malwarebytes A&NZ
@REM
@REM Deleted Logger and Anti-Ransomware
@REM Version: 1.3 Beta
@REM -------------------------------------------------------------------------------------------
 
SET MBRWUnInstallLogPath=%WINDIR%\Temp\Malwarebytes
SET MBRWUnInstallLog=%MBRWUnInstallLogPath%\MBRWLoggerUninstall.log
SET MBRWPath=%ProgramFiles%\Malwarebytes\Anti-Ransomware
SET TASKNAME=MBRWLogger

@REM Create a Folder under Windows\Temp for Malwarebytes installation logging
IF NOT EXIST %WINDIR%\Temp\Malwarebytes MKDIR %WINDIR%\Temp\Malwarebytes

REM Overwrite log at start
 > %MBRWUnInstallLog%        ECHO *** Deleting BMRWLogger from path %MBRWPath%                                          
>> %MBRWUnInstallLog%        ECHO *** Logging to path %MBRWPath%

IF NOT EXIST "%MBRWPath%" (
>> %MBRWUnInstallLog%        ECHO *** Cannot find %MBRWPath% to delete
    GOTO :next1
)
@REM Change directory to program path
pushd "%MBRWPath%"

>> %MBRWUnInstallLog%        ECHO *** Deleting Files
>> %MBRWUnInstallLog% 2>&1   ERASE /S MBRWLogger.ps1                                      
>> %MBRWUnInstallLog% 2>&1   ERASE /S MBRWLoggerSchedule.xml  
>> %MBRWUnInstallLog% 2>&1   ERASE /S InstallMBRWLogger.cmd  
>> %MBRWUnInstallLog% 2>&1   ERASE /S DeleteMBRWLogger.cmd  
                                    
>> %MBRWUnInstallLog%        ECHO *** Delete existing task, if present                                              
>> %MBRWUnInstallLog%        ECHO *** schtasks /Delete /TN "%TASKNAME%" /F
>> %MBRWUnInstallLog% 2>&1   schtasks /Delete /TN "%TASKNAME%" /F                                                    
>> %MBRWUnInstallLog%        ECHO *** schtasks /Delete /TN "%TASKNAME%" /F returned ERRORLEVEL %ERRORLEVEL%                                                   

>> %MBRWUnInstallLog%        echo "%MBRWPath%\unins000.exe" /SP- /verysilent /suppressmsgboxes
>> %MBRWUnInstallLog%             "%MBRWPath%\unins000.exe" /SP- /verysilent /suppressmsgboxes

IF NOT EXIST "%MBRWPath%\MBARW.EXE" (
>> %MBRWUnInstallLog%        ECHO *** SUCCESS
    GOTO :next1
) ELSE (
>> %MBRWUnInstallLog%        ECHO *** FAILED "%MBRWPath%\MBARW.EXE" still EXISTs, unins000.exe may not have worked
)

:next1
>> %MBRWUnInstallLog%        ECHO *** Script Ended

type %MBRWUnInstallLog%

popd


