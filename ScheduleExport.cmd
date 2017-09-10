@ECHO OFF
@ECHO EXPORT Schedule
@ECHO Must run as Administrator on local machine
SET TASKNAME=MBRWLOGGER
SET XMLOUT=MBRWLoggerSchedule.Exported.XML
@ECHO Creates file %XMLOUT% and then launches Notepad to view it
@ECHO -----------------------------------------------
@ECHO.
REM Change to directory batch file was launched from, as 'run-as-admin' defaults to windows\system32
pushd "%~dp0" 


> %XMLOUT% schtasks /Query /S %COMPUTERNAME% /XML /TN "%TASKNAME%"
@ECHO.
@ECHO -----------------------------------------------
start notepad %XMLOUT%
pause