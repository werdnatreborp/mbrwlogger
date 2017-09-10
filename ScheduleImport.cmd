@ECHO OFF
@ECHO ScheduleImport

@ECHO Must run as Administrator on local machine

SET TASKNAME=MBRWLOGGER
SET XMLIN=MBRWLoggerSchedule.XML
@ECHO Does not do any path checking, just imports %XMLIN% from current directory
@ECHO --------------------------------------------------------
@ECHO.

REM Change to directory batch file was launched from, as 'run-as-admin' defaults to windows\system32
pushd "%~dp0" 
schtasks /Create /RU "SYSTEM" /TN "%TASKNAME%" /XML "%XMLIN%" /F
@ECHO.
@ECHO --------------------------------------------------------
schtasks /Query /S %COMPUTERNAME% /XML /TN "%TASKNAME%"

pause