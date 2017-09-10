@ECHO OFF
@ECHO --------------------------------------------------------------------
@ECHO Recreate self-extracting package using IEXPRESS
@ECHO --------------------------------------------------------------------
@ECHO Build self-extracting package with Logging Script
:: Use the 32-bit IEXPRESS for compatibility to both 32-bit and 64-bit
:: Use /N to hide GUI when packaging
c:\windows\syswow64\IEXPRESS /N InstallMBRWLogger.SED


:: c:\windows\syswow64\IEXPRESS InstallMBRWLogger.SED

ECHO ErrorLevel is %ERRORLEVEL%



