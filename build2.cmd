@ECHO OFF
@ECHO --------------------------------------------------------------------
@ECHO Recreate self-extracting package using IEXPRESS
@ECHO --------------------------------------------------------------------
@ECHO Build package including MBARW-Business_Setup-0.9.17.689.exe
:: Use the 32-bit IEXPRESS for compatibility to both 32-bit and 64-bit
c:\windows\syswow64\IEXPRESS /N InstallMBRW.SED
ECHO ErrorLevel is %ERRORLEVEL%



