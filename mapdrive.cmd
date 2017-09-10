@ECHO ON
@ECHO The drive name and file names are hardcoded in SED file
@ECHO Map current directory to drive Z: to allow easy reuse and relocation of sources
subst z: /D
subst z: "%CD%"
subst
 