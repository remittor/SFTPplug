@echo off
set SFTP_ALLINONE=1
call make_libressl.cmd
call make_libssh2.cmd
call make_extlibs.cmd
