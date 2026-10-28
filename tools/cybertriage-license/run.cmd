@echo off
setlocal
java -cp "%~dp0build" com.cybertriage.tools.license4j.License4JKeyPairGenerator %*
