@echo off
setlocal
cd /d "%~dp0"

if exist build rmdir /s /q build
mkdir build

dir /s /b src\main\java\*.java > build\sources.txt
javac -encoding UTF-8 -d build @build\sources.txt
if errorlevel 1 exit /b 1

echo Built classes in %CD%\build
