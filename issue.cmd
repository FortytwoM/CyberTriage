@echo off
setlocal
python "%~dp0tools\cybertriage-license\issue.py" --input-dir "%~dp0input" --output-dir "%~dp0output" --licenses-dir "%~dp0licenses" %*
