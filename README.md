```cmd
set "IDA_DIR=%CD%"
git clone --no-checkout --depth=1 --filter=blob:none https://github.com/apokrana/revtools.git "%TEMP%\revtools_tmp" & cd /d "%TEMP%\revtools_tmp" & git sparse-checkout init --cone & git sparse-checkout set ida/plugins & git checkout & xcopy /E /I /Y "%TEMP%\revtools_tmp\ida\plugins\*" "%IDA_DIR%\plugins\" & cd /d "%IDA_DIR%" & rmdir /S /Q "%TEMP%\revtools_tmp"
```
