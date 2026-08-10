@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 coletar_cves_2026.py --fonte nvd --anos 2018-2026 --somente-web --excluir-rejeitadas --saida cves_web_saida
) else (
  python coletar_cves_2026.py --fonte nvd --anos 2018-2026 --somente-web --excluir-rejeitadas --saida cves_web_saida
)
echo.
pause
