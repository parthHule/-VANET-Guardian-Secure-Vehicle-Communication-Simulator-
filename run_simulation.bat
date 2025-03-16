@echo off
setlocal enabledelayedexpansion

:: Build the project
echo Building project...
if not exist build mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -A x64
if errorlevel 1 (
    echo Build configuration failed!
    exit /b 1
)

cmake --build . --config Release
if errorlevel 1 (
    echo Build failed!
    exit /b 1
)

:: Run simulation scenarios
echo Running urban scenario simulation...
Release\urban-scenario.exe --numVehicles=50 --numMalicious=5 --simTime=300
if errorlevel 1 (
    echo Simulation failed!
    exit /b 1
)

:: Create results directory
cd ..
if not exist results mkdir results

:: Analyze results
echo Analyzing results...
python analysis\analyze_results.py ^
    build\vanet-trace.tr ^
    --output-dir results ^
    --report-file results\report.txt
if errorlevel 1 (
    echo Analysis failed!
    exit /b 1
)

echo Simulation and analysis completed successfully!
echo Results are available in the 'results' directory
echo View the report at results\report.txt 