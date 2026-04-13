@echo off
echo Testing CloudWatch Logs Insights Query...
echo.

rem Update these paths as needed
set PSModulesPath=D:\psmodules
set LogGroupName=StackSet-AWSControlTowerBP-VPC-ACCOUNT-FACTORY-V1-d0d3cf0d-fa1a-4141-b09d-a0c68db385b5-VPCFlowLogsLogGroup-fabb2OlInRka
set AwsProfile=sso-ipf-aws-adfr-prod-nonprivFujitsuCSA

pwsh.exe -ExecutionPolicy Bypass -File "Test-CloudWatchQuery.ps1" -PSModulesPath "%PSModulesPath%" -LogGroupName "%LogGroupName%" -AwsProfile "%AwsProfile%" -LookbackHours 1

echo.
echo Test completed. Press any key to exit...
pause >nul
