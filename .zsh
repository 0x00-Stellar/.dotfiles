# MessageBox Test Script - For testing injection payload
# This script creates a simple Windows message box

# Windows API for MessageBox
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class MessageBoxAPI
{
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int MessageBox(IntPtr hWnd, string text, string caption, uint type);
    
    // MessageBox types
    public const uint MB_OK = 0x00000000;
    public const uint MB_OKCANCEL = 0x00000001;
    public const uint MB_YESNO = 0x00000004;
    public const uint MB_ICONINFORMATION = 0x00000040;
    public const uint MB_ICONWARNING = 0x00000030;
    public const uint MB_ICONERROR = 0x00000010;
    public const uint MB_SYSTEMMODAL = 0x00001000;
}
"@

# Get current process info
$currentProcess = Get-Process -Id $PID
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Message content
$title = "🎯 INJECTION TEST SUCCESS"
$message = @"
✅ AMSI BYPASS INJECTION SUCCESSFUL!

🕒 Timestamp: $timestamp
🔢 Process ID: $($currentProcess.Id)
📝 Process Name: $($currentProcess.ProcessName)
💻 Machine: $env:COMPUTERNAME
👤 User: $env:USERNAME

🚀 This message box proves that:
• Memory injection worked successfully
• AMSI bypass is functional
• Payload execution is operational
• System compromise achieved

Click OK to close this test window.
"@

# Display message box with information icon
Write-Host "Displaying injection test message box..." -ForegroundColor Green
$result = [MessageBoxAPI]::MessageBox(
    [IntPtr]::Zero,
    $message,
    $title,
    [MessageBoxAPI]::MB_OK -bor [MessageBoxAPI]::MB_ICONINFORMATION -bor [MessageBoxAPI]::MB_SYSTEMMODAL
)

# Create proof file
$proofFile = "injection_test_proof_$($currentProcess.Id).txt"
$proofContent = @"
INJECTION TEST PROOF
==================
Timestamp: $timestamp
Process ID: $($currentProcess.Id)
Process Name: $($currentProcess.ProcessName)
Machine: $env:COMPUTERNAME
User: $env:USERNAME
MessageBox Result: $result
Working Directory: $(Get-Location)
PowerShell Version: $($PSVersionTable.PSVersion)

This file proves that the injection test payload executed successfully.
The message box was displayed and the user clicked: $result
"@

$proofContent | Out-File -FilePath $proofFile -Encoding UTF8
Write-Host "Proof file created: $proofFile" -ForegroundColor Cyan

# Display result
Write-Host "Message box test completed successfully!" -ForegroundColor Green
Write-Host "User clicked result code: $result" -ForegroundColor Yellow
Write-Host "Proof file: $proofFile" -ForegroundColor Cyan
