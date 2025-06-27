Add-Type -AssemblyName System.Windows.Forms
[void][System.Windows.Forms.MessageBox]::Show(
    'Close this window to let the script finish.',
    'Blocking MessageBox',
    [System.Windows.Forms.MessageBoxButtons]::OK,
    [System.Windows.Forms.MessageBoxIcon]::Information
)
