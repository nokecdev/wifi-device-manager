using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Text.Json;
using System.IO;


[ApiController]
[Route("api/[controller]")]
public class ScanController : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> Get()
    {
        // Get the backend directory (where Program.cs is located)
        var backendDir = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) 
            ?? Directory.GetCurrentDirectory();
        
        // Navigate to backend directory if we're in bin/Debug/net8.0
        if (backendDir.Contains("bin"))
        {
            backendDir = Path.Combine(backendDir, "..", "..", "..");
            backendDir = Path.GetFullPath(backendDir);
        }

        // The Python script imports "from backend.scan_scripts.tools.oui_loader"
        // So we need to run from the project root (one level up from backend)
        var projectRoot = Path.GetFullPath(Path.Combine(backendDir, ".."));
        var scriptPath = Path.Combine(backendDir, "scan_scripts", "arp_scan.py");
        
        if (!System.IO.File.Exists(scriptPath))
        {
            return StatusCode(500, new { 
                error = "Script not found", 
                details = $"Could not find script at: {scriptPath}",
                backendDir = backendDir
            });
        }

        // Try python3 first, then python (for Windows compatibility)
        string pythonExe = "python3";
        if (Environment.OSVersion.Platform == PlatformID.Win32NT)
        {
            pythonExe = "python";
        }

        var psi = new ProcessStartInfo
        {
            FileName = pythonExe,
            Arguments = $"\"{scriptPath}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = projectRoot
        };

        using var proc = Process.Start(psi);
        if (proc == null) 
        {
            return StatusCode(500, new { 
                error = "Failed to start scan", 
                details = $"Could not start Python process. Is {pythonExe} installed and in PATH?" 
            });
        }

        string output = await proc.StandardOutput.ReadToEndAsync();
        string error = await proc.StandardError.ReadToEndAsync();
        await proc.WaitForExitAsync();

        if (proc.ExitCode != 0)
        {
            return StatusCode(500, new { 
                error = "Script execution failed", 
                details = $"Python script exited with code {proc.ExitCode}",
                stderr = error,
                stdout = output
            });
        }

        if (string.IsNullOrWhiteSpace(output))
        {
            return StatusCode(500, new { 
                error = "Empty output", 
                details = "Python script produced no output",
                stderr = error
            });
        }

        try
        {
            var jsonDoc = JsonDocument.Parse(output);
            return Ok(jsonDoc.RootElement);
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { 
                error = "Parse error", 
                details = ex.Message, 
                raw = output,
                stderr = error
            });
        }
    }
}
