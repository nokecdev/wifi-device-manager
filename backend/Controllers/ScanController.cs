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
        
        var psi = new ProcessStartInfo
        {
            FileName = "python3",
            Arguments = $"\"{scriptPath}\"",
            WorkingDirectory = projectRoot,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        
        // Set PYTHONPATH to include project root so Python can find the 'backend' module
        psi.Environment["PYTHONPATH"] = projectRoot;

        using var proc = Process.Start(psi);
        if (proc == null) return StatusCode(500, "Failed to start scan");
        string output = await proc.StandardOutput.ReadToEndAsync();
        await proc.WaitForExitAsync();

        try
        {
            var jsonDoc = JsonDocument.Parse(output);
            return Ok(jsonDoc.RootElement);
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { error = "Parse error", details = ex.Message, raw = output });
        }
    }
}
