using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Text.Json;


[ApiController]
[Route("api/[controller]")]
public class ScanController : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> Get()
    {
        var psi = new ProcessStartInfo
        {
            FileName = "python3",
            Arguments = "scan_scripts/arp_scan.py",
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

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
