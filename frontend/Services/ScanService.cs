using System.Net.Http;
using System.Text.Json;
using frontend.Models;

namespace frontend.Services
{
    public class ScanService
    {
        private readonly HttpClient _httpClient;
        private readonly string _baseUrl;

        public ScanService(string baseUrl = "http://localhost:5267")
        {
            _baseUrl = baseUrl;
            _httpClient = new HttpClient
            {
                BaseAddress = new Uri(_baseUrl),
                Timeout = TimeSpan.FromMinutes(5) // Scan can take a while
            };
        }

        public async Task<ScanResponse?> ScanNetworkAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var response = await _httpClient.GetAsync("/api/scan", cancellationToken);
                response.EnsureSuccessStatusCode();

                var jsonString = await response.Content.ReadAsStringAsync(cancellationToken);
                var options = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                };

                return JsonSerializer.Deserialize<ScanResponse>(jsonString, options);
            }
            catch (HttpRequestException ex)
            {
                throw new Exception($"Failed to connect to backend: {ex.Message}", ex);
            }
            catch (TaskCanceledException)
            {
                throw new Exception("Scan request timed out. The scan may be taking longer than expected.");
            }
            catch (Exception ex)
            {
                throw new Exception($"Error during scan: {ex.Message}", ex);
            }
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }
}

