using System.Text.Json.Serialization;

namespace frontend.Models
{
    public class ScanResponse
    {
        [JsonPropertyName("interface")]
        public string? Interface { get; set; }

        [JsonPropertyName("myip")]
        public string? MyIp { get; set; }

        [JsonPropertyName("network")]
        public string? Network { get; set; }

        [JsonPropertyName("devices")]
        public List<Device>? Devices { get; set; }
    }

    public class Device
    {
        [JsonPropertyName("ip")]
        public string? Ip { get; set; }

        [JsonPropertyName("mac")]
        public string? Mac { get; set; }

        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("vendor")]
        public string? Vendor { get; set; }

        [JsonPropertyName("open_ports")]
        public List<int>? OpenPorts { get; set; }

        [JsonPropertyName("guessed_type")]
        public string? GuessedType { get; set; }

        public string OpenPortsDisplay => OpenPorts != null && OpenPorts.Count > 0 
            ? string.Join(", ", OpenPorts) 
            : "None";
    }
}

