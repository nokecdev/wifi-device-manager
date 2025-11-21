using System;
using System.Collections.ObjectModel;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using frontend.Models;
using frontend.Services;

namespace frontend.ViewModels
{
    public partial class MainWindowViewModel : ObservableObject
    {
        private readonly ScanService _scanService;
        private CancellationTokenSource? _cancellationTokenSource;

        [ObservableProperty]
        private string _network = "Not scanned";

        [ObservableProperty]
        private string _interface = "-";

        [ObservableProperty]
        private string _myIp = "-";

        [ObservableProperty]
        private string _statusMessage = "Ready to scan";

        [ObservableProperty]
        private bool _isScanning;

        [ObservableProperty]
        private bool _isScanButtonEnabled = true;

        public ObservableCollection<Device> Devices { get; } = new ObservableCollection<Device>();

        public MainWindowViewModel()
        {
            _scanService = new ScanService();
        }

        [RelayCommand]
        private async Task ScanNetworkAsync()
        {
            // Cancel any existing scan
            _cancellationTokenSource?.Cancel();
            _cancellationTokenSource = new CancellationTokenSource();

            // Update state
            IsScanning = true;
            IsScanButtonEnabled = false;
            StatusMessage = "Scanning network... This may take a minute.";
            Devices.Clear();

            try
            {
                var result = await _scanService.ScanNetworkAsync(_cancellationTokenSource.Token);

                if (result != null)
                {
                    // Update network info
                    Network = result.Network ?? "Unknown";
                    Interface = result.Interface ?? "Unknown";
                    MyIp = result.MyIp ?? "Unknown";

                    // Update device list
                    if (result.Devices != null && result.Devices.Count > 0)
                    {
                        foreach (var device in result.Devices)
                        {
                            Devices.Add(device);
                        }
                        StatusMessage = $"Scan complete. Found {result.Devices.Count} device(s).";
                    }
                    else
                    {
                        StatusMessage = "Scan complete. No devices found.";
                    }
                }
                else
                {
                    StatusMessage = "Scan completed but received no data.";
                }
            }
            catch (OperationCanceledException)
            {
                StatusMessage = "Scan was cancelled.";
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error: {ex.Message}";
                MessageBox.Show(
                    $"Failed to scan network:\n\n{ex.Message}\n\nMake sure the backend is running on http://localhost:5267",
                    "Scan Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
            finally
            {
                // Reset state
                IsScanning = false;
                IsScanButtonEnabled = true;
            }
        }

        public void Cleanup()
        {
            _cancellationTokenSource?.Cancel();
            _scanService.Dispose();
        }
    }
}

