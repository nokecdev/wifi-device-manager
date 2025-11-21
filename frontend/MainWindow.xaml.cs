using System.Windows;
using frontend.ViewModels;

namespace frontend
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private readonly MainWindowViewModel _viewModel;

        public MainWindow()
        {
            InitializeComponent();
            _viewModel = new MainWindowViewModel();
            DataContext = _viewModel;
        }

        protected override void OnClosed(EventArgs e)
        {
            _viewModel.Cleanup();
            base.OnClosed(e);
        }
    }
}