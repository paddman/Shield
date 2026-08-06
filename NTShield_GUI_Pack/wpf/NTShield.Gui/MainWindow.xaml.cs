using System;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Input;

namespace NTShield.Gui
{
    public partial class MainWindow : Window
    {
        public ObservableCollection<ResponseAction> Actions { get; } = new ObservableCollection<ResponseAction>
        {
            new ResponseAction("2 min ago", "Investigate", "10.0.105.190", "Auto Response (Password Spray)", "Completed"),
            new ResponseAction("3 min ago", "Capture Evidence", "10.0.105.190", "Auto Response (Password Spray)", "Completed"),
            new ResponseAction("5 min ago", "Block Destination", "10.0.105.190", "Auto Response (Password Spray)", "Completed"),
            new ResponseAction("15 min ago", "Quarantine Host", "10.0.104.22", "Analyst", "In Progress"),
            new ResponseAction("1 hr ago", "Reset Credentials", "user@internal.local", "Analyst", "Completed")
        };

        public MainWindow()
        {
            InitializeComponent();
            DataContext = Actions;
        }

        private void Header_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ClickCount == 2) ToggleMaximize(); else if (e.LeftButton == MouseButtonState.Pressed) DragMove();
        }
        private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
        private void Maximize_Click(object sender, RoutedEventArgs e) => ToggleMaximize();
        private void Close_Click(object sender, RoutedEventArgs e) => Close();
        private void ToggleMaximize() => WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
        private void Action_Click(object sender, RoutedEventArgs e) => MessageBox.Show("ตัวอย่าง UI เท่านั้น: เชื่อมปุ่มนี้กับ Response API ของ NT Shield Agent", "NT Shield Agent", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    public sealed class ResponseAction
    {
        public ResponseAction(string time, string action, string target, string triggeredBy, string status)
        { Time = time; Action = action; Target = target; TriggeredBy = triggeredBy; Status = status; }
        public string Time { get; }
        public string Action { get; }
        public string Target { get; }
        public string TriggeredBy { get; }
        public string Status { get; }
    }
}
