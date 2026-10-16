using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Windows.Forms;
using Microsoft.Win32;

internal static class SetupProgram
{
    [STAThread]
    private static void Main(string[] args)
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        if (args.Length > 0 && args[0] == "/uninstall") { Uninstall(); return; }
        Application.Run(new SetupForm());
    }

    private static void Uninstall()
    {
        string location = Path.GetDirectoryName(Application.ExecutablePath);
        if (MessageBox.Show("TugbayPass uygulaması kaldırılacak. Kasa dosyalarınız bu işlemden etkilenmez. Devam edilsin mi?", "TugbayPass'ı kaldır", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
        try
        {
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\Kasam", true)) if (key != null) Registry.CurrentUser.DeleteSubKeyTree(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\Kasam", false);
            string menu = Environment.GetFolderPath(Environment.SpecialFolder.Programs);
            string shortcut = Path.Combine(menu, "TugbayPass.lnk"); if (File.Exists(shortcut)) File.Delete(shortcut);
            shortcut = Path.Combine(menu, "Kasam.lnk"); if (File.Exists(shortcut)) File.Delete(shortcut);
            shortcut = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "TugbayPass.lnk"); if (File.Exists(shortcut)) File.Delete(shortcut);
            shortcut = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "Kasam.lnk"); if (File.Exists(shortcut)) File.Delete(shortcut);
            string cmd = "/c ping 127.0.0.1 -n 3 > nul & rmdir /s /q " + Quote(location);
            Process.Start(new ProcessStartInfo("cmd.exe", cmd) { CreateNoWindow = true, UseShellExecute = false, WindowStyle = ProcessWindowStyle.Hidden });
        }
        catch (Exception ex) { MessageBox.Show("Kaldırma tamamlanamadı: " + ex.Message, "TugbayPass", MessageBoxButtons.OK, MessageBoxIcon.Error); }
    }

    internal static string Quote(string value) { return "\"" + value.Replace("\"", "\"\"") + "\""; }
}

internal sealed class SetupForm : Form
{
    private readonly TextBox folder;
    private readonly CheckBox desktop;
    private readonly Label message;
    private readonly byte[] appBytes, iconBytes;

    public SetupForm()
    {
        Text = "TugbayPass Kurulumu"; StartPosition = FormStartPosition.CenterScreen; FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false; MinimizeBox = false; ClientSize = new Size(590, 330); BackColor = Color.FromArgb(245, 247, 248); Font = new Font("Segoe UI", 9);
        Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
        Assembly assembly = Assembly.GetExecutingAssembly();
        using (Stream s = assembly.GetManifestResourceStream("Kasam.exe")) appBytes = ReadAll(s);
        using (Stream s = assembly.GetManifestResourceStream("Kasam.ico")) iconBytes = ReadAll(s);
        Label title = new Label { Text = "TugbayPass'i bilgisayarınıza kurun", Font = new Font("Segoe UI Semibold", 17), ForeColor = Color.FromArgb(26, 38, 42), AutoSize = true, Location = new Point(28, 24) }; Controls.Add(title);
        Label desc = new Label { Text = "Kurulum klasörünü seçin. Kasa dosyalarınız bu klasörden ayrı tutulur.", AutoSize = true, ForeColor = Color.FromArgb(96, 110, 116), Location = new Point(30, 66) }; Controls.Add(desc);
        Label label = new Label { Text = "Kurulum konumu", AutoSize = true, Location = new Point(30, 116), Font = new Font("Segoe UI Semibold", 9) }; Controls.Add(label);
        string defaultPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "TugbayPass");
        try { using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\Kasam")) { string saved = key == null ? null : key.GetValue("InstallLocation") as string; if (!String.IsNullOrWhiteSpace(saved)) defaultPath = saved; } } catch { }
        folder = new TextBox { Text = defaultPath, Location = new Point(30, 140), Size = new Size(425, 30), Font = new Font("Segoe UI", 10) }; Controls.Add(folder);
        Button browse = ButtonAt("Gözat…", 466, 138, 94); browse.Click += delegate { using (FolderBrowserDialog dialog = new FolderBrowserDialog { Description = "Kasam'ın kurulacağı klasörü seçin", SelectedPath = Directory.Exists(folder.Text) ? folder.Text : Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), ShowNewFolderButton = true }) if (dialog.ShowDialog(this) == DialogResult.OK) folder.Text = dialog.SelectedPath; }; Controls.Add(browse);
        desktop = new CheckBox { Text = "Masaüstüne TugbayPass kısayolu oluştur", Checked = true, AutoSize = true, Location = new Point(30, 190) }; Controls.Add(desktop);
        message = new Label { Text = "Başlat menüsü kısayolu otomatik oluşturulur.", AutoSize = true, ForeColor = Color.FromArgb(96, 110, 116), Location = new Point(30, 222) }; Controls.Add(message);
        Button install = ButtonAt("Kur", 430, 270, 130); install.BackColor = Color.FromArgb(65, 91, 220); install.ForeColor = Color.White; install.FlatAppearance.BorderSize = 0; install.Click += Install; Controls.Add(install);
        Button cancel = ButtonAt("İptal", 320, 270, 100); cancel.Click += delegate { Close(); }; Controls.Add(cancel);
    }

    private Button ButtonAt(string text, int x, int y, int width) { return new Button { Text = text, Location = new Point(x, y), Size = new Size(width, 38), FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI Semibold", 9), Cursor = Cursors.Hand }; }
    private static byte[] ReadAll(Stream stream) { if (stream == null) throw new InvalidDataException("Kurulum dosyasında bir dosya eksik."); using (MemoryStream ms = new MemoryStream()) { stream.CopyTo(ms); return ms.ToArray(); } }

    private void Install(object sender, EventArgs e)
    {
        string target = folder.Text.Trim();
        if (target.Length < 3 || !Path.IsPathRooted(target)) { MessageBox.Show("Geçerli bir kurulum klasörü seçin.", "Kasam Kurulumu", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
        try
        {
            Directory.CreateDirectory(target);
            File.WriteAllBytes(Path.Combine(target, "Kasam.exe"), appBytes);
            File.WriteAllBytes(Path.Combine(target, "Kasam.ico"), iconBytes);
            string uninstallExe = Path.Combine(target, "Kasam-Uninstall.exe"); File.Copy(Application.ExecutablePath, uninstallExe, true);
            string menu = Environment.GetFolderPath(Environment.SpecialFolder.Programs); Directory.CreateDirectory(menu);
            string oldMenuShortcut = Path.Combine(menu, "Kasam.lnk"); if (File.Exists(oldMenuShortcut)) File.Delete(oldMenuShortcut);
            CreateShortcut(Path.Combine(menu, "TugbayPass.lnk"), Path.Combine(target, "Kasam.exe"), target, Path.Combine(target, "Kasam.ico"));
            if (desktop.Checked) CreateShortcut(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "TugbayPass.lnk"), Path.Combine(target, "Kasam.exe"), target, Path.Combine(target, "Kasam.ico"));
            using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\Kasam"))
            {
                key.SetValue("DisplayName", "TugbayPass"); key.SetValue("DisplayVersion", "1.3.4"); key.SetValue("Publisher", "TugbayPass"); key.SetValue("InstallLocation", target); key.SetValue("DisplayIcon", Path.Combine(target, "Kasam.ico"));
                key.SetValue("UninstallString", SetupProgram.Quote(uninstallExe) + " /uninstall"); key.SetValue("NoModify", 1, RegistryValueKind.DWord); key.SetValue("NoRepair", 1, RegistryValueKind.DWord);
            }
            if (MessageBox.Show("TugbayPass kuruldu. Şimdi başlatılsın mı?", "TugbayPass Kurulumu", MessageBoxButtons.YesNo, MessageBoxIcon.Information) == DialogResult.Yes)
                Process.Start(new ProcessStartInfo(Path.Combine(target, "Kasam.exe")) { UseShellExecute = true });
            Close();
        }
        catch (Exception ex) { message.Text = "Kurulum başarısız: " + ex.Message; message.ForeColor = Color.FromArgb(180, 55, 55); }
    }

    private static void CreateShortcut(string path, string target, string working, string icon)
    {
        Type shellType = Type.GetTypeFromProgID("WScript.Shell");
        object shell = Activator.CreateInstance(shellType); object link = shellType.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell, new object[] { path });
        Type linkType = link.GetType(); linkType.InvokeMember("TargetPath", BindingFlags.SetProperty, null, link, new object[] { target }); linkType.InvokeMember("WorkingDirectory", BindingFlags.SetProperty, null, link, new object[] { working });
        linkType.InvokeMember("IconLocation", BindingFlags.SetProperty, null, link, new object[] { icon + ",0" }); linkType.InvokeMember("Save", BindingFlags.InvokeMethod, null, link, null);
    }
}
