using FragGuard.Shared.Models;
using FragGuard.UI.Infrastructure;

namespace FragGuard.Core.Tests;

/// <summary>
/// La limpieza de restos BORRA carpetas: estos tests comprueban que solo propone coincidencias exactas,
/// que nunca toca la instalación de otro juego y que el envío a la Papelera funciona.
/// Usan carpetas falsas con nombres únicos dentro de %LOCALAPPDATA% y las eliminan al terminar.
/// </summary>
public class LeftoverFinderTests : IDisposable
{
    private readonly string _gameName = "FgTestGame" + Guid.NewGuid().ToString("N")[..8];
    private readonly List<string> _created = new();
    private static readonly string LocalAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

    private string MakeDir(params string[] parts)
    {
        string path = Path.Combine(new[] { LocalAppData }.Concat(parts).ToArray());
        Directory.CreateDirectory(path);
        File.WriteAllText(Path.Combine(path, "save.dat"), "datos");
        _created.Add(Path.Combine(LocalAppData, parts[0]));
        return path;
    }

    private GameDto Game(string? installPath = null) => new() { Id = "test:" + _gameName, Name = _gameName, Launcher = "Otro", InstallPath = installPath };

    [Fact]
    public void FindsExactNameFolder_Unselected_AsPossibleSaves()
    {
        string dir = MakeDir(_gameName);

        var found = LeftoverFinder.Find(Game(), stillInstalled: false, Array.Empty<GameDto>());

        var item = Assert.Single(found, f => f.Path.Equals(dir, StringComparison.OrdinalIgnoreCase));
        Assert.False(item.IsSelected);          // nunca preseleccionar lo que puede ser una partida
        Assert.True(item.MayContainSaves);
        Assert.Equal("AppData\\Local", item.Category);
    }

    [Fact]
    public void FindsSecondLevelFolder_StudioThenGame()
    {
        string dir = MakeDir("FgStudio" + _gameName[^8..], _gameName);
        var found = LeftoverFinder.Find(Game(), false, Array.Empty<GameDto>());
        Assert.Contains(found, f => f.Path.Equals(dir, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void IgnoresPartialNameMatches()
    {
        MakeDir(_gameName + "Extra");
        MakeDir("Pre" + _gameName);
        var found = LeftoverFinder.Find(Game(), false, Array.Empty<GameDto>());
        Assert.DoesNotContain(found, f => f.Path.Contains(_gameName, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void NeverProposesFolderContainingAnotherInstalledGame()
    {
        string dir = MakeDir(_gameName);
        string otherInstall = Path.Combine(dir, "OtroJuegoInstalado");
        Directory.CreateDirectory(otherInstall);
        var other = new GameDto { Id = "test:otro", Name = "Otro", Launcher = "Otro", InstallPath = otherInstall };

        var found = LeftoverFinder.Find(Game(), false, new[] { other });

        Assert.DoesNotContain(found, f => f.Path.Equals(dir, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void InstallFolder_OnlyWhenUninstalled_AndPreselected()
    {
        string install = MakeDir("FgInstall" + _gameName[^8..]);

        var whileInstalled = LeftoverFinder.Find(Game(install), stillInstalled: true, Array.Empty<GameDto>());
        Assert.DoesNotContain(whileInstalled, f => f.Category == "Carpeta de instalación");

        var afterUninstall = LeftoverFinder.Find(Game(install), stillInstalled: false, Array.Empty<GameDto>());
        var item = Assert.Single(afterUninstall, f => f.Category == "Carpeta de instalación");
        Assert.True(item.IsSelected);
    }

    [Fact]
    public void NameVariants_StripTrademarksAndPunctuation()
    {
        var v = LeftoverFinder.NameVariants(new GameDto { Name = "Marvel’s Spider-Man™: Remastered", InstallPath = @"E:\Steam\common\Marvel's Spider-Man Remastered" });
        Assert.Contains("Marvels Spider-Man Remastered", v);
        Assert.Contains("Marvel's Spider-Man Remastered", v);
    }

    [Fact]
    public void RecycleBin_MovesFolderAway()
    {
        string dir = MakeDir(_gameName);
        var (ok, error) = RecycleBin.Send(dir);
        Assert.True(ok, error);
        Assert.False(Directory.Exists(dir));
    }

    public void Dispose()
    {
        foreach (var d in _created)
            try { if (Directory.Exists(d)) Directory.Delete(d, recursive: true); } catch { }
    }
}
