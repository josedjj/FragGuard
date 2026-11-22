using FragGuard.Core.Games;
using FragGuard.Shared;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit.Abstractions;

namespace FragGuard.Core.Tests;

public class VdfParserTests
{
    [Fact]
    public void Parses_SteamAppManifest()
    {
        const string acf = """
            "AppState"
            {
                "appid"        "730"
                "name"         "Counter-Strike 2"
                "installdir"   "Counter-Strike Global Offensive"
                "LastPlayed"   "1763700000"
                "SizeOnDisk"   "34000000000"
                // comentario que debe ignorarse
                "UserConfig"
                {
                    "language" "spanish"
                }
            }
            """;
        var app = VdfParser.Parse(acf).Child("AppState")!;
        Assert.Equal("730", app.Str("appid"));
        Assert.Equal("Counter-Strike 2", app.Str("name"));
        Assert.Equal(1763700000L, app.Long("lastplayed")); // sin distinguir mayúsculas
        Assert.Equal("spanish", app.Child("UserConfig")!.Str("language"));
    }

    [Fact]
    public void Parses_LibraryFolders_WithEscapedPaths()
    {
        const string vdf = """
            "libraryfolders"
            {
                "0" { "path" "C:\\Program Files (x86)\\Steam" }
                "1" { "path" "E:\\SteamLibrary" "apps" { "1174180" "123" } }
            }
            """;
        var root = VdfParser.Parse(vdf).Child("libraryfolders")!;
        var paths = root.Values.OfType<VdfParser.Node>().Select(n => n.Str("path")).ToList();
        Assert.Equal(new[] { @"C:\Program Files (x86)\Steam", @"E:\SteamLibrary" }, paths);
    }

    [Fact]
    public void TruncatedFile_DoesNotThrow()
    {
        var root = VdfParser.Parse("\"AppState\" { \"appid\" \"10\" \"name\" \"Half");
        Assert.NotNull(root);
    }
}

public class CommandLineTests
{
    [Theory]
    [InlineData("\"C:\\Riot Games\\Riot Client\\RiotClientServices.exe\" --uninstall-product=valorant --uninstall-patchline=live",
                @"C:\Riot Games\Riot Client\RiotClientServices.exe", "--uninstall-product=valorant --uninstall-patchline=live")]
    [InlineData(@"C:\Program Files (x86)\Juego\unins000.exe /SILENT", @"C:\Program Files (x86)\Juego\unins000.exe", "/SILENT")]
    [InlineData("MsiExec.exe /X{10AD7848-62A0-425D-9E7C-A14E6EBB46BA}", "MsiExec.exe", "/X{10AD7848-62A0-425D-9E7C-A14E6EBB46BA}")]
    [InlineData("\"F:\\Dead Space (2023)\\Dead Space.exe\"", @"F:\Dead Space (2023)\Dead Space.exe", "")]
    public void Split_HandlesRegistryFormats(string input, string file, string args)
    {
        var parsed = CommandLine.Split(input);
        Assert.Equal(file, parsed.FileName);
        Assert.Equal(args, parsed.Arguments);
    }

    [Theory]
    [InlineData("steam://rungameid/730", true)]
    [InlineData("uplay://launch/926/0", true)]
    [InlineData("\"C:\\Juego\\game.exe\"", false)]
    [InlineData(@"C:\Juego\game.exe", false)]
    public void IsUri(string target, bool expected) => Assert.Equal(expected, CommandLine.IsUri(target));
}

/// <summary>Prueba de humo sobre el equipo real (no falla si no hay juegos instalados).</summary>
public class GameLibrarySmokeTests
{
    private readonly ITestOutputHelper _out;
    public GameLibrarySmokeTests(ITestOutputHelper output) => _out = output;

    [Fact]
    public async Task ScanningThisMachine_DoesNotThrow()
    {
        var library = new GameLibrary(NullLogger<GameLibrary>.Instance);
        var games = await library.GetGamesAsync(forceRefresh: true, default);
        foreach (var g in games)
            _out.WriteLine($"{g.Launcher,-11} | {g.Name,-40} | jugado: {g.LastPlayedUtc?.ToLocalTime():dd/MM/yyyy} ({g.LastPlayedSource}) | {g.SizeBytes / 1_073_741_824.0:0.0} GB | portada: {g.CoverPath is not null}");
        Assert.All(games, g => Assert.False(string.IsNullOrWhiteSpace(g.Name)));
        Assert.Equal(games.Count, games.Select(g => g.Id).Distinct().Count());
    }
}
