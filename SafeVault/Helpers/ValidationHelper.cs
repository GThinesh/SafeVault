using System.Text.RegularExpressions;

namespace Webapi.Helpers;

public static class ValidationHelper
{
    private const int MinUsernameLength = 3;
    private const int MaxUsernameLength = 50;
    private static readonly Regex UsernameRegex = new("^[a-zA-Z0-9_.-]+$", RegexOptions.Compiled);
    private const int MinPasswordLength = 12;
    private const string AllowedSpecialCharacters = "!@#$%^&*?";

    public static bool IsValidUsername(string username)
    {
        return IsValidInput(username) &&
               IsValidXssInput(username) &&
               username.Length >= MinUsernameLength &&
               username.Length <= MaxUsernameLength &&
               UsernameRegex.IsMatch(username);
    }

    public static bool IsValidPassword(string password)
    {
        if (!IsValidInput(password) || password.Length < MinPasswordLength)
        {
            return false;
        }

        return IsValidXssInput(password) &&
               IsValidSpecialCharacters(password, AllowedSpecialCharacters) &&
               password.Any(char.IsUpper) &&
               password.Any(char.IsLower) &&
               password.Any(char.IsDigit) &&
               password.Any(c => AllowedSpecialCharacters.Contains(c));
    }

    private static bool IsValidInput(string input)
    {
        return !string.IsNullOrWhiteSpace(input);
    }

    private static bool IsValidSpecialCharacters(string input, string allowedSpecialCharacters)
    {
        var validCharacters = allowedSpecialCharacters.ToHashSet();
        return input.All(c => char.IsLetterOrDigit(c) || validCharacters.Contains(c));
    }

    private static bool IsValidXssInput(string input)
    {
        string[] dangerous = new[]
        {
            "<script", "<iframe", "<object", "<embed", "<form",
            "javascript:", "vbscript:", "data:", "onerror=", "onload=",
            "onclick=", "onmouseover=", "onfocus=", "onblur="
        };

        return !dangerous.Any(x =>
            input.Contains(x, StringComparison.OrdinalIgnoreCase));
    }
}