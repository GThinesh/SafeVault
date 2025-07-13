using NUnit.Framework;
using Webapi.Helpers;

namespace Webapi.Tests;

[TestFixture]
public class ValidationHelperTest
{
    [TestCase("", false, Description = "Username should not be empty")]
    [TestCase("very_serious_username", true, Description = "Username with underscore should be valid")]
    [TestCase("very_serious_username123345", true, Description = "Username with numbers should be valid")]
    [TestCase("<script>alert('XSS');</script>", false, Description = "Username should be xss safe")]
    public void TestUsernameValidation(string username, bool expectedResult)
    {
        Assert.That(ValidationHelper.IsValidUsername(username), Is.EqualTo(expectedResult));
    }

    [TestCase("", false, Description = "Password should not be empty")]
    [TestCase("password", true, Description = "Simple password should be valid")]
    [TestCase("password1234", true, Description = "Password with numbers should be valid")]
    [TestCase("password!@#$%^&*?", true, Description = "Password with special characters should be valid")]
    [TestCase("password~~××", false, Description = "Password with invalid special characters should not be valid")]
    [TestCase("<script>alert('XSS');</script>", false, Description = "Password should be xss safe")]
    public void TestPasswordValidation(string password, bool expectedResult)
    {
        Assert.That(ValidationHelper.IsValidPassword(password), Is.EqualTo(expectedResult));
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase(" ")]
    public void IsValidUsername_WithInvalidInput_ReturnsFalse(string username)
    {
        Assert.That(ValidationHelper.IsValidUsername(username), Is.False);
    }

    [TestCase("<script>alert('xss')</script>")]
    [TestCase("<SCRIPT>console.log('test')</SCRIPT>")]
    [TestCase("user<iframe>")]
    [TestCase("user<IFRAME src=''>")]
    public void IsValidUsername_WithXssAttempt_ReturnsFalse(string username)
    {
        Assert.That(ValidationHelper.IsValidUsername(username), Is.False);
    }

    [TestCase("validUser123")]
    [TestCase("john_doe")]
    [TestCase("user.name")]
    [TestCase("user@domain")]
    public void IsValidUsername_WithValidInput_ReturnsTrue(string username)
    {
        Assert.That(ValidationHelper.IsValidUsername(username), Is.True);
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase(" ")]
    public void IsValidPassword_WithInvalidInput_ReturnsFalse(string password)
    {
        Assert.That(ValidationHelper.IsValidPassword(password), Is.False);
    }

    [TestCase("<script>alert('xss')</script>")]
    [TestCase("<SCRIPT>console.log('test')</SCRIPT>")]
    [TestCase("pass<iframe>")]
    [TestCase("pass<IFRAME src=''>")]
    public void IsValidPassword_WithXssAttempt_ReturnsFalse(string password)
    {
        Assert.That(ValidationHelper.IsValidPassword(password), Is.False);
    }

    [TestCase("ValidPass123!")]
    [TestCase("Pass@word123")]
    [TestCase("MyP@ssw0rd")]
    [TestCase("Test123#$")]
    public void IsValidPassword_WithValidInput_ReturnsTrue(string password)
    {
        Assert.That(ValidationHelper.IsValidPassword(password), Is.True);
    }

    [TestCase("password|")]
    [TestCase("pass~word")]
    [TestCase("test\\pass")]
    [TestCase("invalid}pass")]
    public void IsValidPassword_WithInvalidSpecialCharacters_ReturnsFalse(string password)
    {
        Assert.That(ValidationHelper.IsValidPassword(password), Is.False);
    }

    [Test]
    public void IsValidPassword_WithAllowedSpecialCharacters_ReturnsTrue()
    {
        var specialChars = "!@#$%^&*?";
        foreach (var specialChar in specialChars)
        {
            var password = $"Password{specialChar}123";
            Assert.That(ValidationHelper.IsValidPassword(password), Is.True,
                $"Password with special character '{specialChar}' should be valid");
        }
    }
}