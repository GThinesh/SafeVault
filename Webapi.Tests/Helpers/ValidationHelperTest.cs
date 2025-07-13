using JetBrains.Annotations;
using Webapi.Helpers;
using Xunit;

namespace Webapi.Tests.Helpers;

[TestSubject(typeof(ValidationHelper))]
public class ValidationHelperTest
{
    private string _username;
    private string _password;

    [Fact]
    public void TestUsernameValidation()
    {
        _username = "";
        Assert.False(ValidationHelper.IsValidUsername(_username), "Username should not be empty");
        _username = "very_serious_username";
        Assert.True(ValidationHelper.IsValidUsername(_username), $"'{_username}' should be valid");
        _username = "very_serious_username123345";
        Assert.True(ValidationHelper.IsValidUsername(_username), $"'{_username}' should be valid");
        _username = "<script>alert('XSS');</script>";
        Assert.False(ValidationHelper.IsValidUsername(_username), "Username should be xss safe");
    }
    
    [Fact]
    public void TestPasswordValidation()
    {
        _password = "";
        Assert.False(ValidationHelper.IsValidPassword(_password), "Password should not be empty");
        _password = "password";
        Assert.True(ValidationHelper.IsValidPassword(_password), $"'{_password}' should be valid");
        _password = "password1234";
        Assert.True(ValidationHelper.IsValidPassword(_password), $"'{_password}' should be valid");
        _password = "password!@#$%^&*?";
        Assert.True(ValidationHelper.IsValidPassword(_password), $"'{_password}' should be valid");
        _password = "password~~××";
        Assert.False(ValidationHelper.IsValidPassword(_password), $"'{_password}' should not be valid");
        _password = "<script>alert('XSS');</script>";
        Assert.False(ValidationHelper.IsValidPassword(_password), "Password should be xss safe");
    }
}