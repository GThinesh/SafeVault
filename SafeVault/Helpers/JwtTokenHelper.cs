using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

namespace Webapi.Helpers;

public static class JwtTokenHelper
{
    public static string CreateJwtToken(IdentityUser user, IList<string> roles, IConfiguration config)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, user.UserName!),
            new(ClaimTypes.NameIdentifier, user.Id),
            new("jti", Guid.NewGuid().ToString()), // Unique token ID
            new("iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()) // Issued at time
        };
        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["JwtConfiguration:SigningKey"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512); 

        var expires = DateTime.UtcNow.AddMinutes(30); // Reduce token lifetime

        var token = new JwtSecurityToken(
            issuer: config["JwtConfiguration:Issuer"],
            audience: config["JwtConfiguration:Audience"],
            claims: claims,
            notBefore: DateTime.UtcNow,
            expires: expires,
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}