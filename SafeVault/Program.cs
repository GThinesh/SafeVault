using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Webapi.Helpers;
using Webapi.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<IdentityDbContext>(options => options.UseInMemoryDatabase("AppDb"));

builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<IdentityDbContext>();

builder.Services.Configure<PasswordHasherOptions>(options =>
{
    options.IterationCount = 150000;
    options.CompatibilityMode = PasswordHasherCompatibilityMode.IdentityV3;
});

builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["JwtConfiguration:Issuer"] ?? throw new Exception("Issuer not found!"),
            ValidAudience = builder.Configuration["JwtConfiguration:Audience"] ??
                            throw new Exception("Audience not found!"),
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                builder.Configuration["JwtConfiguration:SigningKey"] ?? throw new Exception("ApiKey not found!"))),
            ClockSkew = TimeSpan.Zero, // Disable clock skew
            RequireExpirationTime = true,
            ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha512 }
        };

        options.RequireHttpsMetadata = true; // Require HTTPS
        options.SaveToken = false; // Don't save token in auth properties
    });

builder.Services.AddAuthorizationBuilder()
    .AddPolicy("user", policy => policy.RequireRole("user"))
    .AddPolicy("admin", policy => policy.RequireRole("admin"));

builder.Services.AddRateLimiter(options =>
{
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: context.User.Identity?.Name ?? context.Request.Headers.Host.ToString(),
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 100,
                Window = TimeSpan.FromMinutes(1)
            }));

    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
});

builder.Services.AddAntiforgery(options =>
{
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Strict;
});

var app = builder.Build();

app.Use(async (context, next) =>
{
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("X-XSS-Protection", "1; mode=block");
    context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");
    context.Response.Headers.Append("Content-Security-Policy",
        "default-src 'self'; frame-ancestors 'none'");
    await next();
});

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => "WebAPI is running!");

app.MapPost("/register", async (
    UserManager<IdentityUser> userManager,
    RoleManager<IdentityRole> roleManager,
    UserModel model,
    string role = "user") =>
{
    if (!ValidationHelper.IsValidUsername(model.Username) || !ValidationHelper.IsValidPassword(model.Password))
        return Results.BadRequest("Invalid username or password.");

    // Validate role
    if (role != "user" && role != "admin")
        return Results.BadRequest("Invalid role specified.");

    var user = new IdentityUser { UserName = model.Username };
    var result = await userManager.CreateAsync(user, model.Password);

    if (!result.Succeeded)
        return Results.BadRequest(result.Errors);

    if (!await roleManager.RoleExistsAsync(role))
        await roleManager.CreateAsync(new IdentityRole(role));

    await userManager.AddToRoleAsync(user, role);

    return Results.Ok($"{char.ToUpper(role[0]) + role[1..]} registration successful");
});

app.MapPost("/login", async (
    UserManager<IdentityUser> userManager,
    IConfiguration config,
    UserModel model) =>
{
    if (!ValidationHelper.IsValidUsername(model.Username) || !ValidationHelper.IsValidPassword(model.Password))
        return Results.BadRequest("Invalid username or password.");

    var user = await userManager.FindByNameAsync(model.Username);
    if (user == null)
        return Results.BadRequest("User not found.");

    var isValid = await userManager.CheckPasswordAsync(user, model.Password);
    if (!isValid)
        return Results.BadRequest("Invalid password.");

    var roles = await userManager.GetRolesAsync(user);

    var tokenString = JwtTokenHelper.CreateJwtToken(user, roles, config);
    return Results.Ok(new { token = tokenString });
});

app.MapGet("/files", () => Results.Ok("This is authorization protected files root."))
    .RequireAuthorization();

app.MapGet("/admin-dashboard", () => Results.Ok("This is admin role protected admin dashboard root."))
    .RequireAuthorization("admin");

app.Run();