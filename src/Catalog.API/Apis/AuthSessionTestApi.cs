// WARNING: INTENTIONALLY VULNERABLE CODE. Exists solely to test PR security scanning.
// Never merge or deploy. See the PR description for details.
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace eShop.Catalog.API;

public static class AuthSessionTestApi
{
    public static IEndpointRouteBuilder MapAuthSessionTestApi(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("api/auth-test");

        // [VULN] JWT validation disabled: signature, issuer, audience and lifetime are not checked,
        // so a forged token with "role": "admin" is accepted
        group.MapGet("/whoami", async (HttpRequest request) =>
        {
            var token = request.Headers.Authorization.ToString().Replace("Bearer ", "");
            var result = await new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                ValidateIssuerSigningKey = false,
                RequireSignedTokens = false,
                SignatureValidator = (t, _) => new JsonWebToken(t)
            });
            if (!result.IsValid)
            {
                return Results.Unauthorized();
            }
            return Results.Ok(new
            {
                Subject = result.ClaimsIdentity.FindFirst("sub")?.Value,
                IsAdmin = result.ClaimsIdentity.HasClaim("role", "admin")
            });
        });

        // [SAFE] Control for false positives: signed token validated against a configured key, issuer and audience
        group.MapGet("/whoami/safe", async (HttpRequest request, IConfiguration config) =>
        {
            var token = request.Headers.Authorization.ToString().Replace("Bearer ", "");
            var result = await new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
            {
                ValidIssuer = config["AuthTest:Issuer"],
                ValidAudience = config["AuthTest:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(Convert.FromBase64String(config["AuthTest:SigningKey"]!)),
                ValidateIssuerSigningKey = true
            });
            if (!result.IsValid)
            {
                return Results.Unauthorized();
            }
            return Results.Ok(new
            {
                Subject = result.ClaimsIdentity.FindFirst("sub")?.Value,
                IsAdmin = result.ClaimsIdentity.HasClaim("role", "admin")
            });
        });

        // [VULN] Insecure session cookie: readable by JavaScript, sent over plain HTTP, no SameSite protection
        group.MapPost("/session", (HttpResponse response) =>
        {
            response.Cookies.Append("session", RandomNumberGenerator.GetHexString(32), new CookieOptions
            {
                HttpOnly = false,
                Secure = false,
                SameSite = SameSiteMode.None
            });
            return TypedResults.Ok();
        });

        // [VULN] ReDoS: user-supplied regex pattern evaluated with no timeout, e.g. pattern=(a+)+$
        group.MapGet("/match", (string pattern, string input) =>
            TypedResults.Ok(Regex.IsMatch(input, pattern)));

        // [SAFE] Control for false positives: user input is escaped and matching has a timeout
        group.MapGet("/match/safe", (string term, string input) =>
            TypedResults.Ok(Regex.IsMatch(input, Regex.Escape(term), RegexOptions.None, TimeSpan.FromMilliseconds(100))));

        // [VULN] Unsafe reflection / deserialization: the caller picks which .NET type the request body is deserialized into
        group.MapPost("/deserialize", async (HttpRequest request, string typeName) =>
        {
            var type = Type.GetType(typeName) ?? throw new ArgumentException($"Unknown type {typeName}");
            var obj = await JsonSerializer.DeserializeAsync(request.Body, type);
            return TypedResults.Ok(obj?.ToString());
        });

        // [VULN] Information exposure: full exception (stack trace, internal paths, SQL details) returned to the client
        group.MapGet("/items/{id}", async (string id, CatalogContext context) =>
        {
            try
            {
                var itemId = int.Parse(id);
                var item = await context.CatalogItems.SingleAsync(ci => ci.Id == itemId);
                return Results.Ok(item);
            }
            catch (Exception ex)
            {
                return Results.Problem(detail: ex.ToString(), statusCode: 500);
            }
        });

        return app;
    }
}
