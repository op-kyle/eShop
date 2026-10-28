// WARNING: INTENTIONALLY VULNERABLE CODE. Exists solely to test PR security scanning.
// Never merge or deploy. See the PR description for details.
using System.Security.Cryptography;
using System.Text;

namespace eShop.Catalog.API;

public static class CryptoTestApi
{
    // [VULN] Hardcoded symmetric encryption key
    private static readonly byte[] EncryptionKey = Encoding.UTF8.GetBytes("eShopCatalogKey!");

    public static IEndpointRouteBuilder MapCryptoTestApi(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("api/crypto-test");

        // [VULN] Weak password hashing: unsalted MD5
        group.MapPost("/hash", (string password) =>
            TypedResults.Text(Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(password)))));

        // [VULN] Insecure randomness: System.Random used to generate a password reset token
        group.MapGet("/reset-token", () =>
        {
            var random = new Random();
            var token = string.Concat(Enumerable.Range(0, 32).Select(_ => random.Next(16).ToString("x")));
            return TypedResults.Text(token);
        });

        // [VULN] Insecure cipher mode: AES-ECB with the hardcoded key above
        group.MapPost("/encrypt", (string plaintext) =>
        {
            using var aes = Aes.Create();
            aes.Key = EncryptionKey;
            var ciphertext = aes.EncryptEcb(Encoding.UTF8.GetBytes(plaintext), PaddingMode.PKCS7);
            return TypedResults.Text(Convert.ToBase64String(ciphertext));
        });

        // [SAFE] Control for false positives: salted PBKDF2-SHA256
        group.MapPost("/hash/safe", (string password) =>
        {
            var salt = RandomNumberGenerator.GetBytes(16);
            var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, 600_000, HashAlgorithmName.SHA256, 32);
            return TypedResults.Text(Convert.ToHexString(salt) + ":" + Convert.ToHexString(hash));
        });

        // [SAFE] Control for false positives: token from a cryptographically secure RNG
        group.MapGet("/reset-token/safe", () =>
            TypedResults.Text(RandomNumberGenerator.GetHexString(32, lowercase: true)));

        return app;
    }
}
