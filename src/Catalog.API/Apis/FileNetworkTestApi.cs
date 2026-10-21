// WARNING: INTENTIONALLY VULNERABLE CODE. Exists only to test PR security scanning.
// Never merge or deploy. See the PR description.
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;

namespace eShop.Catalog.API;

public static class FileNetworkTestApi
{
    // [VULN] Hardcoded credential: secret committed to source
    private const string AdminApiKey = "catalog-admin-P@ssw0rd-2026";

    public static IEndpointRouteBuilder MapFileNetworkTestApi(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("api/file-network-test");

        // [VULN] Path traversal: user-supplied file name combined into a path without validation
        group.MapGet("/file", (IWebHostEnvironment environment, string name) =>
        {
            var path = Path.Combine(environment.ContentRootPath, "Pics", name);
            return TypedResults.Text(File.ReadAllText(path));
        });

        // [SAFE] Control for false positives: resolved path must stay inside the Pics directory
        group.MapGet("/file/safe", Results<Ok<string>, BadRequest> (IWebHostEnvironment environment, string name) =>
        {
            var root = Path.GetFullPath(Path.Combine(environment.ContentRootPath, "Pics")) + Path.DirectorySeparatorChar;
            var path = Path.GetFullPath(Path.Combine(root, name));
            if (!path.StartsWith(root, StringComparison.Ordinal))
            {
                return TypedResults.BadRequest();
            }
            return TypedResults.Ok(File.ReadAllText(path));
        });

        // [VULN] SSRF: server fetches an arbitrary user-supplied URL (e.g. cloud metadata endpoint)
        group.MapGet("/fetch", async (IHttpClientFactory httpClientFactory, string url) =>
        {
            var client = httpClientFactory.CreateClient();
            var body = await client.GetStringAsync(url);
            return TypedResults.Text(body);
        });

        // [VULN] Open redirect: redirects to any user-supplied URL
        group.MapGet("/redirect", (string returnUrl) => Results.Redirect(returnUrl));

        // [SAFE] Control for false positives: only local redirects are allowed
        group.MapGet("/redirect/safe", (string returnUrl) => Results.LocalRedirect(returnUrl));

        // [VULN] XXE: DTD processing enabled with a URL resolver, so external entities are resolved
        group.MapPost("/xml", async (HttpRequest request) =>
        {
            using var reader = new StreamReader(request.Body);
            var xml = await reader.ReadToEndAsync();
            var settings = new System.Xml.XmlReaderSettings
            {
                DtdProcessing = System.Xml.DtdProcessing.Parse,
                XmlResolver = new System.Xml.XmlUrlResolver()
            };
            using var xmlReader = System.Xml.XmlReader.Create(new StringReader(xml), settings);
            var doc = new System.Xml.XmlDocument { XmlResolver = new System.Xml.XmlUrlResolver() };
            doc.Load(xmlReader);
            return TypedResults.Text(doc.InnerText);
        });

        // [VULN] Broken access control: admin action guarded only by a hardcoded key compared non-constant-time
        group.MapDelete("/admin/items/{id:int}", async (CatalogContext context, [FromHeader(Name = "X-Api-Key")] string apiKey, int id) =>
        {
            if (apiKey != AdminApiKey)
            {
                return Results.Unauthorized();
            }
            var item = await context.CatalogItems.FindAsync(id);
            if (item is null)
            {
                return Results.NotFound();
            }
            context.CatalogItems.Remove(item);
            await context.SaveChangesAsync();
            return Results.NoContent();
        });

        return app;
    }
}
