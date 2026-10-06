// WARNING: INTENTIONALLY VULNERABLE CODE. Exists only to test PR security scanning.
// Never merge or deploy. See the PR description.
namespace eShop.Catalog.API;

public static class InjectionTestApi
{
    public static IEndpointRouteBuilder MapInjectionTestApi(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("api/injection-test");

        // [VULN] SQL injection: EF Core raw SQL built with string concatenation
        group.MapGet("/sql/efcore", async (CatalogContext context, string name) =>
        {
            var items = await context.CatalogItems
                .FromSqlRaw("SELECT * FROM \"Catalog\" WHERE \"Name\" = '" + name + "'")
                .ToListAsync();
            return TypedResults.Ok(items);
        });

        // [VULN] SQL injection: interpolated string passed to FromSqlRaw (not FromSqlInterpolated)
        group.MapGet("/sql/interpolated", async (CatalogContext context, string brand) =>
        {
            var items = await context.CatalogItems
                .FromSqlRaw($"SELECT * FROM \"Catalog\" WHERE \"Description\" LIKE '%{brand}%'")
                .ToListAsync();
            return TypedResults.Ok(items);
        });

        // [VULN] SQL injection: ADO.NET command text built from user input
        group.MapDelete("/sql/ado", async (CatalogContext context, string id) =>
        {
            var connection = context.Database.GetDbConnection();
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM \"Catalog\" WHERE \"Id\" = " + id;
            var rows = await command.ExecuteNonQueryAsync();
            return TypedResults.Ok(rows);
        });

        // [SAFE] Control for false positives: parameterized query via FromSqlInterpolated
        group.MapGet("/sql/safe", async (CatalogContext context, string name) =>
        {
            var items = await context.CatalogItems
                .FromSqlInterpolated($"SELECT * FROM \"Catalog\" WHERE \"Name\" = {name}")
                .ToListAsync();
            return TypedResults.Ok(items);
        });

        // [VULN] OS command injection: user input concatenated into a shell command
        group.MapGet("/cmd", (string host) =>
        {
            var psi = new System.Diagnostics.ProcessStartInfo("/bin/sh", "-c \"ping -c 1 " + host + "\"")
            {
                RedirectStandardOutput = true
            };
            using var process = System.Diagnostics.Process.Start(psi)!;
            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            return TypedResults.Text(output);
        });

        // [VULN] XPath injection: user input concatenated into an XPath expression
        group.MapGet("/xpath", (string user) =>
        {
            var doc = new System.Xml.XmlDocument();
            doc.LoadXml("<users><user name=\"admin\" role=\"admin\"/><user name=\"guest\" role=\"guest\"/></users>");
            var node = doc.SelectSingleNode("//user[@name='" + user + "']");
            return TypedResults.Text(node?.OuterXml ?? "not found");
        });

        return app;
    }
}
