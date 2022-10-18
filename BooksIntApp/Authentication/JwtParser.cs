using System.Security.Claims;
using System.Text.Json;

namespace BooksIntApp.Authentication;

public static class JwtParser
{
    /// <summary>
    /// Parse the claims from the json web token
    /// </summary>
    /// <param name="jwt">passing in the json web token and get back an innumerable of claim</param>
    /// <returns></returns>
    public static IEnumerable<Claim> ParseClaimsFromJwt(string jwt)
    {
        var claims = new List<Claim>();
        var payload = jwt.Split(separator: '.')[1]; // Grabing the payload.[1]- payload section from our jwt.

        var jsonBytes = ParseBase64WithoutPadding(payload);

        var keyValuePairs = JsonSerializer.Deserialize<Dictionary<string, object>>(jsonBytes); // Breaking down these bytes and searialize them into the key value pairs

        ExtracRolesFromJWT(claims, keyValuePairs);

        claims.AddRange(keyValuePairs.Select(kvp => new Claim(kvp.Key, kvp.Value.ToString()))); // Adding any claims to out claims List that are in keyValuePairs

        return claims;
    }

    /// <summary>
    /// Extrac roles from json web token
    /// </summary>
    /// <param name="claims"></param>
    /// <param name="keyValueParis">pulling key value paris</param>
    /// <param name="ClaimTypes.Role">looking for the role type in list</param>
    /// <param name="out object role">If it find the role then extract the roles</param>
    private static void ExtracRolesFromJWT(List<Claim> claims, Dictionary<string, object> keyValueParis)
    {
        keyValueParis.TryGetValue(ClaimTypes.Role, out object roles);

        if (roles is not null)
        {
            var parsedRoles = roles.ToString().Trim().TrimStart(trimChar: '[').TrimEnd(trimChar: ']').Split(separator: ','); // Parse all the roles the user has access to

            if (parsedRoles.Length > 1)// If we find more then one roll for each roll
            {
                foreach (var parsedRole in parsedRoles)
                {
                    claims.Add(item: new Claim(ClaimTypes.Role, parsedRole.Trim(trimChar: '"'))); // Add the rolls to our claims list
                }

            }
            else
            {
                claims.Add(item: new Claim(ClaimTypes.Role, parsedRoles[0]));// Add the roll to our claims list
            }

            keyValueParis.Remove(ClaimTypes.Role);// Take out role from the list to ensure that it is not double processed 
        }

    }
    private static byte[] ParseBase64WithoutPadding(string base64)
    {
        switch (base64.Length % 4)
        {
            case 2:
                base64 += "==";
                break;
            case 3:
                base64 += "=";
                break;
        }
        return Convert.FromBase64String(base64);
    }
}
