using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components.Authorization;
using System.Net.Http.Headers;
using System.Security.Claims;

namespace BooksIntApp.Authentication;


//Chek to see if we are logged in or not
public class AuthStateProvider : AuthenticationStateProvider
{
    private readonly HttpClient _httpClient;
    private readonly ILocalStorageService _localStorage;
    private readonly IConfiguration _config;
    private readonly AuthenticationState _anonymous;

    public AuthStateProvider(HttpClient httpClient,
                             ILocalStorageService localStorage,
                             IConfiguration config)
    {
        _httpClient = httpClient;
        _localStorage = localStorage;
        _config = config;
        _anonymous = new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
    }

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        string authTokenStorageKey = _config[key: "authTokenStorageKey"];
        var token = await _localStorage.GetItemAsync<string>(authTokenStorageKey); // Loking up in the local storage to find a token

        if (string.IsNullOrWhiteSpace(token)) // If that token is empty return anonymous that means we are not logged
        {
            return _anonymous;
        }

        _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(scheme: "bearer", token); // Checking the authentication state if find token add the token in as the "bearer" in the header

        return new AuthenticationState(
            user: new ClaimsPrincipal(
                identity: new ClaimsIdentity(JwtParser.ParseClaimsFromJwt(token),
                authenticationType: "jwtAuthType"))); // Parsing our token which returns a lsit of claims   
    }

    public void NotifyUserAuthentication(string token) // When someone is logged in it is going to trigger is notify authentication sate changed whenever the state changed
    {
        var authenticatedUser = new ClaimsPrincipal(
            identity: new ClaimsIdentity(JwtParser.ParseClaimsFromJwt(token),
            authenticationType: "jwtAuthType"));

        var authState = Task.FromResult(new AuthenticationState(authenticatedUser));
        NotifyAuthenticationStateChanged(authState);
    }

    public void NotifyUserLogout() // Alert that this is the new state of the user which is logged out
    {
        var authState = Task.FromResult(_anonymous);
        NotifyAuthenticationStateChanged(authState);
    }
}
