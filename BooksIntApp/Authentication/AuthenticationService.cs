using Blazored.LocalStorage;
using BooksIntApp.Models;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.WebAssembly.Http;
using System.Net.Http.Headers;
using System.Text.Json;

namespace BooksIntApp.Authentication;

public class AuthenticationService : IAuthenticationService
{
    private readonly HttpClient _client;
    private readonly AuthenticationStateProvider _authStateProvider;
    private readonly ILocalStorageService _localStorage;
    private readonly IConfiguration _config;
    private string authTokenStorageKey;

    public AuthenticationService(HttpClient client,
                                 AuthenticationStateProvider authStateProvider,
                                 ILocalStorageService localStorage,
                                 IConfiguration config)
    {
        _client = client;
        _authStateProvider = authStateProvider;
        _localStorage = localStorage;
        _config = config;
        authTokenStorageKey = _config[key: "authTokenStorageKey"];
    }

    ///<summury>
    ///Login method
    ///</summury>
    ///<param name="AuthenticationUserModel">this is email adress and password</param>
    /// <param name="AuthenticatedUserModel">this is result</param>
    public async Task<AuthenticatedUserModel> Login(AuthenticationUserModel userForAuthentication)
    {
        var data = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>(key:"grant_type", value:"password"), // Grant type of password
            new KeyValuePair<string, string>(key:"username", userForAuthentication.Login),
            new KeyValuePair<string, string>(key:"password", userForAuthentication.Password)
        });


        string api = _config[key: "apiLocation"] + _config[key: "tokenEndpoint"];
        var authResult = await _client.PostAsync(api, data); // Give us the result
        var authContent = await authResult.Content.ReadAsStringAsync(); // Grab the result and put into auth content

        if (authResult.IsSuccessStatusCode == false)
        {
            return null;
        }
        var result = JsonSerializer.Deserialize<AuthenticatedUserModel>( // Deserialize the value into the authenticated user model
            authContent,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true }); // Ensure our results are correct  

        await _localStorage.SetItemAsync(authTokenStorageKey, result.Access_Token); // Gonna store the access token in local storage under the key auth token

        ((AuthStateProvider)_authStateProvider).NotifyUserAuthentication(result.Access_Token);

        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(scheme: "bearer", result.Access_Token);

        

        return result;
    }

    public async Task Logout()
    {
        await _localStorage.RemoveItemAsync(authTokenStorageKey); // Remove the token from local storage
        ((AuthStateProvider)_authStateProvider).NotifyUserLogout(); // Notify the user of logout
        _client.DefaultRequestHeaders.Authorization = null; // Wipe out the request headers(deleting token)
    }
}
