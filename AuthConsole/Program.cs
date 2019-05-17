using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;



namespace AuthConsole
{

    public class wellopenIdconfiguration
    {
        public string authorization_endpoint { get; set; }
        public string token_endpoint { get; set; }
        public List<string> token_endpoint_auth_methods_supported { get; set; }
        public string jwks_uri { get; set; }
        public List<string> response_modes_supported { get; set; }
        public List<string> subject_types_supported { get; set; }
        public List<string> id_token_signing_alg_values_supported { get; set; }
        public bool http_logout_supported { get; set; }
        public bool frontchannel_logout_supported { get; set; }
        public string end_session_endpoint { get; set; }
        public List<string> response_types_supported { get; set; }
        public List<string> scopes_supported { get; set; }
        public string issuer { get; set; }
        public List<string> claims_supported { get; set; }
        public bool microsoft_multi_refresh_token { get; set; }
        public string check_session_iframe { get; set; }
        public string userinfo_endpoint { get; set; }
        public string tenant_region_scope { get; set; }
        public string cloud_instance_name { get; set; }
        public string cloud_graph_host_name { get; set; }
        public string msgraph_host { get; set; }
        public string rbac_url { get; set; }
    }



    public class Value
    {
        public string id { get; set; }
        public string tenantId { get; set; }
        public string countryCode { get; set; }
        public string displayName { get; set; }
        public List<string> domains { get; set; }
        public string tenantCategory { get; set; }
    }

    public class Tenants
    {
        public List<Value> Value { get; set; }
    }
    class Program
    {
        private const string ClientId = "ApplicationGUID";
        private const string ServicePrincipalPassword = "Password";
        private const string AzureTenantId = "AzureTenantGUID";
        private const string AzureSubscriptionId = "AzureSubscriptionGUID";

        
        private static string AuthToken { get; set; }

        private static string ResourceGroupName { get; set; }

        public static async Task<object> GetRequestJson(Type mytype,string url, string authToken, string apiversion) 
        {
            //Type type = mytype.GetType();
            dynamic result = "";
            using (var httpClient = new HttpClient())
            {
                httpClient.DefaultRequestHeaders.Add("Authorization", string.Format("Bearer {0}", authToken));
                var response = httpClient.GetAsync(new Uri(string.Concat(url, "?api-version=", apiversion))).Result;
                if (response.IsSuccessStatusCode)
                {
                    string content = await response.Content.ReadAsStringAsync();
                    result = JsonConvert.DeserializeObject(content, mytype);
                }
                if (!response.IsSuccessStatusCode)
                {
                    throw new Exception((int)response.StatusCode + "-" + response.StatusCode.ToString());
                }
               
            }
            return result;
        }

        static void Main(string[] args)
        {
            string clientId = "1950a258-227b-4e31-a9cf-717495945fc2";
            //string aadTenantId = "sharmakiet86hotmail.onmicrosoft.com";

            string AadInstance = "https://login.windows.net/{0}";
            string ResourceId = "https://management.azure.com/";//"https://management.core.windows.net";


            //Step1:
            // OAuth2 authority Uri  
            string authorityUri = "https://login.microsoftonline.com/common";
            AuthenticationContext authContext = new AuthenticationContext(authorityUri);

            //AuthenticationContext authenticationContext = new AuthenticationContext(string.Format(AadInstance, aadTenantId));


            DateTime startTime = DateTime.Now;
            Console.WriteLine("Time " + String.Format("{0:mm:ss.fff}", startTime));
            var authParam = new PlatformParameters(PromptBehavior.SelectAccount);
            string redirectUri = "urn:ietf:wg:oauth:2.0:oob";


            // 3. Acquire a token
            //AuthenticationResult authenticationResult = authenticationContext.AcquireTokenAsync(ResourceId, clientId, new Uri(redirectUri), authParam).Result;
            AuthenticationResult authenticationResult = authContext.AcquireTokenAsync(ResourceId, clientId, new Uri(redirectUri), authParam).Result;
            AuthToken = authenticationResult.AccessToken;

            Tenants oTenants = (Tenants)GetRequestJson(typeof(Tenants), string.Concat(ResourceId, "tenants"), AuthToken, "2019-05-01").Result;

            var subs = (wellopenIdconfiguration)GetRequestJson(typeof(wellopenIdconfiguration),string.Concat(string.Format(AadInstance, oTenants.Value.FirstOrDefault().domains[0]), "/.well-known/openid-configuration"), AuthToken, "2019-05-01").Result;

            AuthenticationContext authenticationContext = null;

            if (oTenants.Value.Any())
            {
                // 3. Pick an authority. Note that some applications even handle multiple authorities
                // instantiate several authentication contexts and get tokens for each
                Value DefaultTenant = oTenants.Value.FirstOrDefault(); // for example
                
                authenticationContext = new AuthenticationContext(string.Format(AadInstance, DefaultTenant.tenantId));
                

            }            

            // 4. In the case where there was no cached tokens yet, we did not do 3). The authority is still the common authority. 
            // We need to re-instantiate an AuthenticationContext with the real (tenanted) authority
            //if (authContext.Authority == authorityUri)
            //{
            //    // We now know the tenant (it's in authenticationResult.Authority)
            //    authContext = new AuthenticationContext(authenticationResult.Authority, authContext.TokenCache);
            //}

            AuthenticationResult FinalauthenticationResult = authenticationContext.AcquireTokenAsync(ResourceId, clientId, new Uri(redirectUri), new PlatformParameters(PromptBehavior.Never)).Result;

            DateTime endTime = DateTime.Now;
            Console.WriteLine("Got token at " + String.Format("{0:mm:ss.fff}", endTime));

            Console.WriteLine("Total time to get token in milliseconds " + (endTime - startTime).TotalMilliseconds);


            Console.ReadKey();

        }

        //static AuthenticationResult AccessToken()
        //{
        //    //Get access token:   
        //    // To call a Data Catalog REST operation, create an instance of AuthenticationContext and call AcquireToken  
        //    // AuthenticationContext is part of the Active Directory Authentication Library NuGet package  
        //    // To install the Active Directory Authentication Library NuGet package in Visual Studio,   
        //    //  run "Install-Package Microsoft.IdentityModel.Clients.ActiveDirectory Version 2.19.208020213" from the nuget Package Manager Console.  

        //    //Resource Uri for Data Catalog API  
        //    string resourceUri = "https://datacatalog.azure.com";

        //    //To learn how to register a client app and get a Client ID, see https://msdn.microsoft.com/en-us/library/azure/mt403303.aspx#clientID     
        //    string clientId = "a0448380-c346-4f9f-b897-c18733de9394";

        //    //A redirect uri gives AAD more details about the specific application that it will authenticate.  
        //    //Since a client app does not have an external service to redirect to, this Uri is the standard placeholder for a client app.  
        //    string redirectUri = "https://login.live.com/oauth20_desktop.srf";

        //    // Create an instance of AuthenticationContext to acquire an Azure access token  
        //    // OAuth2 authority Uri  
        //    string authorityUri = "https://login.windows.net/common/oauth2/authorize";
        //    AuthenticationContext authContext = new AuthenticationContext(authorityUri);

        //    // Call AcquireToken to get an Azure token from Azure Active Directory token issuance endpoint  
        //    //  AcquireToken takes a Client Id that Azure AD creates when you register your client app.  
        //    return authContext.AcquireToken(resourceUri, clientId, new Uri(redirectUri), PromptBehavior.RefreshSession);
        //}


        //public static TokenCredentials AuthenticateUser(string tenantId, string resource, string appClientId, Uri appRedirectUri, string userId = "")
        //{
        //    var authContext = new AuthenticationContext("https://login.microsoftonline.com/" + tenantId);

        //    var tokenAuthResult = authContext.AcquireToken(resource, appClientId, appRedirectUri,
        //        PromptBehavior.Auto, UserIdentifier.AnyUser);

        //    return new TokenCredentials(tokenAuthResult.AccessToken);
        //}
        //private static string GetAuthorizationToken()
        //{
        //    ClientCredential cc = new ClientCredential(ClientId, ServicePrincipalPassword);
        //    var context = new AuthenticationContext("https://login.windows.net/" + AzureTenantId);
        //    var result = context.AcquireTokenAsync("https://management.azure.com/", cc);
        //    if (result == null)
        //    {
        //        throw new InvalidOperationException("Failed to obtain the JWT token");
        //    }

        //    return result.Result.AccessToken;
        //}
    }
}
