using System;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace ScheduledTasks.CertificateChecker
{
    public class CertificateHelper
    {
        public static async Task<X509Certificate2> GetServerCertificateAsync(string url)
        {
            X509Certificate2 certificate = null;
            var httpClientHandler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (sender, cert, chain, error) =>
                {
                    certificate = new X509Certificate2(cert.GetRawCertData());
                    return true;
                }
            };

            var httpClient = new HttpClient(httpClientHandler);
            await httpClient.SendAsync(new HttpRequestMessage(HttpMethod.Head, url));

            return certificate ?? throw new NullReferenceException();
        }
    }
}
