using ScheduledTasks.CertificateChecker;
using System;

//TODO: Move this to a configuration file
var url = "https://google.com";

var cert = await CertificateHelper.GetServerCertificateAsync(url);

var verb = "expires";

if (cert.NotAfter < DateTime.Now)
{
    //Certificate is expired
    Console.ForegroundColor = ConsoleColor.Red;
    verb = "expired";
    //TODO: Trigger Alert
}
else if (cert.NotAfter < DateTime.Now.AddDays(30))
{
    //Certificate is about to expire
    Console.ForegroundColor = ConsoleColor.Yellow;
    //TODO: Trigger Alert
}
else
{
    //Certificate is valid
    Console.ForegroundColor = ConsoleColor.Green;
}

Console.WriteLine($"{url} certificate {verb} on {cert.NotAfter}");

Console.ReadKey();