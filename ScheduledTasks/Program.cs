using Microsoft.Extensions.Configuration;
using ScheduledTasks.FortifyReport;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

IConfiguration _configuration;

_configuration = new ConfigurationBuilder().AddJsonFile("appsettings.json", optional: true)
                                           .AddUserSecrets("64e32b73-d726-4114-8d8e-21cbd1b1497b")
                                           .Build();

var applications = _configuration.GetSection("Applications").GetChildren();
var versions = _configuration.GetSection("Versions").GetChildren();
var reportTasks = new List<Task>();

foreach (var application in applications)
{
    foreach (var version in versions)
    {
        reportTasks.Add(ReportHelper.UpdateReportAsync(application.Value, version.Value, _configuration));
    }
}

Task.WaitAll(reportTasks.ToArray());

Console.WriteLine("Process is finished.");
Console.ReadLine();

