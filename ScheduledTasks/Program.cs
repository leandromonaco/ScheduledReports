using Hangfire;
using Hangfire.SqlServer;
using Microsoft.Extensions.Configuration;
using ScheduledTasks.FortifyReport;
using System;

IConfiguration _configuration;

GlobalConfiguration.Configuration.SetDataCompatibilityLevel(CompatibilityLevel.Version_170)
                                 .UseSimpleAssemblyNameTypeSerializer()
                                 .UseSqlServerStorage("Database=ScheduledTasks; Integrated Security=True;", new SqlServerStorageOptions
                                 {
                                     CommandBatchMaxTimeout = TimeSpan.FromSeconds(30),
                                     QueuePollInterval = TimeSpan.Zero,
                                     SlidingInvisibilityTimeout = TimeSpan.FromSeconds(30),
                                     UseRecommendedIsolationLevel = true,
                                     PrepareSchemaIfNecessary = true, // Default value: true
                                     EnableHeavyMigrations = false     // Default value: false
                                 });

_configuration = new ConfigurationBuilder().AddJsonFile("appsettings.json", optional: true)
                                           .AddUserSecrets("64e32b73-d726-4114-8d8e-21cbd1b1497b")
                                           .Build();

var applications = _configuration.GetSection("Applications").GetChildren();
var versions = _configuration.GetSection("Versions").GetChildren();

foreach (var application in applications)
{
    foreach (var version in versions)
    {
        BackgroundJob.Enqueue(() => ReportHelper.UpdateReport(application.Value, version.Value, _configuration).RunSynchronously());
    }
}

using (var server = new BackgroundJobServer())
{
    Console.ReadLine();
}

