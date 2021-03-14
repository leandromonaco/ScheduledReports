using AutomationConnectors.Common;
using AutomationConnectors.Common.Http;
using AutomationConnectors.Fortify;
using Hangfire;
using Hangfire.SqlServer;
using Microsoft.Extensions.Configuration;
using ScheduledTasks.Server.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace ScheduledTasks
{
    class Program
    {
        static IConfiguration _configuration;

        static void Main(string[] args)
        {
            GlobalConfiguration.Configuration
                               .SetDataCompatibilityLevel(CompatibilityLevel.Version_170)
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

            foreach (var app in applications)
            {
                BackgroundJob.Enqueue(() => UpdateReport(app.Value).RunSynchronously());
            }

            using (var server = new BackgroundJobServer())
            {
                Console.ReadLine();
            }
        }

        private static async Task UpdateReport(string projectName)
        {
            try
            {
                Console.WriteLine($"{projectName} started");
                var timeoutInMinutes = 10;
                var url = _configuration["Fortify:Url"];
                var key = _configuration["Fortify:Key"];

                var _fortifyConnector = new FortifyConnector(url, key, AuthenticationType.Basic);
                _fortifyConnector.Timeout = TimeSpan.FromMinutes(timeoutInMinutes);

                var unifiedLoginToken = await _fortifyConnector.GetUnifiedLoginTokenAsync();

                _fortifyConnector = new FortifyConnector(url, unifiedLoginToken, AuthenticationType.FortifyToken);
                _fortifyConnector.Timeout = TimeSpan.FromMinutes(timeoutInMinutes);

                var projects = await _fortifyConnector.GetProjectsAsync();
                var project = projects.FirstOrDefault(p => p.Name.Equals(projectName));

                if (project != null)
                {
                    var versions = await _fortifyConnector.GetProjectVersionsAsync(project.Id);

                    var appSecItems = new List<AppSecItem>();

                    foreach (var projectVersion in versions)
                    {
                        var issues = await _fortifyConnector.GetIssuesAsync(projectVersion.Id);

                        foreach (var issue in issues)
                        {
                            var appSecItem = new AppSecItem() 
                            {
                                UploadDate = DateTime.Now.Date.ToString("yyyy-MM-dd"),
                                UAID = $"{project.Name} {project.Description}",
                                Version = projectVersion.Name,
                                Status = issue.IssueStatus,
                                Category = issue.IssueName,
                                Severity = issue.friority,
                                Source = issue.EngineType,
                                Tag = issue.PrimaryTag,
                                IsRedBall = IsRedBall(issue.IssueName)
                            };

                            appSecItems.Add(appSecItem);
                        }
                    }

                    var jsonBody = JsonSerializer.Serialize(appSecItems);

                    var genericRepo = new GenericConnector();
                    await genericRepo.PostAsync(_configuration["PowerBI:Url"], jsonBody);
                    Console.WriteLine($"{projectName} finished");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{ex.Message}");
                throw;
            }
        }

        private static bool IsRedBall(string issueName)
        {
            if (
                 issueName.Contains("Cross-Site Scripting: DOM", StringComparison.InvariantCultureIgnoreCase) ||
                 issueName.Contains("Cross-Site Scripting: Reflected", StringComparison.InvariantCultureIgnoreCase) ||
                 issueName.Contains("Cross-Site Scripting: Stored", StringComparison.InvariantCultureIgnoreCase) ||
                 issueName.Contains("XSS: DOM", StringComparison.InvariantCultureIgnoreCase) ||
                 issueName.Contains("XSS: Reflected", StringComparison.InvariantCultureIgnoreCase) ||
                 issueName.Contains("XSS: Stored", StringComparison.InvariantCultureIgnoreCase) ||
                 issueName.Contains("Code Injection", StringComparison.InvariantCultureIgnoreCase) ||
                 issueName.Contains("Dynamic Code Evaluation: Script Injection", StringComparison.InvariantCultureIgnoreCase) ||
                 issueName.Contains("JSON Injection", StringComparison.InvariantCultureIgnoreCase) ||
                 issueName.Contains("Link Injection: Auto Dial", StringComparison.InvariantCultureIgnoreCase) ||
                 issueName.Contains("SQL injection", StringComparison.InvariantCultureIgnoreCase) ||
                 issueName.Contains("XML External Entity Injection", StringComparison.InvariantCultureIgnoreCase) ||
                 issueName.Contains("Process Control", StringComparison.InvariantCultureIgnoreCase) ||
                 issueName.Contains("ASP.NET Misconfiguration: Use of Impersonation Context", StringComparison.InvariantCultureIgnoreCase) ||
                 issueName.Contains("Path Manipulation", StringComparison.InvariantCultureIgnoreCase) ||
                 issueName.Contains("Setting Manipulation", StringComparison.InvariantCultureIgnoreCase)
               )
            {
                return true;
            }
            return false;
        }
    }
}
