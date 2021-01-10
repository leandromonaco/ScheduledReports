using AutomationToolkit.Common;
using AutomationToolkit.Common.Http;
using AutomationToolkit.Fortify;
using Hangfire;
using Hangfire.SqlServer;
using Microsoft.Extensions.Configuration;
using System;
using System.Linq;
using System.Text;
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
                var url = _configuration["Fortify:Url"];
                var key = _configuration["Fortify:Key"];

                var _fortifyTestRepository = new FortifyRepository(url, key, AuthenticationType.Basic);

                var unifiedLoginToken = await _fortifyTestRepository.GetUnifiedLoginTokenAsync();

                var _fortifyTestRepository2 = new FortifyRepository(url, unifiedLoginToken, AuthenticationType.FortifyToken);

                var projects = await _fortifyTestRepository2.GetProjectsAsync();
                var project = projects.FirstOrDefault(p => p.Name.Equals(projectName));

                if (project != null)
                {
                    var versions = await _fortifyTestRepository2.GetProjectVersionsAsync(project.Id);

                    var sb = new StringBuilder();
                    sb.Append("[");

                    foreach (var projectVersion in versions)
                    {
                        var issues = await _fortifyTestRepository2.GetIssuesAsync(projectVersion.Id);

                        foreach (var issue in issues)
                        {
                            var jsonBody = $"{{ \"UploadDate\" :\"{DateTime.Now.Date.ToString("yyyy-MM-dd")}\", \"UAID\" :\"{project.Name} {project.Description}\", \"Version\" :\"{projectVersion.Name}\", \"Status\" :\"{issue.IssueStatus}\", \"Category\" :\"{issue.IssueName}\", \"Severity\" :\"{issue.friority}\", \"Source\" :\"{issue.EngineType}\", \"Tag\" :\"{issue.PrimaryTag}\", \"IsRedBall\" :\"{IsRedBall(issue.IssueName)}\" }},";
                            sb.Append(jsonBody);
                        }
                    }

                    sb.Append("]");
                    var genericRepo = new GenericRepository();
                    await genericRepo.PostAsync(_configuration["PowerBI:Url"], sb.ToString());
                }
            }
            catch (Exception)
            {
                throw;
            }
        }

        private static bool IsRedBall(string issueName)
        {
            if (issueName.Contains("Injection", StringComparison.InvariantCultureIgnoreCase) ||
                issueName.Contains("Process", StringComparison.InvariantCultureIgnoreCase) ||
                issueName.Contains("Cross-Site", StringComparison.InvariantCultureIgnoreCase) ||
                issueName.Contains("Escalation", StringComparison.InvariantCultureIgnoreCase) ||
                issueName.Contains("Manipulation", StringComparison.InvariantCultureIgnoreCase) ||
                issueName.Contains("Impersonation", StringComparison.InvariantCultureIgnoreCase) ||
                issueName.Contains("Auto Dial", StringComparison.InvariantCultureIgnoreCase))
            {
                return true;
            }
            return false;
        }
    }
}
