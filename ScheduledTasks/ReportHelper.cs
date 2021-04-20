using IntegrationConnectors.Common;
using IntegrationConnectors.Fortify;
using IntegrationConnectors.Fortify.Model;
using Microsoft.Extensions.Configuration;
using ScheduledTasks.Server.Model;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace ScheduledTasks.FortifyReport
{
    public class ReportHelper
    {
        static FortifyConnector _fortifyConnector;

        internal static async Task UpdateReport(string projectName, string version, IConfiguration configuration)
        {
            var genericRepo = new BaseConnector(null, null, AuthenticationType.None);
            var reportStatus = new List<ReportExecutionStatus>();
            var projectDescription = string.Empty; 

            try
            {
                var timeoutInMinutes = 10;
                var url = configuration["Fortify:Url"];
                var key = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{configuration["Fortify:User"]}:{configuration["Fortify:Password"]}"));

                _fortifyConnector = new FortifyConnector(url, key, AuthenticationType.Basic)
                {
                    Timeout = TimeSpan.FromMinutes(timeoutInMinutes)
                };

                var unifiedLoginToken = await _fortifyConnector.GetUnifiedLoginTokenAsync();

                _fortifyConnector = new FortifyConnector(url, unifiedLoginToken, AuthenticationType.FortifyToken)
                {
                    Timeout = TimeSpan.FromMinutes(timeoutInMinutes)
                };

                var projects = await _fortifyConnector.GetProjectsAsync();
                var project = projects.FirstOrDefault(p => p.Name.Equals(projectName));

                if (project != null)
                {
                    var projectVersions = await _fortifyConnector.GetProjectVersionsAsync(project.Id);
                    var projectVersion = projectVersions.FirstOrDefault(v => version.Equals(v.Name, StringComparison.InvariantCultureIgnoreCase));
                    projectDescription = project.Description;

                    if (projectVersion!=null)
                    {
                        Console.WriteLine($"{project.Name} {project.Description} {projectVersion.Name} started");
                        var appSecItems = new List<AppSecItem>();

                        var issues = await _fortifyConnector.GetIssuesAsync(projectVersion.Id);

                        if (issues != null)
                        {
                            foreach (var issue in issues)
                            {
                                var issueDetails = await GetIssueDetailsAsync(project.Name, projectVersion.Name, issue.IssueInstanceId);

                                var appSecItem = new AppSecItem()
                                {
                                    Id = issue.IssueInstanceId,
                                    UploadDate = DateTime.Now.Date.ToString("yyyy-MM-dd"),
                                    UAID = $"{project.Name} {project.Description}",
                                    Version = projectVersion.Name,
                                    Status = issue.IssueStatus,
                                    Category = issue.IssueName,
                                    Severity = issue.friority,
                                    Source = issue.EngineType,
                                    Tag = issue.PrimaryTag,
                                    IsRedBall = IsRedBall(issue) || issueDetails.IsOWASPTopTen,
                                    OWASPCategory = issueDetails.OWASPCategory,
                                    File = issue.PrimaryLocation,
                                    LineNumber = issue.LineNumber,
                                    ScanStatus = issue.ScanStatus
                                };

                                appSecItems.Add(appSecItem);
                            }
                        }

                        var jsonBody = JsonSerializer.Serialize(appSecItems);

                        //Save file for further analysis
                        File.WriteAllText($@"C:\Temp\UVMS\{DateTime.Now.Date.ToString("yyyy-MM-dd")} {projectVersion.Name} {project.Name} {project.Description}.json", jsonBody);

                        await genericRepo.PostWithJsonAsync(configuration["PowerBI:UVMSDashboardUrl"], jsonBody);

                        Console.WriteLine($"{project.Name} {project.Description} {projectVersion.Name} finished");

                        var executionStatus = new ReportExecutionStatus()
                        {
                            ReportDate = DateTime.Now.Date.ToString("yyyy-MM-dd"),
                            UAID = $"{projectName} {projectDescription}",
                            Version = version,
                            Status = "Successful"
                        };

                        reportStatus.Add(executionStatus);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{ex.Message}");

                var executionStatus = new ReportExecutionStatus()
                {
                    ReportDate = DateTime.Now.Date.ToString("yyyy-MM-dd"),
                    UAID = $"{projectName} {projectDescription}",
                    Version = version,
                    Status = "Failed"
                };

                reportStatus.Add(executionStatus);
            }

            await genericRepo.PostWithJsonAsync(configuration["PowerBI:ReportExecutionDashboardUrl"], JsonSerializer.Serialize(reportStatus));
        }

        protected static bool IsRedBall(FortifyIssue issue)
        {
            if (
                 issue.IssueName.Contains("Cross-Site Scripting: DOM", StringComparison.InvariantCultureIgnoreCase) ||
                 issue.IssueName.Contains("Cross-Site Scripting: Reflected", StringComparison.InvariantCultureIgnoreCase) ||
                 issue.IssueName.Contains("Cross-Site Scripting: Stored", StringComparison.InvariantCultureIgnoreCase) ||
                 issue.IssueName.Contains("XSS: DOM", StringComparison.InvariantCultureIgnoreCase) ||
                 issue.IssueName.Contains("XSS: Reflected", StringComparison.InvariantCultureIgnoreCase) ||
                 issue.IssueName.Contains("XSS: Stored", StringComparison.InvariantCultureIgnoreCase) ||
                 issue.IssueName.Contains("Code Injection", StringComparison.InvariantCultureIgnoreCase) ||
                 issue.IssueName.Contains("Dynamic Code Evaluation: Script Injection", StringComparison.InvariantCultureIgnoreCase) ||
                 issue.IssueName.Contains("JSON Injection", StringComparison.InvariantCultureIgnoreCase) ||
                 issue.IssueName.Contains("Link Injection: Auto Dial", StringComparison.InvariantCultureIgnoreCase) ||
                 issue.IssueName.Contains("SQL injection", StringComparison.InvariantCultureIgnoreCase) ||
                 issue.IssueName.Contains("XML External Entity Injection", StringComparison.InvariantCultureIgnoreCase) ||
                 issue.IssueName.Contains("Process Control", StringComparison.InvariantCultureIgnoreCase) ||
                 issue.IssueName.Contains("ASP.NET Misconfiguration: Use of Impersonation Context", StringComparison.InvariantCultureIgnoreCase) ||
                 issue.IssueName.Contains("Path Manipulation", StringComparison.InvariantCultureIgnoreCase) ||
                 issue.IssueName.Contains("Setting Manipulation", StringComparison.InvariantCultureIgnoreCase) ||
                 IsSonaTypeRedBall(issue)
               )
            {
                return true;
            }
            return false;
        }

        private static bool IsSonaTypeRedBall(FortifyIssue issue)
        {
            if (issue.EngineType.Equals("SONATYPE", StringComparison.InvariantCultureIgnoreCase) &&
               (issue.friority.Equals("Critical", StringComparison.InvariantCultureIgnoreCase) ||
                issue.friority.Equals("High", StringComparison.InvariantCultureIgnoreCase)))
            {
                return true;
            }
            return false;
        }

        protected static async Task<FortifyIssueDetails> GetIssueDetailsAsync(string projectName, string projectVersionName, string instanceId)
        {
            var issueDetail = await _fortifyConnector.GetIssueDetailsAsync(projectName, projectVersionName, instanceId);
            if (issueDetail != null)
            {
                return issueDetail[0];
            }

            return new FortifyIssueDetails();
        }
    }
}
