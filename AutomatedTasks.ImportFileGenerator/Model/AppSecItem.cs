﻿namespace AutomatedTasks.ImportFileGenerator.Model
{
    public class AppSecItem
    {
        public string Id { get; set; }
        public string UploadDate { get; set; }
        public string UAID { get; set; }
        public string Version { get; set; }
        public string Status { get; set; }
        public string Category { get; set; }
        public string Severity { get; set; }
        public string Source { get; set; }
        public string Tag { get; set; }
        public bool IsRedBall { get; set; }
        public string OWASPCategory { get; set; }
        public string File { get; set; }
        public int LineNumber { get; set; }
        public string ScanStatus { get; set; }
    }
}
