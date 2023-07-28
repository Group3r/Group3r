﻿using Group3r.View;
using System.Security.Principal;

namespace Group3r.Options
{
    public class GrouperOptions
    {
        // Manual Targeting Options
        public string SysvolPath { get; set; }
        public bool OfflineMode { get; set; } = false;
        public string TargetDomain { get; set; }
        public string TargetDc { get; set; }
        public string Password { get; set; }
        public string Username { get; set; }
        public bool CurrentPolOnly { get; set; } = false;
        public bool EnabledPolOnly { get; set; } = false;
        public bool QuietMode { get; set; }
        public string TargetUserName { get; set; } = WindowsIdentity.GetCurrent().Name;

        // Concurrency Options
        public int MaxThreads { get; set; } = 30;
        public int MaxSysvolThreads { get; set; } = 15;
        public int MaxGpoaThreads { get; set; } = 15;
        public int MaxSysvolQueue { get; set; } = 0;
        public int MaxGpoaQueue { get; set; } = 0;

        // Logging Options
        public bool LogToFile { get; set; } = false;
        public string LogFilePath { get; set; }
        public char Separator { get; set; } = ' ';
        public bool LogToConsole { get; set; } = true;
        public string LogLevelString { get; set; } = "info";
        public string PrinterType { get; set; }
        public bool FindingsOnly { get; set; } = false;

        // JSON output options
        public bool JsonResults { get; set; } = false;
        public string JsonFilePath { get; set; }

        public AssessmentOptions.AssessmentOptions AssessmentOptions { get; set; }
        /*
        public AutoMapper.ConfigurationStore AutoMapperConfig { get; set; }
        public AutoMapper.MappingEngine MappingEngine { get; set; }
        */

        public IGpoPrinter Printer { get; set; }

        public GrouperOptions()
        {
            AssessmentOptions = new AssessmentOptions.AssessmentOptions();

            Printer = GpoPrinterFactory.GetPrinter(PrinterType, this);
        }
    }
}