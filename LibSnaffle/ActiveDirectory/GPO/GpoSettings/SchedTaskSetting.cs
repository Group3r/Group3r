using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;

namespace LibSnaffle.ActiveDirectory
{
    public class SchedTaskSetting : GpoSetting
    {
        //Properties
        public string Name { get; set; }
        public string Type { get; set; }
        public DateTime Changed { get; set; }

        public SchedTaskType TaskType { get; set; }
        public SettingAction SettingAction { get; set; }
        public string SchedTaskAction { get; set; }
        public string Author { get; set; }
        public List<SchedTaskPrincipal> Principals { get; set; }
        public string Description1 { get; set; }
        public string Comment { get; set; }
        public string Duration { get; set; }
        public string WaitTimeout { get; set; }
        public bool StartOnlyIfIdle { get; set; }
        public bool StopOnIdleEnd { get; set; }
        public bool RestartOnIdle { get; set; }
        public string MultipleInstancesPolicy { get; set; }
        public bool DisallowStartIfOnBatteries { get; set; }
        public bool StopIfGoingOnBatteries { get; set; }
        public bool SystemRequired { get; set; }
        public bool AllowHardTerminate { get; set; }
        public bool AllowStartOnDemand { get; set; }
        public bool Enabled { get; set; }
        public bool Hidden { get; set; }
        public string ExecutionTimeLimit { get; set; }
        public int Priority { get; set; }

        public List<SchedTaskAction> Actions { get; set; }
        public XmlNodeList Triggers { get; set; }
    }

    public class SchedTaskPrincipal
    {
        public string Id { get; set; }
        public string UserId { get; set; }
        public string Cpassword { get; set; }
        public string LogonType { get; set; }
        public string RunLevel { get; set; }
    }

    public class SchedTaskAction
    {
    }

    public class SchedTaskExecAction : SchedTaskAction
    {
        public string Command { get; set; }
        public string Args { get; set; }
        public string WorkingDir { get; set; }
    }

    public class SchedTaskEmailAction : SchedTaskAction
    {
        public string From { get; set; }
        public string To { get; set; }
        public string Subject { get; set; }
        public string Body { get; set; }
        public string HeaderFields { get; set; }
        public List<string> Attachments { get; set; }
        public string Server { get; set; }
    }

    public class SchedTaskShowMessageAction : SchedTaskAction
    {
        public string Title { get; set; }
        public string Body { get; set; }
    }

    public enum SchedTaskType
    {
        Task,
        TaskV2,
        ImmediateTask,
        ImmediateTaskV2
    }

    /*
    public class TaskTrigger
    {
        public string Type { get; set; }
        public int StartHour { get; set; }
        public int StartMinutes { get; set; }
        public int BeginYear { get; set; }
        public int BeginMonth { get; set; }
        public bool HasEndDate { get; set; }
        public bool RepeatTask { get; set; }
        public bool Interval { get; set; }
    }
    */
}
