using System;
using System.Collections.Generic;
using System.Net;
using System.Xml;

namespace LibSnaffle.ActiveDirectory
{
    public class SchedTaskV2Parser
    {
        public string GetXmlValueSafe(XmlNode node, string xPathQuery)
        {
            string result = null;
            XmlNode selectedNode = node.SelectSingleNode(xPathQuery);
            if (selectedNode != null)
            {
                return selectedNode.InnerText;
            }
            else
            {
                return null;
            }
        }

        public SchedTaskSetting ParseSchedTask(SchedTaskType taskType, XmlNode schedTask)
        {
            SchedTaskSetting sts = new SchedTaskSetting();
            sts.TaskType = taskType;
            XmlAttributeCollection stAttributes = schedTask.Attributes;
            XmlNode stProperties = schedTask.SelectSingleNode("Properties");
            XmlAttributeCollection stPropAtts = stProperties.Attributes;

            // basic atts
            sts.Name = stAttributes?["name"]?.Value;
            DateTime changed;
            if (DateTime.TryParse(stAttributes?["changed"]?.Value, out changed))
            {
                // TODO put this in all the other settings parsers
                sts.Changed = changed;
            }
            // detailed properties
            sts.SettingAction = sts.ParseSettingAction(stPropAtts?["action"]?.Value);
            // Registration Info
            XmlNode regInfo = stProperties.SelectSingleNode("Task/RegistrationInfo");
            sts.Author = GetXmlValueSafe(regInfo, "Author");
            sts.Description1 = GetXmlValueSafe(regInfo, "Description");
            // Principals
            XmlNodeList principals = stProperties.SelectNodes("Task/Principals/Principal");
            sts.Principals = new List<SchedTaskPrincipal>();
            foreach (XmlNode principal in principals)
            {
                SchedTaskPrincipal stPrincipal = new SchedTaskPrincipal();
                stPrincipal.Id = principal.Attributes?["id"]?.Value;
                stPrincipal.UserId = GetXmlValueSafe(principal, "UserId");
                stPrincipal.LogonType = GetXmlValueSafe(principal, "LogonType");
                stPrincipal.RunLevel = GetXmlValueSafe(principal, "RunLevel");
                stPrincipal.Cpassword = GetXmlValueSafe(principal, "Cpassword");
                sts.Principals.Add(stPrincipal);
            }
            //Settings
              // Idle Settings

            sts.Duration = GetXmlValueSafe(stProperties, "Task/Settings/IdleSettings/Duration");
            sts.WaitTimeout = GetXmlValueSafe(stProperties, "Task/Settings/IdleSettings/WaitTimeout");

            bool stopOnIdleEnd;
            if (Boolean.TryParse(GetXmlValueSafe(stProperties, "Task/Settings/IdleSettings/StopOnIdleEnd"), out stopOnIdleEnd))
            {
                sts.StopOnIdleEnd = stopOnIdleEnd;
            }

            bool restartOnIdle;
            if (Boolean.TryParse(GetXmlValueSafe(stProperties, "Task/Settings/IdleSettings/RestartOnIdle"), out restartOnIdle))
            {
                sts.RestartOnIdle = restartOnIdle;
            }

            sts.MultipleInstancesPolicy =
                GetXmlValueSafe(stProperties, "Task/Settings/MultipleInstancesPolicy");
            bool noIfBatt;
            if (Boolean.TryParse(GetXmlValueSafe(stProperties, "Task/Settings/DisallowStartIfOnBatteries"), out noIfBatt))
            {
                sts.DisallowStartIfOnBatteries = noIfBatt;
            }

            bool stopGoBatt;
            if (Boolean.TryParse(GetXmlValueSafe(stProperties, "Task/Settings/StopIfGoingOnBatteries"), out stopGoBatt))
            {
                sts.StopIfGoingOnBatteries = stopGoBatt;
            }

            bool allowHardTerminate;
            if (Boolean.TryParse(GetXmlValueSafe(stProperties, "Task/Settings/AllowHardTerminate"), out allowHardTerminate))
            {
                sts.AllowHardTerminate = allowHardTerminate;
            }

            bool allowStartOnDemand;
            if (Boolean.TryParse(GetXmlValueSafe(stProperties, "Task/Settings/AllowStartOnDemand"), out allowStartOnDemand))
            {
                sts.AllowStartOnDemand = allowStartOnDemand;
            }

            bool enabled;
            if (Boolean.TryParse(GetXmlValueSafe(stProperties, "Task/Settings/Enabled"), out enabled))
            {
                sts.Enabled = enabled;
            }

            bool hidden;
            if (Boolean.TryParse(GetXmlValueSafe(stProperties, "Task/Settings/Hidden"), out hidden))
            {
                sts.Hidden = hidden;
            }

            sts.ExecutionTimeLimit = GetXmlValueSafe(stProperties, "Task/Settings/ExecutionTimeLimit");

            int priority;
            if (int.TryParse(GetXmlValueSafe(stProperties, "Task/Settings/Priority"), out priority))
            {
                sts.Priority = priority;
            }

            sts.Triggers = stProperties.SelectNodes("Task/Triggers/*");

            // V2 can have multiple actions
            List<SchedTaskAction> stActions = new List<SchedTaskAction>();
            XmlNodeList messageActions = stProperties.SelectNodes("Task/Actions/ShowMessage");
            foreach ( XmlNode messageAction in messageActions)
            {
                SchedTaskShowMessageAction messageActionSetting = new SchedTaskShowMessageAction();
                messageActionSetting.Title = GetXmlValueSafe(messageAction, "Title");
                messageActionSetting.Body = GetXmlValueSafe(messageAction, "Body");
                stActions.Add(messageActionSetting);
            }

            XmlNodeList execActions = stProperties.SelectNodes("Task/Actions/Exec");
            foreach (XmlNode execAction in execActions)
            {
                SchedTaskExecAction execActionSetting = new SchedTaskExecAction();
                execActionSetting.Command = GetXmlValueSafe(execAction, "Command");
                execActionSetting.Args = GetXmlValueSafe(execAction,"Arguments");
                execActionSetting.WorkingDir = GetXmlValueSafe(execAction, "WorkingDirectory");
                stActions.Add(execActionSetting);
            }

            XmlNodeList emailActions = stProperties.SelectNodes("Task/Actions/SendEmail");
            foreach (XmlNode emailAction in emailActions)
            {
                SchedTaskEmailAction emailActionSetting = new SchedTaskEmailAction();
                emailActionSetting.From = GetXmlValueSafe(emailAction,"From");
                emailActionSetting.To = GetXmlValueSafe(emailAction,"To");
                emailActionSetting.Subject = GetXmlValueSafe(emailAction, "Subject");
                emailActionSetting.Body = GetXmlValueSafe(emailAction,"Body");
                emailActionSetting.HeaderFields = GetXmlValueSafe(emailAction,"HeaderFields");
                XmlNodeList xmlAttachments = emailAction.SelectNodes("Attachments/*");
                if (xmlAttachments.Count >= 1)
                {
                    emailActionSetting.Attachments = new List<string>();

                    foreach (XmlNode node in xmlAttachments)
                    {
                        emailActionSetting.Attachments.Add(node.InnerText);
                    }
                }

                emailActionSetting.Server = GetXmlValueSafe(emailAction,"Server");
                stActions.Add(emailActionSetting);
            }
            sts.Actions = stActions;

            // comment
            sts.Comment = stPropAtts?["comment"]?.Value;

            bool systemRequired;
            if (Boolean.TryParse(stPropAtts?["systemRequired"]?.Value, out systemRequired))
            {
                sts.SystemRequired = systemRequired;
            }

            return sts;
        }
    }
}