using System;
using System.Collections.Generic;
using System.Xml;

namespace LibSnaffle.ActiveDirectory
{
    public class SchedTaskParser
    {

        // TODO - STILL NOT FINISHED

        public SchedTaskSetting ParseSchedTask(SchedTaskType taskType, XmlNode schedTask)
        {
            SchedTaskSetting sts = new SchedTaskSetting
            {
                TaskType = taskType
            };
            XmlAttributeCollection stAttributes = schedTask.Attributes;
            XmlNode stProperties = schedTask.SelectSingleNode("Properties");
            XmlAttributeCollection stPropAtts = stProperties.Attributes;

            // basic atts
            sts.Name = stAttributes?["name"]?.Value;
            DateTime changed;
            if (DateTime.TryParse(stAttributes?["changed"]?.Value, out changed))
            {
                sts.Changed = changed;
            }
            // detailed properties
            // these older v1 ones are single action
            sts.SettingAction = sts.ParseSettingAction(stPropAtts?["action"]?.Value);
            SchedTaskExecAction stAction = new SchedTaskExecAction
            {
                Command = stPropAtts?["appName"]?.Value,
                Args = stPropAtts?["args"]?.Value,
                WorkingDir = stPropAtts?["startIn"]?.Value
            };
            List<SchedTaskAction> stsActions = new List<SchedTaskAction>
            {
                stAction
            };
            sts.Actions = stsActions;
            sts.Comment = stPropAtts?["comment"]?.Value;

            bool noIfBatt;
            if (Boolean.TryParse(stPropAtts?["noStartIfOnBatteries"]?.Value, out noIfBatt))
            {
                sts.DisallowStartIfOnBatteries = noIfBatt;
            }

            bool startIfIdle;
            if (Boolean.TryParse(stPropAtts?["startOnlyIfIdle"]?.Value, out startIfIdle))
            {
                sts.StartOnlyIfIdle = startIfIdle;
            }

            bool stopOnIdleEnd;
            if (Boolean.TryParse(stPropAtts?["stopOnIdleEnd"]?.Value, out stopOnIdleEnd))
            {
                sts.StopOnIdleEnd = stopOnIdleEnd;
            }

            bool stopGoBatt;
            if (Boolean.TryParse(stPropAtts?["stopIfGoingOnBatteries"]?.Value, out stopGoBatt))
            {
                sts.StopIfGoingOnBatteries = stopGoBatt;
            }

            bool systemRequired;
            if (Boolean.TryParse(stPropAtts?["systemRequired"]?.Value, out systemRequired))
            {
                sts.SystemRequired = systemRequired;
            }

            // runas details
            sts.Principals = new List<SchedTaskPrincipal>();
            SchedTaskPrincipal stPrincipal = new SchedTaskPrincipal
            {
                UserId = stPropAtts?["runAs"]?.Value,
                LogonType = stPropAtts?["logonType"]?.Value,
                Cpassword = stPropAtts?["cpassword"]?.Value
            };
            sts.Principals.Add(stPrincipal);
            bool enabled;
            if (Boolean.TryParse(stPropAtts?["enabled"]?.Value, out enabled))
            {
                sts.Enabled = enabled;
            }
            // triggers
            sts.Triggers = stProperties.SelectNodes("Triggers/Trigger");
            return sts;
        }
    }
}