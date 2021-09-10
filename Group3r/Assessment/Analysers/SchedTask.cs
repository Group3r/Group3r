using System;
using System.Collections.Generic;
using Group3r.Options.AssessmentOptions;
using LibSnaffle.ActiveDirectory;
using LibSnaffle.Classifiers.Rules;

namespace Group3r.Assessment.Analysers
{
    public class SchedTaskAnalyser : Analyser
    {
        public SchedTaskSetting setting { get; set; }
        public override SettingResult Analyse(AssessmentOptions assessmentOptions)
        {
            List<GpoFinding> findings = new List<GpoFinding>();

            /*
            findings.Add(new GpoFinding()
            {
                FindingReason = "SchedTask analyser not implemented.",
                FindingDetail = "SchedTask analyser not implemented.",
                Triage = Constants.Triage.Green
            });
            // put findings in settingResult
            SettingResult.Findings = findings;

            // make a new setting object minus the ugly bits we don't care about.
            SettingResult.Setting = new SchedTaskSetting();
            */

            // if they're specifying who to run the task as
            if (setting.Principals != null)
            {
                if (setting.Principals.Count >= 1)
                {
                    foreach (SchedTaskPrincipal principal in setting.Principals)
                    {
                        if (!String.IsNullOrWhiteSpace(principal.Cpassword))
                        {

                            string password = setting.DecryptCpassword(principal.Cpassword);
                            findings.Add(new GpoFinding()
                            {
                                FindingReason = "Group Policy Preferences password found:" + password,
                                FindingDetail = "Refer to MS14-025 and https://adsecurity.org/?p=63",
                                Triage = Constants.Triage.Black
                            });
                        }
                    }
                }
            }

            if (setting.Actions != null)
            {
                foreach (SchedTaskAction action in setting.Actions)
                {

                }
            }

            /*
            // handle the entries that are specific to some task types but not others
            // both taskv2 and immediatetaskv2 have the same rough structure
            if (schedTaskType.EndsWith("V2"))
            {
                assessedScheduledTask.Add("Action",
                    JUtil.GetActionString(scheduledTask["Properties"]["@action"].ToString()));
                assessedScheduledTask.Add("Description", JUtil.GetSafeString(scheduledTask, "@desc"));
                assessedScheduledTask.Add("Enabled",
                    JUtil.GetSafeString(scheduledTask["Properties"]["Task"]["Settings"], "Enabled"));
                // just adding the Triggers info raw, there are way too many options.
                assessedScheduledTask.Add("Triggers", scheduledTask["Properties"]["Task"]["Triggers"]);

                if (scheduledTask["Properties"]["Task"]["Actions"]["ShowMessage"] != null)
                {
                    assessedScheduledTask.Add(
                        new JProperty("Action - Show Message", new JObject(
                                new JProperty("Title",
                                    JUtil.GetSafeString(scheduledTask["Properties"]["Task"]["Actions"]["ShowMessage"],
                                        "Title")),
                                new JProperty("Body",
                                    JUtil.GetSafeString(scheduledTask["Properties"]["Task"]["Actions"]["ShowMessage"],
                                        "Body"))
                            )
                        )
                    );
                }

                if (scheduledTask["Properties"]["Task"]["Actions"]["Exec"] != null)
                {
                    // do we have an array of Command?
                    if (scheduledTask["Properties"]["Task"]["Actions"]["Exec"].Type == JTokenType.Array)
                    {
                        int i = 1;
                        foreach (JToken item in scheduledTask["Properties"]["Task"]["Actions"]["Exec"])
                        {
                            assessedScheduledTask.Add(ExtractCommandFromScheduledTask(item, ref interestLevel, i));
                            i++;
                        }
                    }
                    else
                    {
                        // or just one?
                        assessedScheduledTask.Add(ExtractCommandFromScheduledTask(scheduledTask["Properties"]["Task"]["Actions"]["Exec"], ref interestLevel));
                    }
                }

                if (scheduledTask["Properties"]["Task"]["Actions"]["SendEmail"] != null)
                {
                    string attachmentString =
                        JUtil.GetSafeString(
                            scheduledTask["Properties"]["Task"]["Actions"]["SendEmail"]["Attachments"], "File");

                    JObject attachment = new JObject(new JProperty("Attachment", attachmentString));

                    if (GlobalVar.OnlineChecks)
                    {
                        attachment = FileSystem.InvestigateString(attachmentString);
                        if (attachment["InterestLevel"] != null)
                        {
                            int attachmentInterest = (int) attachment["InterestLevel"];
                            interestLevel = interestLevel + attachmentInterest;
                        }
                    }

                    assessedScheduledTask.Add(
                        new JProperty("Action - Send Email", new JObject(
                                new JProperty("From",
                                    JUtil.GetSafeString(scheduledTask["Properties"]["Task"]["Actions"]["SendEmail"],
                                        "From")),
                                new JProperty("To",
                                    JUtil.GetSafeString(scheduledTask["Properties"]["Task"]["Actions"]["SendEmail"],
                                        "To")),
                                new JProperty("Subject",
                                    JUtil.GetSafeString(scheduledTask["Properties"]["Task"]["Actions"]["SendEmail"],
                                        "Subject")),
                                new JProperty("Body",
                                    JUtil.GetSafeString(scheduledTask["Properties"]["Task"]["Actions"]["SendEmail"],
                                        "Body")),
                                new JProperty("Header Fields",
                                    JUtil.GetSafeString(scheduledTask["Properties"]["Task"]["Actions"]["SendEmail"],
                                        "HeaderFields")),
                                new JProperty("Attachment", attachment),
                                new JProperty("Server",
                                    JUtil.GetSafeString(scheduledTask["Properties"]["Task"]["Actions"]["SendEmail"],
                                        "Server"))
                            )
                        )
                    );
                }
            }

            if (schedTaskType == "Task")
            {
                string commandString = JUtil.GetSafeString(scheduledTask["Properties"], "@appname");
                string argumentsString = JUtil.GetSafeString(scheduledTask["Properties"], "@args");
                JObject command = new JObject(new JProperty("Command", commandString));
                JObject arguments = new JObject(new JProperty("Arguments", argumentsString));
                
                command = FileSystem.InvestigatePath(commandString);
                arguments = FileSystem.InvestigateString(argumentsString);

                if ((arguments != null) && (arguments["InterestLevel"] != null))
                {
                    int argumentInterest = (int) arguments["InterestLevel"];
                    interestLevel = interestLevel + argumentInterest;
                }

                if ((command != null) && (command["InterestLevel"] != null))
                {
                    int commandInterest = (int) command["InterestLevel"];
                    interestLevel = interestLevel + commandInterest;
                }
                

                assessedScheduledTask.Add("Action",
                    JUtil.GetActionString(scheduledTask["Properties"]["@action"].ToString()));
                assessedScheduledTask.Add("Command", command);
                assessedScheduledTask.Add("Args", arguments);
                JObject assessedWorkingDir =
                    FileSystem.InvestigatePath(JUtil.GetSafeString(scheduledTask["Properties"], "@startIn"));
                if ((assessedWorkingDir != null) && assessedWorkingDir.HasValues)
                {
                    assessedScheduledTask.Add("Working Dir", assessedWorkingDir);
                }
                
                if (scheduledTask["Properties"]["Triggers"] != null)
                {
                    assessedScheduledTask.Add("Triggers", scheduledTask["Properties"]["Triggers"]);
                }
            }

            if (schedTaskType == "ImmediateTask")
            {
                string argumentsString = JUtil.GetSafeString(scheduledTask["Properties"], "@args");
                string commandString = JUtil.GetSafeString(scheduledTask["Properties"], "@appName");
                JObject command = new JObject(new JProperty("Command", commandString));
                JObject arguments = new JObject(new JProperty("Arguments", argumentsString));

                
                command = FileSystem.InvestigatePath(commandString);
                arguments = FileSystem.InvestigateString(argumentsString);

                if ((arguments != null) && (arguments["InterestLevel"] != null))
                {
                    int argumentInterest = (int) arguments["InterestLevel"];
                    interestLevel = interestLevel + argumentInterest;
                }

                if ((command != null) && (command["InterestLevel"] != null))
                {
                    int commandInterest = (int) command["InterestLevel"];
                    interestLevel = interestLevel + commandInterest;
                }
                

                assessedScheduledTask.Add("Command", command);
                assessedScheduledTask.Add("Arguments", arguments);

                JObject assessedWorkingDir =
                    FileSystem.InvestigatePath(JUtil.GetSafeString(scheduledTask["Properties"], "@startIn"));
                if ((assessedWorkingDir != null) && assessedWorkingDir.HasValues)
                {
                    assessedScheduledTask.Add("Working Dir", assessedWorkingDir);
                }

                assessedScheduledTask.Add("Comment", JUtil.GetSafeString(scheduledTask["Properties"], "@comment"));
            }
             */
            SettingResult.Setting = setting;

            return SettingResult;
        }
    }
}