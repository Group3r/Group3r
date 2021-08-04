using System;
using System.IO;
using System.Linq;
using Group3r.Options.AssessmentOptions;
using LibSnaffle.Classifiers;
using LibSnaffle.Classifiers.Results;
using LibSnaffle.Concurrency;

namespace Group3r.Assessment
{
    class PathAnalyser
    {
        private AssessmentOptions AssessmentOptions { get; set; }

        public PathAnalyser(AssessmentOptions assessmentOptions)
        {
            this.AssessmentOptions = assessmentOptions;
        }

        public PathFinding AnalysePath(string originalPath)
        {
            PathFinding pathResult = null;
            SddlAnalyser sddlAnalyser = new SddlAnalyser(AssessmentOptions);
            // first we can check if it's a file (and the file exists) and analyse it
            if (File.Exists(originalPath))
            {
                try
                {
                    PathFinding filePathResult = AnalyseFilePath(originalPath);
                    filePathResult.SetProperties(originalPath, sddlAnalyser);
                    pathResult = filePathResult;
                }
                catch (Exception e)
                {
                    //TODO proper exception handling here
                    throw e;
                }
            }
            else if (Directory.Exists(originalPath))
            {
                // or if it's a dir
                try
                {
                    PathFinding dirPathResult = AnalyseDirPath(originalPath);
                    dirPathResult.SetProperties(originalPath, sddlAnalyser);
                    pathResult = dirPathResult;
                }
                catch (Exception e)
                {
                    //TODO proper exception handling here
                    throw e;
                }
            }
            else 
            {
                // if it doesn't exist at all, we need to step up the path to see if there's a parent dir that exists that might be writable.
                // so we trim backslashes to get an idea of how many elements there are in the path
                int pathElements = originalPath.Trim('\\').Split('\\').Length;

                string path = originalPath;

                while (pathElements >= 1)
                {
                    DirectoryInfo dir = Directory.GetParent(path);
                    if (dir != null)
                    {
                        path = dir.FullName;
                        pathElements--;

                        if (Directory.Exists(path))
                        {
                            PathFinding dirPathResult = AnalyseDirPath(originalPath);
                            dirPathResult.SetProperties(originalPath, sddlAnalyser);
                            pathResult = dirPathResult;
                        }
                    }
                    else
                    {
                        //If we are already at the root then stop looping.
                        //We do this because pathElements will be 2 for network paths when we are at the parent since the server name also gets included.
                        pathElements = 0;
                    }
                }
            }

            return pathResult;
        }

        public PathFinding AnalyseFilePath(string filePath)
        {
            BlockingMq mq = new BlockingMq();

            FileClassifier fileClassifier = new FileClassifier(mq, AssessmentOptions.ClassifierOptions);

            PathFinding filePathResult = new FilePathFinding(); 

            foreach (ClassifierRule rule in AssessmentOptions.ClassifierOptions.AllRules.FileClassifierRules)
            {
                FileResult result = (FileResult)fileClassifier.Classify(rule, filePath);
                if (result != null)
                {
                    filePathResult.FileResult = result;
                }
            }

            // if we didn't get any hits from snaffler we will still create a fileResult to capture the info about if it's writable
            if (filePathResult.FileResult == null)
            {
                FileInfo fileInfo = new FileInfo(filePath);
                FileResult result = new FileResult(fileInfo, false, 0, null);
                filePathResult.FileResult = result;
            }

            return filePathResult;
        }

        public PathFinding AnalyseDirPath(string dirPath)
        {
            BlockingMq mq = new BlockingMq();

            DirClassifier dirClassifier = new DirClassifier(mq, AssessmentOptions.ClassifierOptions);

            PathFinding dirPathResult = new DirPathFinding();

            foreach (ClassifierRule rule in AssessmentOptions.ClassifierOptions.AllRules.DirClassifierRules)
            {
                DirResult result = (DirResult)dirClassifier.Classify(rule, dirPath);
                if (result.MatchedRule != null)
                {
                    dirPathResult.DirResult = result;
                }
            }

            // if we didn't get any hits from snaffler we will still create a dirResult to capture the info about if it's writable
            if (dirPathResult.DirResult == null)
            {
                DirectoryInfo dirInfo = new DirectoryInfo(dirPath);
                DirResult result = new DirResult(dirInfo);
                dirPathResult.DirResult = result;
            }

            return dirPathResult;
        }
    }

    //Just putting these here for now until I can think of or realise a better place to store them.
    public class FilePathFinding : PathFinding
    {
        public override void SetProperties(string originalPath, SddlAnalyser sddlAnalyser)
        {
            FileInfo fileInfo = new FileInfo(originalPath);
            this.FileSecurity = fileInfo.GetAccessControl(System.Security.AccessControl.AccessControlSections.Access | System.Security.AccessControl.AccessControlSections.Owner);
            string fileSecuritySddlString = this.FileSecurity.GetSecurityDescriptorSddlForm(System.Security.AccessControl.AccessControlSections.Access | System.Security.AccessControl.AccessControlSections.Owner);
            this.AclResult = sddlAnalyser.AnalyseSddl(new Sddl.Parser.Sddl(fileSecuritySddlString, Sddl.Parser.SecurableObjectType.File));
            this.AssessedPath = originalPath;
            this.FileExists = true;
            this.FileSecurity = null;
        }
    }

    public class DirPathFinding : PathFinding
    {
        public override void SetProperties(string originalPath, SddlAnalyser sddlAnalyser)
        {
            DirectoryInfo dirInfo = new DirectoryInfo(originalPath);
            this.DirectorySecurity = dirInfo.GetAccessControl(System.Security.AccessControl.AccessControlSections.Access | System.Security.AccessControl.AccessControlSections.Owner);
            string dirSecuritySddlString = this.DirectorySecurity.GetSecurityDescriptorSddlForm(System.Security.AccessControl.AccessControlSections.Access | System.Security.AccessControl.AccessControlSections.Owner);
            this.AclResult = sddlAnalyser.AnalyseSddl(new Sddl.Parser.Sddl(dirSecuritySddlString, Sddl.Parser.SecurableObjectType.Directory));
            this.AssessedPath = originalPath;
            this.DirectoryExists = true;
            this.DirectorySecurity = null;
        }
    }
}
