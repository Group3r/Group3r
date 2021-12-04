using Group3r.Options.AssessmentOptions;
using LibSnaffle.Classifiers;
using LibSnaffle.Classifiers.Results;
using LibSnaffle.Concurrency;
using System;
using System.IO;

namespace Group3r.Assessment
{
    class PathAnalyser
    {
        private AssessmentOptions AssessmentOptions { get; set; }
        SddlAnalyser SddlAnalyser { get; set; }
        FsAclAnalyser FsAclAnalyser { get; set; }
        //EffectivePermissions EffectivePermissions { get; set; }

        public PathAnalyser(AssessmentOptions assessmentOptions)
        {
            AssessmentOptions = assessmentOptions;
            SddlAnalyser = new SddlAnalyser(AssessmentOptions);
            FsAclAnalyser = new FsAclAnalyser(AssessmentOptions);
            //EffectivePermissions = new EffectivePermissions(assessmentOptions.TargetTrustees);
            //EffectivePermissions = new EffectivePermissions();
        }

        public PathFinding AnalysePath(string originalPath)
        {
            PathFinding pathFinding = null;

            // first we can check if it's a file (and the file exists) and analyse it
            if (File.Exists(originalPath))
            {
                try
                {
                    PathFinding filePathFinding = AnalyseFilePath(originalPath);
                    filePathFinding.FileExists = true;
                    filePathFinding.SetProperties(originalPath, true);
                    if (filePathFinding.FileResult.RwStatus.CanModify)
                    {
                        filePathFinding.FileWritable = true;
                    }
                    pathFinding = filePathFinding;
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
                    PathFinding dirPathFinding = AnalyseDirPath(originalPath);
                    dirPathFinding.DirectoryExists = true;
                    dirPathFinding.SetProperties(originalPath, true);
                    if (dirPathFinding.DirResult.RwStatus.CanModify || dirPathFinding.DirResult.RwStatus.CanWrite)
                    {
                        dirPathFinding.DirectoryWritable = true;
                    }
                    pathFinding = dirPathFinding;
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
                string[] pathElements = originalPath.Trim('\\').Split('\\');

                bool unc = false;
                if (originalPath.StartsWith("\\\\")) { unc = true; }
                string path = Path.Combine(pathElements);
                if (unc) { path = "\\\\" + path; }

                while (pathElements.Length >= 1)
                {
                    if (Directory.Exists(path))
                    {
                        RwStatus rwstatus = FsAclAnalyser.GetRwStatus(new DirectoryInfo(path));
                        PathFinding dirPathFinding = AnalyseDirPath(originalPath);
                        dirPathFinding.SetProperties(originalPath, false);
                        dirPathFinding.ParentDirectoryExists = path;
                        dirPathFinding.DirectoryExists = false;
                        dirPathFinding.DirectoryWritable = false;
                        if (rwstatus.CanWrite || rwstatus.CanModify)
                        {
                            dirPathFinding.ParentDirectoryWritable = true;
                        }
                        pathFinding = dirPathFinding;
                        break;
                    }
                    else
                    {
                        Array.Resize(ref pathElements, pathElements.Length - 1);
                        path = Path.Combine(pathElements);
                        if (unc) { path = "\\\\" + path; }
                    }
                }
            }
            return pathFinding;
        }

        public PathFinding AnalyseFilePath(string filePath)
        {
            BlockingMq mq = new BlockingMq();

            FileClassifier fileClassifier = new FileClassifier(mq, AssessmentOptions.ClassifierOptions);

            PathFinding filePathFinding = new FilePathFinding();

            foreach (ClassifierRule rule in AssessmentOptions.ClassifierOptions.AllRules.FileClassifierRules)
            {
                FileResult result = (FileResult)fileClassifier.Classify(rule, filePath);
                if (result != null)
                {
                    FileInfo fileInfo = new FileInfo(filePath);
                    RwStatus rwStatus = FsAclAnalyser.GetRwStatus(fileInfo);
                    result.RwStatus = rwStatus;
                    filePathFinding.FileResult = result;
                }
            }

            // if we didn't get any hits from snaffler we will still create a fileResult to capture the info about if it's writable
            if (filePathFinding.FileResult == null)
            {
                FileInfo fileInfo = new FileInfo(filePath);
                FileResult result = new FileResult(fileInfo, false, 0, null);
                RwStatus rwStatus = FsAclAnalyser.GetRwStatus(fileInfo);
                result.RwStatus = rwStatus;
                filePathFinding.FileResult = result;
            }

            return filePathFinding;
        }

        public PathFinding AnalyseDirPath(string dirPath)
        {
            BlockingMq mq = new BlockingMq();

            DirClassifier dirClassifier = new DirClassifier(mq, AssessmentOptions.ClassifierOptions);

            PathFinding dirPathFinding = new DirPathFinding();

            foreach (ClassifierRule rule in AssessmentOptions.ClassifierOptions.AllRules.DirClassifierRules)
            {
                DirResult result = (DirResult)dirClassifier.Classify(rule, dirPath);
                if (result.MatchedRule != null)
                {
                    DirectoryInfo dirInfo = new DirectoryInfo(dirPath);
                    RwStatus rwStatus = FsAclAnalyser.GetRwStatus(dirInfo);
                    result.RwStatus = rwStatus;
                    dirPathFinding.DirResult = result;
                }
            }

            // if we didn't get any hits from snaffler we will still create a dirResult to capture the info about if it's writable
            if (dirPathFinding.DirResult == null)
            {
                DirectoryInfo dirInfo = new DirectoryInfo(dirPath);
                DirResult result = new DirResult(dirInfo);
                RwStatus rwStatus = FsAclAnalyser.GetRwStatus(dirInfo);
                result.RwStatus = rwStatus;
                dirPathFinding.DirResult = result;
            }

            return dirPathFinding;
        }
    }
}
