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

        public PathResult AnalysePath(string originalPath)
        {
            PathResult pathResult = null;

            // first we can check if it's a file (and the file exists) and analyse it
            if (File.Exists(originalPath))
            {
                try
                {
                    PathResult filePathResult = AnalyseFilePath(originalPath);
                    filePathResult.FileExists = true;
                    filePathResult.SetProperties(originalPath, true);
                    if (filePathResult.RwStatus.CanModify)
                    {
                        filePathResult.FileWritable = true;
                    }
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
                    PathResult dirPathResult = AnalyseDirPath(originalPath);
                    dirPathResult.DirectoryExists = true;
                    dirPathResult.SetProperties(originalPath, true);
                    if (dirPathResult.RwStatus.CanModify || dirPathResult.RwStatus.CanWrite)
                    {
                        dirPathResult.DirectoryWritable = true;
                    }
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
                string[] pathElements = originalPath.Trim('\\').Split('\\');

                bool unc = false;
                if (originalPath.StartsWith("\\\\")) { unc = true; }
                string path = Path.Combine(pathElements);
                if (unc) { path = "\\\\" + path; }

                while (pathElements.Length >= 1)
                {
                    if (Directory.Exists(path))
                    {
                        //RwStatus rwstatus = FsAclAnalyser.AnalyseFsAcl(new DirectoryInfo(path)).RwStatus;
                        DirPathResult dirPathResult = AnalyseDirPath(path);
                        dirPathResult.SetProperties(originalPath, false);
                        dirPathResult.ParentDirectoryExists = path;
                        dirPathResult.DirectoryExists = false;
                        dirPathResult.DirectoryWritable = false;
                        if (dirPathResult.RwStatus.CanWrite || dirPathResult.RwStatus.CanModify)
                        {
                            dirPathResult.ParentDirectoryWritable = true;
                        }
                        pathResult = dirPathResult;
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
            return pathResult;
        }

        public FilePathResult AnalyseFilePath(string filePath)
        {
            BlockingMq mq = new BlockingMq();

            FileClassifier fileClassifier = new FileClassifier(mq, AssessmentOptions.ClassifierOptions);

            FilePathResult filePathResult = new FilePathResult();

            //we know the file exists, so it's worth running through the snaffler engine.
            foreach (ClassifierRule rule in AssessmentOptions.ClassifierOptions.AllRules.FileClassifierRules)
            {
                FileResult snaffResult = (FileResult)fileClassifier.Classify(rule, filePath);
                if (snaffResult != null && snaffResult.MatchedRule != null)
                {
                    filePathResult.SnaffFileResults.Add(snaffResult);
                }
            }

            FileInfo fileInfo = new FileInfo(filePath);
            RwStatus rwStatus = FsAclAnalyser.AnalyseFsAcl(fileInfo).RwStatus;
            filePathResult.RwStatus = rwStatus;

            return filePathResult;
        }

        public DirPathResult AnalyseDirPath(string dirPath)
        {
            BlockingMq mq = new BlockingMq();

            DirClassifier dirClassifier = new DirClassifier(mq, AssessmentOptions.ClassifierOptions);

            DirPathResult dirPathResult = new DirPathResult();

            //we know the dir exists, so it's worth running through the snaffler engine.
            foreach (ClassifierRule rule in AssessmentOptions.ClassifierOptions.AllRules.DirClassifierRules)
            {
                DirResult snaffResult = (DirResult)dirClassifier.Classify(rule, dirPath);
                if (snaffResult != null && snaffResult.MatchedRule != null)
                {
                    dirPathResult.SnaffDirResults.Add(snaffResult);
                }
            }

            DirectoryInfo dirInfo = new DirectoryInfo(dirPath);
            RwStatus rwStatus = FsAclAnalyser.AnalyseFsAcl(dirInfo).RwStatus;
            dirPathResult.RwStatus = rwStatus;

            return dirPathResult;
        }
    }
}
