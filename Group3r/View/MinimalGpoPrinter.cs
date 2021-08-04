using Group3r.Assessment;
using LibSnaffle.ActiveDirectory;

namespace Group3r.View
{
    /**
     * Summary: GpoPrinter to just print the sysvolpath for testing.
     */
    class MinimalGpoPrinter : IGpoPrinter
    {
        public string OutputGPO(GPO gpo)
        {
            return gpo.Attributes.PathInSysvol;
        }

        public string OutputGpoResult(GpoResult gpoResult)
        {
            return gpoResult.Attributes.PathInSysvol;
        }
    }
}
