using Group3r.Assessment;
using LibSnaffle.ActiveDirectory;

namespace Group3r.View
{
    /**
     * Summary: Defines interface for GPO output behaviour.
     */
    public interface IGpoPrinter
    {
        string OutputGPO(GPO gpo);
        string OutputGpoResult(GpoResult gpoResult);
    }
}
