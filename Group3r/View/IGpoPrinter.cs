using BigFish.Assessment;
using LibSnaffle.ActiveDirectory;

namespace BigFish.View
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
