using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Group3r.View
{
    /**
     * Summary: Factory to create GpoPrinter given the control flag.
     */
    static class GpoPrinterFactory
    {
        /**
         * Summary: Returns a GpoPrinter given the setting.
         * Arguments: string containing the control flag.
         * Returns: IGpoPrinter instance.
         */
        public static IGpoPrinter GetPrinter(string setting)
        {
            IGpoPrinter processor;
            // Currently only JSON exists which is the default.
            switch (setting)
            {
                case "minimal":
                    processor = new MinimalGpoPrinter();
                    break;
                case "json":
                    processor = new JsonGpoPrinter();
                    break;
                default:
                    processor = new JsonGpoPrinter();
                    break;
            }
            return processor;
        }
    }
}
