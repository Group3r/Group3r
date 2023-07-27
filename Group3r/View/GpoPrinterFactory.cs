using Group3r.Options;
using System;

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
        public static IGpoPrinter GetPrinter(string setting, GrouperOptions options)
        {
            IGpoPrinter processor;
            // Currently only JSON exists which is the default.
            Console.WriteLine("~~~~~~~~~Current printer setting: " + options.PrinterType);
            switch (options.PrinterType)
            {
                case "json":
                    processor = new JsonGpoPrinter(options);
                    break;
                case "nice":
                    processor = new NiceGpoPrinter(options);
                    break;
                default:
                    processor = new JsonGpoPrinter(options);
                    break;
            }
            //processor = new NiceGpoPrinter(options);

            return processor;
        }
    }
}
