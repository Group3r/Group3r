using LibSnaffle.ActiveDirectory;
using Newtonsoft.Json;
using Group3r.Assessment;
using Newtonsoft.Json.Converters;
using System.Collections.Generic;

namespace Group3r.View
{
    /**
     * Summary: Implementation of IGpoOutputter which just serializes the GPO as JSON and returns it.
     */
    class JsonGpoPrinter : IGpoPrinter
    {
        private JsonSerializerSettings jSettings;
        /**
         * Summary: constructor
         * Arguments: none
         * Returns: JsonGpoPrinter instance
         */
        public JsonGpoPrinter()
        {
            // Set up the Json serializer
            jSettings = new JsonSerializerSettings
            {
                NullValueHandling = NullValueHandling.Ignore,
                Formatting = Formatting.Indented,
                Converters = new List<JsonConverter>() { new StringEnumConverter() }
            };
        }


        /**
         * Summary: Implementation of OutputGPO which returns the serialized GPO as a Json string.
         * Arguments: GPO object to be outputted
         * Returns: string representation of GPO
         */
        public string OutputGPO(GPO gpo)
        {
            return JsonConvert.SerializeObject(gpo, jSettings);
        }

        public string OutputGpoResult(GpoResult gpoResult)
        {
            return JsonConvert.SerializeObject(gpoResult, jSettings);
        }
    }
}
