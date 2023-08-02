//using Newtonsoft.Json;
//using Newtonsoft.Json.Converters;

namespace BigFish.View
{
    //   /*
    //    * Summary: Implementation of IGpoOutputter which just serializes the GPO as JSON and returns it.
    //    */
    //   /*
    //   class JsonGpoPrinter : IGpoPrinter
    //   {
    //       private JsonSerializerSettings jSettings;
    //       private GrouperOptions grouperOptions;
    //       /**
    //        * Summary: constructor
    //        * Arguments: none
    //        * Returns: JsonGpoPrinter instance
    //        */
    //       public JsonGpoPrinter(GrouperOptions options)
    //       {
    //           grouperOptions = options;
    //           // Set up the Json serializer
    //           jSettings = new JsonSerializerSettings
    //           {
    //               NullValueHandling = NullValueHandling.Ignore,
    //               Formatting = Formatting.Indented,
    //               Converters = new List<JsonConverter>() { new StringEnumConverter() }
    //           };
    //       }
    //
    //
    //       /**
    //        * Summary: Implementation of OutputGPO which returns the serialized GPO as a Json string.
    //        * Arguments: GPO object to be outputted
    //        * Returns: string representation of GPO
    //        */
    //       public string OutputGPO(GPO gpo)
    //       {
    //           return JsonConvert.SerializeObject(gpo, jSettings);
    //       }
    //
    //       public string OutputGpoResult(GpoResult gpoResult)
    //       {
    //           return JsonConvert.SerializeObject(gpoResult, jSettings);
    //       }
    //   }
    //   
}
