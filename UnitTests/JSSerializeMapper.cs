using System;
using System.Linq;
using Jose;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace UnitTests
{
    class JSSerializeMapper : IJsonMapper
    {
        public string Serialize(object obj)
        {
            return JsonConvert.SerializeObject(obj);
        }

        public T Parse<T>(string json)
        {
            return DeserializeRecursive<T>(json);
        }

        private static T DeserializeRecursive<T>(string json)
        {
            return (T)ToObject(JToken.Parse(json));
        }

        private static object ToObject(JToken token)
        {
            if (token.Type == JTokenType.Object)
            {
                return ((JObject) token).Properties().ToDictionary(prop => prop.Name, prop => ToObject(prop.Value));
            }
            else if (token.Type == JTokenType.Array)
            {
                return token.Values().Select(ToObject).ToList();
            }
            else
            {
                return ((JValue)token).Value;
            }
        }

    }
}
