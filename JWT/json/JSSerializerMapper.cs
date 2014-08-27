using System;
using System.Linq;
#if NET35
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
#else
using System.Web.Script.Serialization;
#endif

namespace Jose
{
    public class JSSerializerMapper:IJsonMapper
    {
#if NET35
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
#else
        private static JavaScriptSerializer js;

        private JavaScriptSerializer JS
        {
            get { return js ?? (js = new JavaScriptSerializer()); }
        }

        public string Serialize(object obj)
        {
            return JS.Serialize(obj);
        }

        public T Parse<T>(string json)
        {
            return JS.Deserialize<T>(json);
        }
#endif
    }
}