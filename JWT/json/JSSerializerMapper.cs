using System;
using System.IO;
using System.Linq;
#if !NET35
using System.Web.Script.Serialization;
#endif
using System.Text;

namespace Jose
{
    public class JSSerializerMapper:IJsonMapper
    {
#if NET35
        public string Serialize(object obj)
        {
            throw new Exception("Must implement IJsonMapper");
        }

        public T Parse<T>(string json)
        {
            throw new Exception("Must implement IJsonMapper");
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