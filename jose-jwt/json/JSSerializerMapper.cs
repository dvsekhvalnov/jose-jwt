#if NET40 || NET461
using System.Web.Script.Serialization;

namespace Jose
{
    public class JSSerializerMapper:IJsonMapper
    {
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
    }
}
#endif