#if NET40 || NET461 || NET472
using System.Web.Script.Serialization;

namespace Jose
{
    public class JSSerializerMapper : IJsonMapper
    {
        private static readonly JavaScriptSerializer js = new JavaScriptSerializer();

        public string Serialize(object obj)
        {
            return js.Serialize(obj);
        }

        public T Parse<T>(string json)
        {
            return js.Deserialize<T>(json);
        }
    }
}
#endif