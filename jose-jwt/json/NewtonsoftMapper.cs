#if NETSTANDARD1_4
using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace Jose
{

    public class NewtonsoftMapper : IJsonMapper
    {
        public string Serialize(object obj)
        {
            return JsonConvert.SerializeObject(obj, Formatting.None);
        }

        public T Parse<T>(string json)
        {
            Type objectType = typeof(T);

            if (objectType == typeof(IDictionary<string, object>))
            {
                return JsonConvert.DeserializeObject<T>(json, new NestedDictionariesConverter());
            }

            return JsonConvert.DeserializeObject<T>(json);
        }
    }

    class NestedDictionariesConverter : CustomCreationConverter<object>
    {
        public override object Create(Type objectType)
        {
            if (objectType == typeof(IEnumerable<>))
            {
                return new List<object>();
            }

            return new Dictionary<string, object>();
        }

        public override bool CanConvert(Type objectType)
        {
            // in addition to handling IDictionary<string, object>
            // we want to handle the deserialization of dict value
            // which is of type object
            return objectType == typeof(object) || base.CanConvert(objectType);
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            if (reader.TokenType == JsonToken.StartObject
                || reader.TokenType == JsonToken.Null)
            {
                return base.ReadJson(reader, objectType, existingValue, serializer);
            }

            if (reader.TokenType == JsonToken.StartArray)
            {
                return base.ReadJson(reader, typeof(IEnumerable<>), existingValue, serializer);
            }

            if (reader.TokenType == JsonToken.Integer)
            {
                return Convert.ToInt64(reader.Value);
            }

            // if the next token is not an object
            // then fall back on standard deserializer (strings, numbers etc.)
            return serializer.Deserialize(reader);
        }
    }
}
#endif