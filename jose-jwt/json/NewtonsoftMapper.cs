﻿#if NETSTANDARD1_4 || NETSTANDARD2_0
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
            return JsonConvert.DeserializeObject<T>(json, new NestedDictionariesConverter());
        }
    }

    class NestedDictionariesConverter : CustomCreationConverter<IDictionary<string, object>>
    {
        public override IDictionary<string, object> Create(Type objectType)
        {
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
                return base.ReadJson(reader, objectType, existingValue, serializer);

            // if the next token is not an object
            // then fall back on standard deserializer (strings, numbers etc.)
            return serializer.Deserialize(reader);
        }
    }
}
#endif