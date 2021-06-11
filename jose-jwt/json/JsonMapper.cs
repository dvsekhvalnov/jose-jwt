#if NETSTANDARD2_1
using System;
using System.Collections.Generic;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Unicode;

namespace Jose
{
    public class JsonMapper : IJsonMapper
    {
        private readonly JsonSerializerOptions SerializeOptions;
        private readonly JsonSerializerOptions DeserializeOptions;

        public JsonMapper()
        {
            SerializeOptions = new JsonSerializerOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            };

            DeserializeOptions = new JsonSerializerOptions();
            DeserializeOptions.Converters.Add(new NestedDictionariesConverter());
        }

        public string Serialize(object obj)
        {
            var json = JsonSerializer.Serialize(obj, SerializeOptions);
            return json;
        }

        public T Parse<T>(string json)
        {
            if (String.IsNullOrEmpty(json))
            {
                return default(T);
            }

            Type objectType = typeof(T);

            if (objectType == typeof(IDictionary<string, object>))
            {
                return JsonSerializer.Deserialize<T>(json, DeserializeOptions);
            }

            return JsonSerializer.Deserialize<T>(json);
        }
    }

    class NestedDictionariesConverter : JsonConverter<object>
    {
        public override bool CanConvert(Type objectType)
        {
            // in addition to handling IDictionary<string, object>
            // we want to handle the deserialization of dict value
            // which is of type object
            return objectType == typeof(object) || base.CanConvert(objectType);
        }

        public override object Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType == JsonTokenType.String)
            {
                return reader.GetString();
            }

            if (reader.TokenType == JsonTokenType.Number)
            {
                return reader.GetInt64();
            }

            if (reader.TokenType == JsonTokenType.True)
            {
                return true;
            }

            if (reader.TokenType == JsonTokenType.False)
            {
                return false;
            }

            if (reader.TokenType == JsonTokenType.Null)
            {
                return null;
            }

            var type = typeToConvert;

            if (reader.TokenType == JsonTokenType.StartObject)
            {
                type = typeof(IDictionary<string, object>);
            }
            else if (reader.TokenType == JsonTokenType.StartArray)
            {
                type = typeof(IEnumerable<object>);
            }

            return JsonSerializer.Deserialize(ref reader, type, options);
        }

        public override void Write(Utf8JsonWriter writer, object value, JsonSerializerOptions options)
        {
            JsonSerializer.Serialize(writer, value, typeof(object), options);
        }
    }
}
#endif