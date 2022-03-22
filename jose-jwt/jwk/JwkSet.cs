using System.Collections;
using System.Collections.Generic;

namespace Jose
{
    public class JwkSet : IEnumerable<Jwk>
    {
        private List<Jwk> keys;

        public List<Jwk> Keys
        {
            get { return keys; }
        }

        public JwkSet(IEnumerable<Jwk> keys)
        {
            this.keys = new List<Jwk>(keys);
        }

        public JwkSet(params Jwk[] keys)
        {
            this.keys = new List<Jwk>(keys);
        }

        public void Add(Jwk key)
        {
            if (keys == null)
            {
                keys = new List<Jwk>();
            }

            keys.Add(key);
        }

        public static JwkSet FromDictionary(IDictionary<string, object> data)
        {
            var keyList = Dictionaries.Get<IEnumerable<object>>(data, "keys");

            JwkSet result = new JwkSet();

            foreach (var key in keyList)
            {
                result.Add(Jwk.FromDictionary((IDictionary<string, object>)key));
            }

            return result;

        }

        public IDictionary<string, object> ToDictionary()
        {
            var result = new Dictionary<string, object>();

            var keyList = new List<IDictionary<string, object>>();

            if (keys != null)
            {
                foreach (Jwk key in keys)
                {
                    keyList.Add(key.ToDictionary());
                }                
            }

            result["keys"] = keyList;

            return result;
        }

        public string ToJson(IJsonMapper mapper = null)
        {
            return mapper.Serialize(ToDictionary());
        }

        public static JwkSet FromJson(string json, IJsonMapper mapper = null)
        {
            return JwkSet.FromDictionary(
                mapper.Parse<IDictionary<string, object>>(json)
            );
        }

        public IEnumerator<Jwk> GetEnumerator()
        {
            return keys.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return keys.GetEnumerator();
        }
    }
}
