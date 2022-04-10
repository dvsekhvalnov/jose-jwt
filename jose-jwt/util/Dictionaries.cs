using System;
using System.Collections.Generic;
using System.Linq;

namespace Jose
{
    public static class Dictionaries
    {
        /// <summary>
        /// Appends `other` key/value pairs to 'src'. Conflicting keys are not appended (e.g. 'src' keys has priority).
        /// Operation in mutable, 'src' modified as result. Null safe operation.
        /// </summary>
        public static void Append<K, V>(IDictionary<K, V> src, IDictionary<K, V> other)
        {
            if (src!=null && other != null)
            {
                foreach (var pair in other.Where(pair => !src.ContainsKey(pair.Key)))
                {
                    src.Add(pair);
                }
            }
        }

        /// <summary>
        /// Syntax sugar for IDictionary.TryGetValue() to lookup unknown keys.
        /// </summary>
        public static V Get<V>(IDictionary<string, object> src, string key)
        {
            if(src==null)
            {
                return default;
            }

            object value;

            return src.TryGetValue(key, out value) ? (V)value : default;
        }

        public static List<V> GetList<V>(IDictionary<string, object> src, string key)
        {
            IEnumerable<object> value = Get<IEnumerable<object>>(src, key);

            if (value == null)
            {
                return default;
            }

            return value.Select(i => (V)Convert.ChangeType(i, typeof(V))).ToList();
        }

        public static IDictionary<string, object> Except(IDictionary<string, object> src, HashSet<string> keys)
        {
            IDictionary<string, object> result = null;

            foreach (var kp in src)
            {
                if (!keys.Contains(kp.Key))
                {
                    if (result == null)
                    {
                        result = new Dictionary<string, object>();
                    }

                    result[kp.Key] = kp.Value;
                }
            }

            return result;
        }

        /// <summary>
        /// Merges the IDictionaries supplied and returns an IDictionary containing the union of key/value pairs of all
        /// supplied IDictionaries.
        /// Note - the method will throw an ArgumentException if there are duplicate key names supplied.
        /// </summary>
        /// <param name="dicts"></param>
        /// <exception cref="ArgumentException">Thrown if there are duplicated keys between the supplied dicts.</exception>
        /// <returns>IDictionary containing union of key/values of all supplied dicts.</returns>
        public static IDictionary<string, object> MergeHeaders(params IDictionary<string, object>[] dicts)
        {
            return dicts
                .Where(dict => dict != null)
                .SelectMany(x => x)
                .ToDictionary(k => k.Key, k => k.Value);
        }
    }
}