using System.Collections;
using System.Collections.Generic;

namespace Jose
{
    public static class Collections
    {
        /// <summary>
        /// Union 'src' array with 'other' enumerable. Deduplicating values.
        /// 'other' expected to be IEnumerable, all values will be coerced to string.
        /// Operation is immutable, new array of strings returned. Null safe operation.
        /// </summary>
        public static string[] Union(string[] src, object other)
        {                        
            var enumerable = other as IEnumerable;

            if (enumerable == null)
            {
                return src;
            }

            ISet<string> union = (src == null)
                ? new HashSet<string>() 
                : new HashSet<string>(src);            
           
            foreach (var item in enumerable)
            {
                union.Add(item.ToString());
            }

            var result = new string[union.Count];
            union.CopyTo(result, 0);

            return result;
        }
    }
}