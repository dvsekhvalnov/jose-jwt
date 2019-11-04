using System.Collections.Generic;
using Jose;
using Xunit;

namespace UnitTests
{
    public class CollectionsTest
    {
        [Fact]
        public void UnionArrays()
        {
            var src = new[] {"one", "two"};
            var other = new[] {"two", "three"};

            Assert.Equal(Collections.Union(src, other), new [] {"one", "two", "three"});
        } 

        [Fact]
        public void UnionArrayList()
        {
            var src = new[] { "one", "two" };
            var other = new List<string>(new [] { "two", "three" });

            Assert.Equal(Collections.Union(src, other), new[] { "one", "two", "three" });

        }

        [Fact]
        public void UnionArraySet()
        {
            var src = new[] { "one", "two" };
            var other = new HashSet<string>(new [] { "two", "three" });

            Assert.Equal(Collections.Union(src, other), new[] { "one", "two", "three" });

        }

        [Fact]
        public void UnionNonStrings()
        {
            var src = new[] { "one", "two" };
            var other = new[] { 2, 3 };

            Assert.Equal(Collections.Union(src, other), new[] { "one", "two", "2", "3" });
        }

        [Fact]
        public void UnionNull()
        {            
            var other = new[] { "two", "three" };

            Assert.Equal(Collections.Union(null, other), new[] { "two", "three" });
        }

        [Fact]
        public void UnionWithNonEnumerable()
        {            
            var src = new[] { "one", "two" };
            var other = 3;

            Assert.Equal(Collections.Union(src, other), new[] { "one", "two" });
        }

        [Fact]
        public void UnionWithNull()
        {            
            var src = new[] { "one", "two" };            

            Assert.Equal(Collections.Union(src, null), new[] { "one", "two" });
        }

    }
}