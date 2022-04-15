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
            var src = new[] { "one", "two" };
            var other = new[] { "two", "three" };

            Assert.Equal(new[] { "one", "two", "three" }, Collections.Union(src, other));
        }

        [Fact]
        public void UnionArrayList()
        {
            var src = new[] { "one", "two" };
            var other = new List<string>(new[] { "two", "three" });

            Assert.Equal(new[] { "one", "two", "three" }, Collections.Union(src, other));
        }

        [Fact]
        public void UnionArraySet()
        {
            var src = new[] { "one", "two" };
            var other = new HashSet<string>(new[] { "two", "three" });

            Assert.Equal(new[] { "one", "two", "three" }, Collections.Union(src, other));
        }

        [Fact]
        public void UnionNonStrings()
        {
            var src = new[] { "one", "two" };
            var other = new[] { 2, 3 };

            Assert.Equal(new[] { "one", "two", "2", "3" }, Collections.Union(src, other));
        }

        [Fact]
        public void UnionNull()
        {
            var other = new[] { "two", "three" };

            Assert.Equal(new[] { "two", "three" }, Collections.Union(null, other));
        }

        [Fact]
        public void UnionWithNonEnumerable()
        {
            var src = new[] { "one", "two" };
            var other = 3;

            Assert.Equal(new[] { "one", "two" }, Collections.Union(src, other));
        }

        [Fact]
        public void UnionWithNull()
        {
            var src = new[] { "one", "two" };

            Assert.Equal(new[] { "one", "two" }, Collections.Union(src, null));
        }
    }
}