using System.Collections.Generic;
using Jose;
using NUnit.Framework;

namespace UnitTests
{
    public class CollectionsTest
    {
        [Test]
        public void UnionArrays()
        {
            var src = new[] {"one", "two"};
            var other = new[] {"two", "three"};

            Assert.That(Collections.Union(src, other), Is.EqualTo(new [] {"one", "two", "three"}));
        } 

        [Test]
        public void UnionArrayList()
        {
            var src = new[] { "one", "two" };
            var other = new List<string>(new [] { "two", "three" });

            Assert.That(Collections.Union(src, other), Is.EqualTo(new[] { "one", "two", "three" }));

        }

        [Test]
        public void UnionArraySet()
        {
            var src = new[] { "one", "two" };
            var other = new HashSet<string>(new [] { "two", "three" });

            Assert.That(Collections.Union(src, other), Is.EqualTo(new[] { "one", "two", "three" }));

        }

        [Test]
        public void UnionNonStrings()
        {
            var src = new[] { "one", "two" };
            var other = new[] { 2, 3 };

            Assert.That(Collections.Union(src, other), Is.EqualTo(new[] { "one", "two", "2", "3" }));
        }

        [Test]
        public void UnionNull()
        {            
            var other = new[] { "two", "three" };

            Assert.That(Collections.Union(null, other), Is.EqualTo(new[] { "two", "three" }));
        }

        [Test]
        public void UnionWithNonEnumerable()
        {            
            var src = new[] { "one", "two" };
            var other = 3;

            Assert.That(Collections.Union(src, other), Is.EqualTo(new[] { "one", "two" }));
        }

        [Test]
        public void UnionWithNull()
        {            
            var src = new[] { "one", "two" };            

            Assert.That(Collections.Union(src, null), Is.EqualTo(new[] { "one", "two" }));
        }

    }
}