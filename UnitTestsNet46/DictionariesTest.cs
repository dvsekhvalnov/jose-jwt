using System.Collections.Generic;
using Jose;
using Xunit;

namespace UnitTests
{
    public class DictionariesTest
    {
        [Fact]
        public void Append()
        {
            //given
            var src = new Dictionary<string, string> { { "one", "1" }, { "two", "2" } };
            var other = new Dictionary<string, string> { { "three", "3" }, { "two", "3" } };

            //when
            Dictionaries.Append(src, other);

            //then
            Assert.Equal(src.Count, 3);
            Assert.Equal(src["one"], "1");
            Assert.Equal(src["two"], "2");
            Assert.Equal(src["three"], "3");
        }

        [Fact]
        public void AppendNull()
        {
            //given
            var src = new Dictionary<string, string> { { "one", "1" }, { "two", "2" } };

            //when
            Dictionaries.Append(src, null);

            //then
            Assert.Equal(src.Count, 2);
            Assert.Equal(src["one"], "1");
            Assert.Equal(src["two"], "2");
        }

        [Fact]
        public void Get()
        {
            //given
            var src = new Dictionary<string, string> { { "one", "1" }, { "two", "2" } };

            //then
            Assert.Equal(Dictionaries.Get(src, "one"), "1");
            Assert.Equal(Dictionaries.Get(src, "two"), "2");
            Assert.Null(Dictionaries.Get(src, "three"));
        }
    }
}