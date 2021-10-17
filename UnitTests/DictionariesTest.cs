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
            Assert.Equal(3, src.Count);
            Assert.Equal("1", src["one"]);
            Assert.Equal("2", src["two"]);
            Assert.Equal("3", src["three"]);
        }

        [Fact]
        public void AppendNull()
        {
            //given
            var src = new Dictionary<string, string> { { "one", "1" }, { "two", "2" } };

            //when
            Dictionaries.Append(src, null);

            //then
            Assert.Equal(2, src.Count);
            Assert.Equal("1", src["one"]);
            Assert.Equal("2", src["two"]);
        }

        [Fact]
        public void Get()
        {
            //given
            var src = new Dictionary<string, object> { { "one", "1" }, { "two", 2 }, { "four", new double[] { 4.1, 4.2, 4.3 } } };

            //then
            Assert.Equal("1", Dictionaries.Get<string>(src, "one"));
            Assert.Equal(2, Dictionaries.Get<int>(src, "two"));
            Assert.Equal(new double[] { 4.1, 4.2, 4.3 }, Dictionaries.Get<double[]>(src, "four"));
            Assert.Null(Dictionaries.Get<string>(src, "three"));
            Assert.Null(Dictionaries.Get<string>(null, "one"));
        }

        [Fact]
        public void MergeHeaders_CalledWithOnlyNulls_ReturnsEmptyDictionary()
        {
            //given


            //when
            var ret = Dictionaries.MergeHeaders(null, null);

            //then
            Assert.NotNull(ret);
            Assert.Empty(ret);
        }

        [Fact]
        public void MergeHeaders_MergeNullDictionary_ReturnsCopyOfOriginal()
        {
            //given
            var src = new Dictionary<string, object> { { "one", "1" }, { "two", "2" } };

            //when
            var ret = Dictionaries.MergeHeaders(src, null);

            //then
            Assert.NotSame(ret, src);
            Assert.Equal(2, ret.Count);
            Assert.Equal("1", ret["one"]);
            Assert.Equal("2", ret["two"]);
        }

        [Fact]
        public void MergeHeaders_MergeUniqueKeys_ReturnsExpectedunion()
        {
            //given
            var dict1 = new Dictionary<string, object> { { "one", "1" }, { "two", "2" } };
            var dict2 = new Dictionary<string, object> { { "three", "3" }, { "four", "4" } };
            var dict3 = new Dictionary<string, object> { { "five", 5 }, { "six", 6 } };

            //when
            var ret = Dictionaries.MergeHeaders(dict1, dict2, dict3);

            //then
            Assert.Equal(6, ret.Count);
            Assert.Equal("1", ret["one"]);
            Assert.Equal("2", ret["two"]);
            Assert.Equal("3", ret["three"]);
            Assert.Equal("4", ret["four"]);
            Assert.Equal(5, ret["five"]);
            Assert.Equal(6, ret["six"]);
        }

        [Fact]
        public void MergeHeaders_MergeNonUniqueKeys_ThrowsArgumentException()
        {
            //given
            var dict1 = new Dictionary<string, object> { { "one", "1" }, { "two", "2" } };
            var dict2 = new Dictionary<string, object> { { "three", "3" }, { "four", "4" } };
            var dict3 = new Dictionary<string, object> { { "five", 5 }, { "one", 6 } };

            //when
            var exception = Record.Exception(() => Dictionaries.MergeHeaders(dict1, dict2, dict3));

            //then
            Assert.NotNull(exception);
            Assert.IsType<System.ArgumentException>(exception);
            Assert.StartsWith("An item with the same key has already been added.", exception.Message);
        }
    }
}