using System;
using System.Collections.Generic;
using Jose;
using NUnit.Framework;

namespace UnitTests
{
    [TestFixture]
    public class DictionariesTest
    {
        [Test]
        public void Append()
        {
            //given
            var src = new Dictionary<string, string> {{"one", "1"}, {"two", "2"}};
            var other = new Dictionary<string, string> {{"three", "3"}, {"two", "3"}};
            
            //when
            Dictionaries.Append(src, other);

            //then
            Assert.That(src, Has.Count.EqualTo(3));
            Assert.That(src["one"],Is.EqualTo("1"));
            Assert.That(src["two"],Is.EqualTo("2"));
            Assert.That(src["three"],Is.EqualTo("3"));
        }

        [Test]
        public void AppendNull()
        {
            //given
            var src = new Dictionary<string, string> { { "one", "1" }, { "two", "2" } };

            //when
            Dictionaries.Append(src, null);

            //then
            Assert.That(src, Has.Count.EqualTo(2));
            Assert.That(src["one"], Is.EqualTo("1"));
            Assert.That(src["two"], Is.EqualTo("2"));
        }

        [Test]
        public void Get()
        {
            //given
            var src = new Dictionary<string, object> { { "one", "1" }, { "two", 2 }, { "four", new double[] { 4.1, 4.2, 4.3 } } };

            //then
            Assert.That(Dictionaries.Get<string>(src, "one"), Is.EqualTo("1"));
            Assert.That(Dictionaries.Get<int>(src, "two"), Is.EqualTo(2));
            Assert.That(Dictionaries.Get<double[]>(src, "four"), Is.EqualTo(new double[] { 4.1, 4.2, 4.3 }));
            Assert.Null(Dictionaries.Get<string>(src, "three"));
            Assert.Null(Dictionaries.Get<string>(null, "one"));
        }

        [Test]
        public void MergeHeaders_CalledWithOnlyNulls_ReturnsEmptyDictionary()
        {
            //given


            //when
            var ret = Dictionaries.MergeHeaders(null, null);

            //then 
            Assert.NotNull(ret);
            Assert.That(ret.Count, Is.EqualTo(0));
        }

        [Test]
        public void MergeHeaders_MergeNullDictionary_ReturnsCopyOfOriginal()
        {
            //given
            var src = new Dictionary<string, object> { { "one", "1" }, { "two", "2" } };

            //when
            var ret = Dictionaries.MergeHeaders(src, null);

            //then
            Assert.AreNotSame(ret, src);
            Assert.That(ret.Count, Is.EqualTo(2));
            Assert.That(ret["one"], Is.EqualTo("1"));
            Assert.That(ret["two"], Is.EqualTo("2"));
        }

        [Test]
        public void MergeHeaders_MergeUniqueKeys_ReturnsExpectedunion()
        {
            //given
            var dict1 = new Dictionary<string, object> { { "one", "1" }, { "two", "2" } };
            var dict2 = new Dictionary<string, object> { { "three", "3" }, { "four", "4" } };
            var dict3 = new Dictionary<string, object> { { "five", 5 }, { "six", 6 } };

            //when
            var ret = Dictionaries.MergeHeaders(dict1, dict2, dict3);

            //then
            Assert.That(6, Is.EqualTo(ret.Count));
            Assert.That(ret["one"], Is.EqualTo("1"));
            Assert.That(ret["two"], Is.EqualTo("2"));
            Assert.That(ret["three"], Is.EqualTo("3"));
            Assert.That(ret["four"], Is.EqualTo("4"));
            Assert.That(ret["five"], Is.EqualTo(5));
            Assert.That(ret["six"], Is.EqualTo(6));
        }


        [Test]
        public void MergeHeaders_MergeNonUniqueKeys_ThrowsArgumentException()
        {
            //given
            var dict1 = new Dictionary<string, object> { { "one", "1" }, { "two", "2" } };
            var dict2 = new Dictionary<string, object> { { "three", "3" }, { "four", "4" } };
            var dict3 = new Dictionary<string, object> { { "five", 5 }, { "one", 6 } };

            //when
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                Dictionaries.MergeHeaders(dict1, dict2, dict3);
            });

            //then
            Assert.That(exception.Message, Is.StringStarting("An item with the same key has already been added."));
        }
    }
}